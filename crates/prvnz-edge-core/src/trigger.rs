// SPDX-License-Identifier: Apache-2.0

//! [`DppLifecycleTrigger`] — `TriggerSource` impl that fires DPP lifecycle
//! events (`onProductionComplete`, `onRepairDetected`, `onTransferOfOwnership`,
//! …) from a JSON-Lines event feed on local disk.
//!
//! # Wire shape
//!
//! Each line of the watched file is one JSON object of the form:
//!
//! ```jsonc
//! { "lifecycle": "onProductionComplete", "tags": ["public"], "payload": { ... } }
//! ```
//!
//! - `lifecycle` (required, string) — DPP lifecycle event name. Becomes the
//!   first tag on the emitted [`TriggerEvent`], so `PolicyRouter` impls can
//!   match on it directly.
//! - `tags` (optional, array of strings) — additional tags merged after the
//!   lifecycle tag.
//! - `payload` (optional, any JSON value) — opaque payload handed to the
//!   agent step that runs in response.
//!
//! Lines that fail to parse are skipped with a `tracing::warn!`; the stream
//! keeps running because a malformed line in an external feed must not stall
//! the production line.
//!
//! # Why file-watch first
//!
//! The PRVNZ spec accepts any of: file-watch, MQTT subscribe, HTTP poll, or
//! a local event log. File-watch is the lowest-risk first move because:
//!
//! - Zero external infra. A factory MES, ERP, or quality-control script can
//!   just append a line to a file.
//! - Survives a 72-hour offline window trivially — the file is just there
//!   when the runtime comes back up.
//! - The same crate ships MQTT / HTTP siblings later without breaking the
//!   `TriggerSource` contract.

use std::path::PathBuf;
use std::sync::Arc;

use async_stream::try_stream;
use async_trait::async_trait;
use furcate_inference_core::{TriggerError, TriggerEvent, TriggerId, TriggerSource, TriggerStream};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};
use tokio::sync::Mutex;

/// `TriggerSource` impl for DPP lifecycle events delivered as JSON-Lines.
#[derive(Clone, Debug)]
pub struct DppLifecycleTrigger {
    id: TriggerId,
    feed_path: PathBuf,
}

impl DppLifecycleTrigger {
    /// Construct a lifecycle trigger that tails `feed_path` for newline-
    /// delimited JSON lifecycle events.
    #[must_use]
    pub fn new(id: impl Into<String>, feed_path: impl Into<PathBuf>) -> Self {
        Self {
            id: TriggerId(id.into()),
            feed_path: feed_path.into(),
        }
    }
}

fn parse_line(source: &TriggerId, line: &str) -> Option<TriggerEvent> {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "dpp lifecycle trigger: skipping malformed line");
            return None;
        }
    };
    let lifecycle = v.get("lifecycle").and_then(Value::as_str).map(String::from);
    let Some(lifecycle) = lifecycle else {
        tracing::warn!("dpp lifecycle trigger: skipping line missing 'lifecycle' field");
        return None;
    };
    let mut tags = vec![lifecycle];
    if let Some(arr) = v.get("tags").and_then(Value::as_array) {
        tags.extend(arr.iter().filter_map(|t| t.as_str().map(String::from)));
    }
    let payload = v.get("payload").cloned().unwrap_or(Value::Null);
    Some(TriggerEvent {
        source: source.clone(),
        tags,
        payload,
    })
}

#[async_trait]
impl TriggerSource for DppLifecycleTrigger {
    fn id(&self) -> TriggerId {
        self.id.clone()
    }

    async fn start(&self) -> std::result::Result<TriggerStream, TriggerError> {
        let path = self.feed_path.clone();
        let id = self.id.clone();

        // Open the file (creating an empty one is the caller's job — if the
        // feed doesn't exist that's a configuration bug). We seek to the end
        // so we only deliver *new* events; historical replay is a separate
        // concern (see `prvnz-edge-cli replay`).
        let mut file = tokio::fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .await
            .map_err(|e| TriggerError::Setup(format!("open feed {}: {e}", path.display())))?;
        let initial_pos = file
            .seek(SeekFrom::End(0))
            .await
            .map_err(|e| TriggerError::Setup(format!("seek end: {e}")))?;
        let reader = BufReader::new(file);
        let reader = Arc::new(Mutex::new(reader));

        // notify::recommended_watcher fires whenever the file is modified.
        // We wake an mpsc channel; the stream task then drains all new lines
        // from the last-known byte offset.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<notify::Result<Event>>();
        let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
            // Send-on-closed is fine — happens when the stream is dropped.
            let _ = tx.send(res);
        })
        .map_err(|e| TriggerError::Setup(format!("watcher init: {e}")))?;
        watcher
            .watch(&path, RecursiveMode::NonRecursive)
            .map_err(|e| TriggerError::Setup(format!("watch {}: {e}", path.display())))?;

        let stream = try_stream! {
            // Hold the watcher inside the stream so it stays alive for the
            // stream's lifetime. Dropping the stream drops the watcher and
            // releases the inotify/kqueue/FSEvents handle.
            let _watcher_guard = watcher;
            let mut last_pos = initial_pos;

            while let Some(event_res) = rx.recv().await {
                let event = match event_res {
                    Ok(ev) => ev,
                    Err(e) => {
                        tracing::warn!(error = %e, "notify error, skipping");
                        continue;
                    }
                };

                // Any Modify event triggers a re-read from the last offset.
                // We don't try to distinguish DataChange/Metadata/Name — the
                // re-read is the source of truth.
                if !matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    continue;
                }

                // Drain new bytes one line at a time. We lock the BufReader
                // for the whole drain so a fast burst of writes can't
                // interleave partial lines.
                let mut guard = reader.lock().await;
                if let Err(e) = guard.get_mut().seek(SeekFrom::Start(last_pos)).await {
                    Err(TriggerError::Terminated(format!("seek to {last_pos}: {e}")))?;
                }

                loop {
                    let mut line = String::new();
                    match guard.read_line(&mut line).await {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            last_pos += n as u64;
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                continue;
                            }
                            if let Some(ev) = parse_line(&id, trimmed) {
                                yield ev;
                            }
                        }
                        Err(e) => {
                            Err(TriggerError::Terminated(format!("read line: {e}")))?;
                        }
                    }
                }
                drop(guard);
            }
        };

        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    #[tokio::test(flavor = "current_thread")]
    async fn trigger_emits_appended_lines() {
        let dir = tempdir_for_tests();
        let feed = dir.join("events.jsonl");
        tokio::fs::write(&feed, b"").await.unwrap();

        let trigger = DppLifecycleTrigger::new("prvnz:lifecycle", &feed);
        let mut stream = trigger.start().await.unwrap();

        // Give notify a moment to install the watch.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut f = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&feed)
            .await
            .unwrap();
        f.write_all(
            br#"{"lifecycle":"onProductionComplete","tags":["public"],"payload":{"sku":"X"}}
"#,
        )
        .await
        .unwrap();
        f.flush().await.unwrap();

        let event = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await
            .expect("trigger did not fire within 3s")
            .expect("stream ended")
            .expect("trigger error");
        assert_eq!(
            event.tags.first().map(String::as_str),
            Some("onProductionComplete")
        );
        assert!(event.tags.iter().any(|t| t == "public"));
    }

    fn tempdir_for_tests() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("prvnz-trigger-{}", uuid_like()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn uuid_like() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{nanos:x}")
    }
}
