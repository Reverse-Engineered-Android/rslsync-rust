use crate::secret::ShareKey;
use crate::selective::SyncSelection;
use crate::server_state::{ServerStateStore, SyncRunRecord};
use crate::sync_session::SyncNode;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone)]
pub struct SyncManager {
    state: Arc<ServerStateStore>,
    running: Arc<Mutex<HashSet<String>>>,
}

impl SyncManager {
    pub fn new(state: Arc<ServerStateStore>) -> Self {
        Self {
            state,
            running: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn start_scheduler(self) {
        thread::spawn(move || loop {
            if let Err(error) = self.run_due_syncs() {
                eprintln!("automatic sync scheduler failed: {error:#}");
            }
            thread::sleep(Duration::from_secs(5));
        });
    }

    pub fn start_manual(&self, folder_id: &str) -> Result<SyncRunRecord> {
        self.start(folder_id, "manual")
    }

    pub fn run_due_syncs(&self) -> Result<()> {
        for folder in self.state.list_folders()? {
            let Some(settings) = &folder.sync else {
                continue;
            };
            if !folder.enabled || !settings.auto_sync {
                continue;
            }
            let now = crate::server_state::unix_time();
            let due_at = folder
                .last_sync
                .as_ref()
                .and_then(|run| run.completed_at.or(Some(run.started_at)))
                .map(|timestamp| timestamp + settings.sync_interval_seconds)
                .unwrap_or(0);
            if now < due_at {
                continue;
            }
            if let Err(error) = self.start(&folder.id, "auto") {
                if !error.to_string().contains("already running") {
                    eprintln!("automatic sync failed for {}: {error:#}", folder.name);
                }
            }
        }
        Ok(())
    }

    pub fn is_running(&self, folder_id: &str) -> bool {
        self.running
            .lock()
            .expect("sync run lock poisoned")
            .contains(folder_id)
    }

    fn start(&self, folder_id: &str, trigger: &str) -> Result<SyncRunRecord> {
        let folder = self.state.get_folder(folder_id)?;
        let settings = folder
            .sync
            .clone()
            .context("folder has no synchronization link")?;
        if !folder.enabled {
            anyhow::bail!("folder is disabled");
        }
        if settings.peers.is_empty() {
            anyhow::bail!("folder has no synchronization peers");
        }
        {
            let mut running = self.running.lock().expect("sync run lock poisoned");
            if !running.insert(folder_id.to_owned()) {
                anyhow::bail!("sync is already running for this folder");
            }
        }
        let run_id = random_id();
        let record = match self.state.record_sync_start(folder_id, &run_id, trigger) {
            Ok(record) => record,
            Err(error) => {
                self.running
                    .lock()
                    .expect("sync run lock poisoned")
                    .remove(folder_id);
                return Err(error);
            }
        };
        let state = Arc::clone(&self.state);
        let running = Arc::clone(&self.running);
        let folder_id = folder_id.to_owned();
        thread::spawn(move || {
            let mut successes = Vec::new();
            let mut failures = Vec::new();
            for peer in &settings.peers {
                let result = run_sync_once(
                    &folder.path,
                    &settings.key,
                    &settings.device_name,
                    &folder.include,
                    &folder.exclude,
                    peer,
                );
                match result {
                    Ok(()) => successes.push(peer.clone()),
                    Err(error) => failures.push(format!("{peer}: {error:#}")),
                }
            }
            let (status, message) = if failures.is_empty() {
                (
                    "success",
                    Some(format!("synchronized with {}", successes.join(", "))),
                )
            } else if successes.is_empty() {
                ("error", Some(failures.join("; ")))
            } else {
                (
                    "partial",
                    Some(format!(
                        "synchronized with {}; failed: {}",
                        successes.join(", "),
                        failures.join("; ")
                    )),
                )
            };
            if let Err(error) = state.record_sync_finish(&run_id, status, message) {
                eprintln!("record sync completion failed: {error:#}");
            }
            running
                .lock()
                .expect("sync run lock poisoned")
                .remove(&folder_id);
        });
        Ok(record)
    }
}

fn run_sync_once(
    root: &std::path::Path,
    key: &str,
    device_name: &str,
    include: &Option<String>,
    exclude: &Option<String>,
    peer: &str,
) -> Result<()> {
    let key = ShareKey::parse(key)?;
    let selection = SyncSelection::from_csv(include.as_deref(), exclude.as_deref())?;
    let sync = SyncNode::new(root, key, device_name)?.with_selection(selection);
    sync.connect_any_once(peer)
}

fn random_id() -> String {
    use rand::RngCore;
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
