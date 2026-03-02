use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use piflasher_protocol::{DeviceInfo, PolicyConfig, PolicyReader};

use crate::{CoreError, CoreResult};

#[derive(Clone)]
pub struct PolicyStore {
    path: PathBuf,
    policy: Arc<Mutex<PolicyConfig>>,
}

impl PolicyStore {
    pub fn load_or_default(path: &Path) -> CoreResult<Self> {
        let policy = if path.exists() {
            let raw = std::fs::read_to_string(path)?;
            toml::from_str::<PolicyConfig>(&raw)?
        } else {
            let policy = PolicyConfig::default();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let raw = toml::to_string_pretty(&policy)?;
            std::fs::write(path, raw)?;
            policy
        };

        Ok(Self {
            path: path.to_path_buf(),
            policy: Arc::new(Mutex::new(policy)),
        })
    }

    pub fn get(&self) -> CoreResult<PolicyConfig> {
        let guard = self
            .policy
            .lock()
            .map_err(|_| CoreError::Internal("policy lock poisoned".to_string()))?;
        Ok(guard.clone())
    }

    pub fn save(&self) -> CoreResult<()> {
        let guard = self
            .policy
            .lock()
            .map_err(|_| CoreError::Internal("policy lock poisoned".to_string()))?;
        let raw = toml::to_string_pretty(&*guard)?;
        std::fs::write(&self.path, raw)?;
        Ok(())
    }

    pub fn enroll_from_device(&self, device: &DeviceInfo, label: &str) -> CoreResult<()> {
        let mut guard = self
            .policy
            .lock()
            .map_err(|_| CoreError::Internal("policy lock poisoned".to_string()))?;

        let reader = PolicyReader {
            label: label.to_string(),
            fingerprint: device.fingerprint.clone(),
        };

        let exists = guard.allowed_readers.iter().any(|r| {
            r.fingerprint.usb_serial_or_path_hash == reader.fingerprint.usb_serial_or_path_hash
        });
        if !exists {
            guard.allowed_readers.push(reader);
        }

        drop(guard);
        self.save()
    }

    pub fn clear_quarantine(&self, device_key: &str) -> CoreResult<()> {
        let mut guard = self
            .policy
            .lock()
            .map_err(|_| CoreError::Internal("policy lock poisoned".to_string()))?;
        guard.quarantined_readers.retain(|v| v != device_key);
        drop(guard);
        self.save()
    }

    pub fn quarantine(&self, device_key: &str) -> CoreResult<()> {
        let mut guard = self
            .policy
            .lock()
            .map_err(|_| CoreError::Internal("policy lock poisoned".to_string()))?;
        if !guard.quarantined_readers.iter().any(|v| v == device_key) {
            guard.quarantined_readers.push(device_key.to_string());
        }
        drop(guard);
        self.save()
    }

    pub fn effective_parallel_limit(
        &self,
        requested: Option<u8>,
        detected_targets: usize,
    ) -> CoreResult<u8> {
        let policy = self.get()?;
        let policy_cap = policy.max_parallel.max(1);
        let detected_cap = detected_targets.clamp(1, 10) as u8;
        let requested = requested.unwrap_or(4).clamp(1, 10);
        Ok(requested.min(policy_cap).min(detected_cap))
    }

    pub fn is_device_allowed(&self, device: &DeviceInfo, noninteractive: bool) -> CoreResult<bool> {
        let policy = self.get()?;
        let quarantined = policy
            .quarantined_readers
            .iter()
            .any(|v| v == &device.id || v == &device.fingerprint.usb_serial_or_path_hash);
        if quarantined && noninteractive {
            return Ok(false);
        }

        if !noninteractive || !policy.require_fingerprint_noninteractive {
            return Ok(true);
        }

        let matched = policy.allowed_readers.iter().any(|reader| {
            let fp = &reader.fingerprint;
            fp.vid == device.fingerprint.vid
                && fp.pid == device.fingerprint.pid
                && fp.usb_serial_or_path_hash == device.fingerprint.usb_serial_or_path_hash
                && fp.vendor == device.fingerprint.vendor
                && fp.product == device.fingerprint.product
                && device.capacity_bytes >= fp.capacity_min_bytes
                && device.capacity_bytes <= fp.capacity_max_bytes
        });

        Ok(matched)
    }
}
