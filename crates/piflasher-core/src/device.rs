use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use piflasher_protocol::{DeviceFingerprint, DeviceInfo};

use crate::{CoreError, CoreResult};

pub trait BlockDevice: Send {
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> CoreResult<usize>;
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> CoreResult<usize>;
    fn flush(&mut self) -> CoreResult<()>;
    fn capacity(&self) -> u64;
}

pub trait DeviceManager: Send + Sync {
    fn list_devices(&self) -> CoreResult<Vec<DeviceInfo>>;
    fn lock(&self, device_id: &str) -> CoreResult<()>;
    fn unlock(&self, device_id: &str) -> CoreResult<()>;
    fn open_for_write(&self, device_id: &str) -> CoreResult<Box<dyn BlockDevice>>;
    fn open_for_read(&self, device_id: &str) -> CoreResult<Box<dyn BlockDevice>>;
    fn eject(&self, device_id: &str) -> CoreResult<()>;
}

#[derive(Clone, Debug)]
pub struct FileDeviceSpec {
    pub id: String,
    pub path: PathBuf,
    pub removable: bool,
    pub is_system_disk: bool,
    pub bus: String,
    pub vendor: String,
    pub product: String,
    pub vid: String,
    pub pid: String,
    pub serial_or_path_hash: String,
}

impl FileDeviceSpec {
    pub fn from_path(path: &Path) -> CoreResult<Self> {
        let canonical = std::fs::canonicalize(path)?;
        let id = canonical
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(|| CoreError::InvalidRequest("invalid device filename".to_string()))?
            .to_string();
        let hash = blake3::hash(canonical.to_string_lossy().as_bytes())
            .to_hex()
            .to_string();
        Ok(Self {
            id,
            path: canonical,
            removable: true,
            is_system_disk: false,
            bus: "usb".to_string(),
            vendor: "Simulated".to_string(),
            product: "FileBackedMicroSD".to_string(),
            vid: "SIM0".to_string(),
            pid: "SIM1".to_string(),
            serial_or_path_hash: hash,
        })
    }
}

#[derive(Clone, Default)]
pub struct FileBackedDeviceManager {
    devices: Arc<Mutex<HashMap<String, FileDeviceSpec>>>,
    locks: Arc<Mutex<HashSet<String>>>,
}

impl FileBackedDeviceManager {
    pub fn new(specs: Vec<FileDeviceSpec>) -> Self {
        let mut devices = HashMap::new();
        for spec in specs {
            devices.insert(spec.id.clone(), spec);
        }
        Self {
            devices: Arc::new(Mutex::new(devices)),
            locks: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn discover_from_dir(path: &Path) -> CoreResult<Self> {
        let mut specs = Vec::new();
        if !path.exists() {
            return Ok(Self::new(specs));
        }
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            if p.extension().and_then(|v| v.to_str()) != Some("imgdev") {
                continue;
            }
            specs.push(FileDeviceSpec::from_path(&p)?);
        }
        Ok(Self::new(specs))
    }

    pub fn register(&self, spec: FileDeviceSpec) {
        let mut devices = self
            .devices
            .lock()
            .expect("device manager lock poisoned while registering");
        devices.insert(spec.id.clone(), spec);
    }

    fn lookup(&self, device_id: &str) -> CoreResult<FileDeviceSpec> {
        let devices = self
            .devices
            .lock()
            .map_err(|_| CoreError::Internal("device map lock poisoned".to_string()))?;
        devices
            .get(device_id)
            .cloned()
            .ok_or_else(|| CoreError::InvalidRequest(format!("unknown device: {device_id}")))
    }

    fn fingerprint(spec: &FileDeviceSpec, capacity: u64) -> DeviceFingerprint {
        let slack = capacity / 50;
        DeviceFingerprint {
            vid: spec.vid.clone(),
            pid: spec.pid.clone(),
            usb_serial_or_path_hash: spec.serial_or_path_hash.clone(),
            vendor: spec.vendor.clone(),
            product: spec.product.clone(),
            capacity_min_bytes: capacity.saturating_sub(slack),
            capacity_max_bytes: capacity.saturating_add(slack),
        }
    }
}

impl DeviceManager for FileBackedDeviceManager {
    fn list_devices(&self) -> CoreResult<Vec<DeviceInfo>> {
        let devices = self
            .devices
            .lock()
            .map_err(|_| CoreError::Internal("device map lock poisoned".to_string()))?;

        let mut result = Vec::with_capacity(devices.len());
        for spec in devices.values() {
            let capacity = std::fs::metadata(&spec.path)?.len();
            let fingerprint = Self::fingerprint(spec, capacity);
            let mut reasons = Vec::new();
            if !spec.removable {
                reasons.push("not_removable".to_string());
            }
            if spec.is_system_disk {
                reasons.push("system_disk".to_string());
            }
            result.push(DeviceInfo {
                id: spec.id.clone(),
                path: spec.path.to_string_lossy().to_string(),
                removable: spec.removable,
                is_system_disk: spec.is_system_disk,
                capacity_bytes: capacity,
                bus: spec.bus.clone(),
                vendor: spec.vendor.clone(),
                product: spec.product.clone(),
                fingerprint,
                eligible: reasons.is_empty(),
                ineligible_reasons: reasons,
            });
        }

        result.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(result)
    }

    fn lock(&self, device_id: &str) -> CoreResult<()> {
        let mut locks = self
            .locks
            .lock()
            .map_err(|_| CoreError::Internal("device lock set poisoned".to_string()))?;
        if locks.contains(device_id) {
            return Err(CoreError::DeviceBusy(format!(
                "device already locked: {device_id}"
            )));
        }
        locks.insert(device_id.to_string());
        Ok(())
    }

    fn unlock(&self, device_id: &str) -> CoreResult<()> {
        let mut locks = self
            .locks
            .lock()
            .map_err(|_| CoreError::Internal("device lock set poisoned".to_string()))?;
        locks.remove(device_id);
        Ok(())
    }

    fn open_for_write(&self, device_id: &str) -> CoreResult<Box<dyn BlockDevice>> {
        let spec = self.lookup(device_id)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(spec.path)
            .map_err(|e| CoreError::WriteIo(format!("open for write failed: {e}")))?;
        let cap = file.metadata()?.len();
        Ok(Box::new(FileBlockDevice {
            file,
            capacity: cap,
        }))
    }

    fn open_for_read(&self, device_id: &str) -> CoreResult<Box<dyn BlockDevice>> {
        let spec = self.lookup(device_id)?;
        let file = OpenOptions::new()
            .read(true)
            .open(spec.path)
            .map_err(|e| CoreError::DeviceRemoved(format!("open for read failed: {e}")))?;
        let cap = file.metadata()?.len();
        Ok(Box::new(FileBlockDevice {
            file,
            capacity: cap,
        }))
    }

    fn eject(&self, _device_id: &str) -> CoreResult<()> {
        Ok(())
    }
}

struct FileBlockDevice {
    file: File,
    capacity: u64,
}

impl BlockDevice for FileBlockDevice {
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> CoreResult<usize> {
        self.file.seek(SeekFrom::Start(offset))?;
        let written = self
            .file
            .write(buf)
            .map_err(|e| CoreError::WriteIo(e.to_string()))?;
        Ok(written)
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> CoreResult<usize> {
        self.file.seek(SeekFrom::Start(offset))?;
        let n = self
            .file
            .read(buf)
            .map_err(|e| CoreError::DeviceRemoved(e.to_string()))?;
        Ok(n)
    }

    fn flush(&mut self) -> CoreResult<()> {
        self.file.sync_all().map_err(CoreError::Io)
    }

    fn capacity(&self) -> u64 {
        self.capacity
    }
}
