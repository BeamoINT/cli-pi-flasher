use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "macos")]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use piflasher_core::device::{BlockDevice, DeviceManager, FileBackedDeviceManager};
use piflasher_core::{CoreError, CoreResult};
use piflasher_protocol::{DeviceFingerprint, DeviceInfo};

#[derive(Clone, Debug)]
struct MacDiskSpec {
    id: String,
    node: String,
    raw_node: String,
    capacity_bytes: u64,
    removable: bool,
    is_system_disk: bool,
    bus: String,
    vendor: String,
    product: String,
    serial_or_path_hash: String,
}

#[derive(Default)]
struct MacDeviceManager {
    specs: Mutex<HashMap<String, MacDiskSpec>>,
    locks: Mutex<HashSet<String>>,
    sim: Option<FileBackedDeviceManager>,
}

pub fn default_manager() -> CoreResult<Arc<dyn DeviceManager>> {
    let sim = match std::env::var("PIFLASHER_SIM_DEVICE_DIR") {
        Ok(path) => Some(FileBackedDeviceManager::discover_from_dir(&PathBuf::from(
            path,
        ))?),
        Err(_) => None,
    };

    Ok(Arc::new(MacDeviceManager {
        specs: Mutex::new(HashMap::new()),
        locks: Mutex::new(HashSet::new()),
        sim,
    }))
}

pub fn backend_description() -> &'static str {
    "macOS backend (direct external physical disk discovery via diskutil, with optional simulated devices via PIFLASHER_SIM_DEVICE_DIR)"
}

pub fn ensure_supported() -> CoreResult<()> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        Err(CoreError::AgentUnavailable(
            "macOS backend requested on non-macOS target".to_string(),
        ))
    }
}

impl MacDeviceManager {
    fn refresh_specs(&self) -> CoreResult<()> {
        let disk_ids = discover_external_disks()?;
        let mut specs = HashMap::new();
        for disk_id in disk_ids {
            let spec = build_spec_for_disk(&disk_id)?;
            specs.insert(spec.id.clone(), spec);
        }

        let mut guard = self
            .specs
            .lock()
            .map_err(|_| CoreError::Internal("macOS spec map lock poisoned".to_string()))?;
        *guard = specs;
        Ok(())
    }

    fn lookup(&self, device_id: &str) -> CoreResult<MacDiskSpec> {
        let guard = self
            .specs
            .lock()
            .map_err(|_| CoreError::Internal("macOS spec map lock poisoned".to_string()))?;
        guard
            .get(device_id)
            .cloned()
            .ok_or_else(|| CoreError::InvalidRequest(format!("unknown device: {device_id}")))
    }

    fn mk_fingerprint(spec: &MacDiskSpec) -> DeviceFingerprint {
        let slack = spec.capacity_bytes / 50;
        let hash_prefix = &spec.serial_or_path_hash[..8.min(spec.serial_or_path_hash.len())];
        DeviceFingerprint {
            vid: "MAC0".to_string(),
            pid: "DISK".to_string(),
            usb_serial_or_path_hash: spec.serial_or_path_hash.clone(),
            vendor: spec.vendor.clone(),
            product: spec.product.clone(),
            capacity_min_bytes: spec.capacity_bytes.saturating_sub(slack),
            capacity_max_bytes: spec.capacity_bytes.saturating_add(slack),
        }
        .with_vid_pid(hash_prefix)
    }

    fn maybe_sim_id(id: &str) -> Option<&str> {
        id.strip_prefix("sim:")
    }

    fn add_simulated_devices(&self, mut devices: Vec<DeviceInfo>) -> CoreResult<Vec<DeviceInfo>> {
        if let Some(sim) = &self.sim {
            let mut sim_devices = sim.list_devices()?;
            for d in &mut sim_devices {
                d.id = format!("sim:{}", d.id);
            }
            devices.extend(sim_devices);
        }
        Ok(devices)
    }
}

impl DeviceManager for MacDeviceManager {
    fn list_devices(&self) -> CoreResult<Vec<DeviceInfo>> {
        self.refresh_specs()?;
        let specs = self
            .specs
            .lock()
            .map_err(|_| CoreError::Internal("macOS spec map lock poisoned".to_string()))?;

        let mut devices = specs
            .values()
            .map(|spec| {
                let mut reasons = Vec::new();
                if !spec.removable {
                    reasons.push("not_removable".to_string());
                }
                if spec.is_system_disk {
                    reasons.push("system_disk".to_string());
                }
                if matches!(
                    spec.bus.to_lowercase().as_str(),
                    "sata" | "pci" | "pcie" | "nvme"
                ) {
                    reasons.push("non_usb_bus".to_string());
                }

                DeviceInfo {
                    id: spec.id.clone(),
                    path: spec.raw_node.clone(),
                    removable: spec.removable,
                    is_system_disk: spec.is_system_disk,
                    capacity_bytes: spec.capacity_bytes,
                    bus: spec.bus.clone(),
                    vendor: spec.vendor.clone(),
                    product: spec.product.clone(),
                    fingerprint: Self::mk_fingerprint(spec),
                    eligible: reasons.is_empty(),
                    ineligible_reasons: reasons,
                }
            })
            .collect::<Vec<_>>();

        drop(specs);
        devices = self.add_simulated_devices(devices)?;
        devices.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(devices)
    }

    fn lock(&self, device_id: &str) -> CoreResult<()> {
        if let Some(sim_id) = Self::maybe_sim_id(device_id) {
            if let Some(sim) = &self.sim {
                return sim.lock(sim_id);
            }
        }

        let mut locks = self
            .locks
            .lock()
            .map_err(|_| CoreError::Internal("macOS lock set poisoned".to_string()))?;
        if locks.contains(device_id) {
            return Err(CoreError::DeviceBusy(format!(
                "device already locked: {device_id}"
            )));
        }

        let spec = self.lookup(device_id)?;
        let output = Command::new("diskutil")
            .args(["unmountDisk", "force", &spec.node])
            .output()
            .map_err(|e| {
                CoreError::DeviceBusy(format!("failed to run diskutil unmountDisk: {e}"))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CoreError::DeviceBusy(format!(
                "failed to unmount {}: {}",
                spec.node,
                stderr.trim()
            )));
        }

        locks.insert(device_id.to_string());
        Ok(())
    }

    fn unlock(&self, device_id: &str) -> CoreResult<()> {
        if let Some(sim_id) = Self::maybe_sim_id(device_id) {
            if let Some(sim) = &self.sim {
                return sim.unlock(sim_id);
            }
        }

        let mut locks = self
            .locks
            .lock()
            .map_err(|_| CoreError::Internal("macOS lock set poisoned".to_string()))?;
        locks.remove(device_id);
        Ok(())
    }

    fn open_for_write(&self, device_id: &str) -> CoreResult<Box<dyn BlockDevice>> {
        if let Some(sim_id) = Self::maybe_sim_id(device_id) {
            if let Some(sim) = &self.sim {
                return sim.open_for_write(sim_id);
            }
        }

        let spec = self.lookup(device_id)?;
        let file = open_raw_device_node(&spec.raw_node, true).map_err(|e| {
            CoreError::WriteIo(format!("failed to open {} for write: {e}", spec.raw_node))
        })?;
        Ok(Box::new(RawDiskBlockDevice {
            file,
            capacity: spec.capacity_bytes,
            cursor: 0,
        }))
    }

    fn open_for_read(&self, device_id: &str) -> CoreResult<Box<dyn BlockDevice>> {
        if let Some(sim_id) = Self::maybe_sim_id(device_id) {
            if let Some(sim) = &self.sim {
                return sim.open_for_read(sim_id);
            }
        }

        let spec = self.lookup(device_id)?;
        let file = open_raw_device_node(&spec.raw_node, false).map_err(|e| {
            CoreError::DeviceRemoved(format!("failed to open {} for read: {e}", spec.raw_node))
        })?;
        Ok(Box::new(RawDiskBlockDevice {
            file,
            capacity: spec.capacity_bytes,
            cursor: 0,
        }))
    }

    fn eject(&self, device_id: &str) -> CoreResult<()> {
        if let Some(sim_id) = Self::maybe_sim_id(device_id) {
            if let Some(sim) = &self.sim {
                return sim.eject(sim_id);
            }
        }

        let spec = self.lookup(device_id)?;
        let output = Command::new("diskutil")
            .args(["eject", &spec.node])
            .output()
            .map_err(|e| CoreError::DeviceBusy(format!("failed to run diskutil eject: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CoreError::DeviceBusy(format!(
                "failed to eject {}: {}",
                spec.node,
                stderr.trim()
            )));
        }

        Ok(())
    }
}

struct RawDiskBlockDevice {
    file: File,
    capacity: u64,
    cursor: u64,
}

impl BlockDevice for RawDiskBlockDevice {
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> CoreResult<usize> {
        if self.cursor != offset {
            self.file.seek(SeekFrom::Start(offset)).map_err(|e| {
                CoreError::WriteIo(format!(
                    "failed to seek raw device for write at offset {offset}: {e}"
                ))
            })?;
            self.cursor = offset;
        }
        let written = self.file.write(buf).map_err(|e| {
            CoreError::WriteIo(format!(
                "failed to write raw device at offset {offset}: {e}"
            ))
        })?;
        self.cursor = self.cursor.saturating_add(written as u64);
        Ok(written)
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> CoreResult<usize> {
        if self.cursor != offset {
            self.file.seek(SeekFrom::Start(offset)).map_err(|e| {
                CoreError::DeviceRemoved(format!(
                    "failed to seek raw device for read at offset {offset}: {e}"
                ))
            })?;
            self.cursor = offset;
        }
        let read = self.file.read(buf).map_err(|e| {
            CoreError::DeviceRemoved(format!("failed to read raw device at offset {offset}: {e}"))
        })?;
        self.cursor = self.cursor.saturating_add(read as u64);
        Ok(read)
    }

    fn flush(&mut self) -> CoreResult<()> {
        #[cfg(target_os = "macos")]
        {
            let fd = self.file.as_raw_fd();
            let rc = unsafe { libc::fcntl(fd, libc::F_FULLFSYNC, 0) };
            if rc == 0 {
                return Ok(());
            }
            let fullsync_err = std::io::Error::last_os_error();
            if !matches!(
                fullsync_err.raw_os_error(),
                Some(libc::ENOTTY) | Some(libc::EINVAL) | Some(libc::EOPNOTSUPP)
            ) {
                return Err(CoreError::WriteIo(format!(
                    "failed to fully sync raw device: {fullsync_err}"
                )));
            }
        }

        match self.file.sync_all() {
            Ok(()) => Ok(()),
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENOTTY) | Some(libc::EINVAL) | Some(libc::EOPNOTSUPP)
                ) =>
            {
                // Some raw disk nodes do not support fsync/fcntl sync ioctls.
                // Fall back to a global sync barrier before readback verification.
                unsafe { libc::sync() };
                Ok(())
            }
            Err(e) => Err(CoreError::WriteIo(format!(
                "failed to flush raw device: {e}"
            ))),
        }
    }

    fn capacity(&self) -> u64 {
        self.capacity
    }
}

fn open_raw_device_node(path: &str, write: bool) -> std::io::Result<File> {
    #[cfg(target_os = "macos")]
    {
        let mut opts = OpenOptions::new();
        opts.read(true);
        if write {
            opts.write(true);
            opts.custom_flags(libc::O_EXLOCK | libc::O_SYNC);
        } else {
            opts.custom_flags(libc::O_EXLOCK);
        }

        match opts.open(path) {
            Ok(file) => {
                tune_raw_fd(&file);
                return Ok(file);
            }
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EINVAL) | Some(libc::ENOTTY) | Some(libc::EOPNOTSUPP)
                ) =>
            {
                // Fall through to a basic open on systems/drivers that reject lock/sync flags.
            }
            Err(e) => return Err(e),
        }
    }

    let mut opts = OpenOptions::new();
    opts.read(true);
    if write {
        opts.write(true);
    }
    let file = opts.open(path)?;
    #[cfg(target_os = "macos")]
    tune_raw_fd(&file);
    Ok(file)
}

#[cfg(target_os = "macos")]
fn tune_raw_fd(file: &File) {
    let fd = file.as_raw_fd();
    // Best-effort tuning only; raw nodes may reject these controls on some adapters.
    unsafe {
        let _ = libc::fcntl(fd, libc::F_NOCACHE, 1);
    }
}

fn discover_external_disks() -> CoreResult<Vec<String>> {
    let output = Command::new("diskutil")
        .args(["list", "external", "physical"])
        .output()
        .map_err(|e| CoreError::AgentUnavailable(format!("failed to run diskutil list: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CoreError::AgentUnavailable(format!(
            "diskutil list failed: {}",
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ids = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("/dev/disk") {
            if let Some(path) = trimmed.split_whitespace().next() {
                if let Some(id) = path.trim_end_matches(':').strip_prefix("/dev/") {
                    ids.push(id.to_string());
                }
            }
        }
    }
    Ok(ids)
}

fn build_spec_for_disk(disk_id: &str) -> CoreResult<MacDiskSpec> {
    let cmd = format!(
        "diskutil info -plist {} | plutil -convert json -o - -",
        disk_id
    );
    let output = Command::new("sh")
        .args(["-c", &cmd])
        .output()
        .map_err(|e| CoreError::AgentUnavailable(format!("failed to run diskutil info: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CoreError::AgentUnavailable(format!(
            "diskutil info failed for {}: {}",
            disk_id,
            stderr.trim()
        )));
    }

    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| CoreError::Internal(format!("failed to parse diskutil JSON: {e}")))?;

    let node = value
        .get("DeviceNode")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("/dev/{disk_id}"));

    let raw_node = node.replacen("/dev/disk", "/dev/rdisk", 1);
    let capacity_bytes = value.get("TotalSize").and_then(value_to_u64).unwrap_or(0);
    let is_internal = value
        .get("Internal")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let removable = value
        .get("RemovableMedia")
        .and_then(|v| v.as_bool())
        .unwrap_or(!is_internal);
    let bus = value
        .get("BusProtocol")
        .or_else(|| value.get("Protocol"))
        .and_then(|v| v.as_str())
        .unwrap_or("USB")
        .to_string();
    let vendor = value
        .get("DeviceVendor")
        .or_else(|| value.get("Manufacturer"))
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();
    let product = value
        .get("MediaName")
        .or_else(|| value.get("DeviceModel"))
        .and_then(|v| v.as_str())
        .unwrap_or(disk_id)
        .to_string();

    let serial_seed = value
        .get("DiskUUID")
        .or_else(|| value.get("DeviceIdentifier"))
        .and_then(|v| v.as_str())
        .unwrap_or(disk_id);
    let serial_or_path_hash = blake3::hash(serial_seed.as_bytes()).to_hex().to_string();

    Ok(MacDiskSpec {
        id: disk_id.to_string(),
        node,
        raw_node,
        capacity_bytes,
        removable,
        is_system_disk: is_internal,
        bus,
        vendor,
        product,
        serial_or_path_hash,
    })
}

fn value_to_u64(value: &serde_json::Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    value.as_f64().map(|v| v as u64)
}

trait FingerprintExt {
    fn with_vid_pid(self, seed: &str) -> Self;
}

impl FingerprintExt for DeviceFingerprint {
    fn with_vid_pid(mut self, seed: &str) -> Self {
        let prefix = seed.chars().take(4).collect::<String>();
        self.vid = format!("M{}", prefix);
        self.pid = format!("D{}", prefix);
        self
    }
}
