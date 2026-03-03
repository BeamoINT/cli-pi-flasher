use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use piflasher_core::device::{BlockDevice, DeviceManager, FileBackedDeviceManager};
use piflasher_core::{CoreError, CoreResult};
use piflasher_protocol::{DeviceFingerprint, DeviceInfo};

#[derive(Clone, Debug)]
struct WindowsDiskSpec {
    id: String,
    path: String,
    capacity_bytes: u64,
    removable: bool,
    bus: String,
    vendor: String,
    product: String,
    serial_or_path_hash: String,
}

#[derive(Default)]
struct WindowsDeviceManager {
    specs: Mutex<HashMap<String, WindowsDiskSpec>>,
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

    Ok(Arc::new(WindowsDeviceManager {
        specs: Mutex::new(HashMap::new()),
        locks: Mutex::new(HashSet::new()),
        sim,
    }))
}

pub fn backend_description() -> &'static str {
    "Windows backend (direct USB disk discovery via PowerShell/CIM, with optional simulated devices via PIFLASHER_SIM_DEVICE_DIR)"
}

pub fn ensure_supported() -> CoreResult<()> {
    if cfg!(target_os = "windows") {
        Ok(())
    } else {
        Err(CoreError::AgentUnavailable(
            "Windows backend requested on non-Windows target".to_string(),
        ))
    }
}

impl WindowsDeviceManager {
    fn disk_number_from_id(device_id: &str) -> CoreResult<u32> {
        device_id
            .strip_prefix("disk")
            .ok_or_else(|| CoreError::InvalidRequest(format!("unexpected device id: {device_id}")))?
            .parse::<u32>()
            .map_err(|_| CoreError::InvalidRequest(format!("unexpected device id: {device_id}")))
    }

    fn refresh_specs(&self) -> CoreResult<()> {
        let disks = discover_usb_disks()?;
        let mut specs = HashMap::new();
        for spec in disks {
            specs.insert(spec.id.clone(), spec);
        }

        let mut guard = self
            .specs
            .lock()
            .map_err(|_| CoreError::Internal("windows spec map lock poisoned".to_string()))?;
        *guard = specs;
        Ok(())
    }

    fn lookup(&self, id: &str) -> CoreResult<WindowsDiskSpec> {
        let guard = self
            .specs
            .lock()
            .map_err(|_| CoreError::Internal("windows spec map lock poisoned".to_string()))?;
        guard
            .get(id)
            .cloned()
            .ok_or_else(|| CoreError::InvalidRequest(format!("unknown device: {id}")))
    }

    fn mk_fingerprint(spec: &WindowsDiskSpec) -> DeviceFingerprint {
        let slack = spec.capacity_bytes / 50;
        DeviceFingerprint {
            vid: "WIN0".to_string(),
            pid: "DISK".to_string(),
            usb_serial_or_path_hash: spec.serial_or_path_hash.clone(),
            vendor: spec.vendor.clone(),
            product: spec.product.clone(),
            capacity_min_bytes: spec.capacity_bytes.saturating_sub(slack),
            capacity_max_bytes: spec.capacity_bytes.saturating_add(slack),
        }
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

impl DeviceManager for WindowsDeviceManager {
    fn list_devices(&self) -> CoreResult<Vec<DeviceInfo>> {
        self.refresh_specs()?;
        let specs = self
            .specs
            .lock()
            .map_err(|_| CoreError::Internal("windows spec map lock poisoned".to_string()))?;

        let mut devices = specs
            .values()
            .map(|spec| {
                let mut reasons = Vec::new();
                if !spec.removable {
                    reasons.push("not_removable".to_string());
                }
                if !spec.bus.eq_ignore_ascii_case("usb") {
                    reasons.push("non_usb_bus".to_string());
                }

                DeviceInfo {
                    id: spec.id.clone(),
                    path: spec.path.clone(),
                    removable: spec.removable,
                    is_system_disk: false,
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
            .map_err(|_| CoreError::Internal("windows lock set poisoned".to_string()))?;
        if locks.contains(device_id) {
            return Err(CoreError::DeviceBusy(format!(
                "device already locked: {device_id}"
            )));
        }

        let disk_number = Self::disk_number_from_id(device_id)?;
        prepare_disk_for_raw_write(disk_number)?;
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
            .map_err(|_| CoreError::Internal("windows lock set poisoned".to_string()))?;
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
        let file = OpenOptions::new()
            .write(true)
            .open(&spec.path)
            .map_err(|e| CoreError::WriteIo(format!("failed to open {}: {e}", spec.path)))?;

        Ok(Box::new(RawDiskBlockDevice {
            file,
            capacity: spec.capacity_bytes,
        }))
    }

    fn open_for_read(&self, device_id: &str) -> CoreResult<Box<dyn BlockDevice>> {
        if let Some(sim_id) = Self::maybe_sim_id(device_id) {
            if let Some(sim) = &self.sim {
                return sim.open_for_read(sim_id);
            }
        }

        let spec = self.lookup(device_id)?;
        let file = OpenOptions::new()
            .read(true)
            .open(&spec.path)
            .map_err(|e| CoreError::DeviceRemoved(format!("failed to open {}: {e}", spec.path)))?;

        Ok(Box::new(RawDiskBlockDevice {
            file,
            capacity: spec.capacity_bytes,
        }))
    }

    fn eject(&self, device_id: &str) -> CoreResult<()> {
        if let Some(sim_id) = Self::maybe_sim_id(device_id) {
            if let Some(sim) = &self.sim {
                return sim.eject(sim_id);
            }
        }
        Ok(())
    }
}

struct RawDiskBlockDevice {
    file: File,
    capacity: u64,
}

impl BlockDevice for RawDiskBlockDevice {
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
        let read = self
            .file
            .read(buf)
            .map_err(|e| CoreError::DeviceRemoved(e.to_string()))?;
        Ok(read)
    }

    fn flush(&mut self) -> CoreResult<()> {
        self.file.sync_all().map_err(CoreError::Io)
    }

    fn capacity(&self) -> u64 {
        self.capacity
    }
}

fn discover_usb_disks() -> CoreResult<Vec<WindowsDiskSpec>> {
    let script = "Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' } | Select-Object Index,DeviceID,Model,Size,PNPDeviceID,MediaType,Manufacturer,InterfaceType,MediaLoaded | ConvertTo-Json -Compress";
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
        .map_err(|e| {
            CoreError::AgentUnavailable(format!("failed to run PowerShell disk discovery: {e}"))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CoreError::AgentUnavailable(format!(
            "PowerShell disk discovery failed: {}",
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() || stdout.eq_ignore_ascii_case("null") {
        return Ok(Vec::new());
    }

    let value: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| CoreError::Internal(format!("failed to parse PowerShell JSON: {e}")))?;

    let mut rows = Vec::new();
    match value {
        serde_json::Value::Array(arr) => rows.extend(arr),
        serde_json::Value::Object(_) => rows.push(value),
        _ => {}
    }

    let mut specs = Vec::new();
    for row in rows {
        let index = row.get("Index").and_then(value_to_u64).unwrap_or(9999);
        let path = row
            .get("DeviceID")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if path.is_empty() {
            continue;
        }

        let size = row.get("Size").and_then(value_to_u64).unwrap_or(0);
        let media_loaded = row
            .get("MediaLoaded")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if !media_loaded || size < 1_048_576 {
            // Windows can report placeholder USB disk entries (for example, empty multi-slot
            // readers) with a size of 0 bytes. These are not writable targets and create a
            // confusing extra drive option in the selector UI.
            continue;
        }

        let media_type = row
            .get("MediaType")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        let removable = media_type.contains("removable") || media_type.contains("external");
        let bus = row
            .get("InterfaceType")
            .and_then(|v| v.as_str())
            .unwrap_or("USB")
            .to_string();
        let vendor = row
            .get("Manufacturer")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();
        let product = row
            .get("Model")
            .and_then(|v| v.as_str())
            .unwrap_or("USB Disk")
            .to_string();
        let serial_seed = row
            .get("PNPDeviceID")
            .and_then(|v| v.as_str())
            .unwrap_or(&path);
        let serial_or_path_hash = blake3::hash(serial_seed.as_bytes()).to_hex().to_string();

        specs.push(WindowsDiskSpec {
            id: format!("disk{index}"),
            path,
            capacity_bytes: size,
            removable,
            bus,
            vendor,
            product,
            serial_or_path_hash,
        });
    }

    Ok(specs)
}

fn prepare_disk_for_raw_write(disk_number: u32) -> CoreResult<()> {
    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         Set-Disk -Number {disk_number} -IsReadOnly $false -ErrorAction Stop; \
         Get-Partition -DiskNumber {disk_number} -ErrorAction SilentlyContinue | \
         ForEach-Object {{ \
             $_.AccessPaths | \
             Where-Object {{ $_ -match '^[A-Za-z]:\\$' }} | \
             ForEach-Object {{ mountvol $_ /p | Out-Null }} \
         }}"
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .map_err(|e| CoreError::DeviceBusy(format!("failed to prepare disk {disk_number}: {e}")))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(CoreError::DeviceBusy(format!(
        "failed to dismount volumes on disk {disk_number}: {}",
        stderr.trim()
    )))
}

fn value_to_u64(value: &serde_json::Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    if let Some(s) = value.as_str() {
        return s.parse::<u64>().ok();
    }
    value.as_f64().map(|v| v as u64)
}
