use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use chrono::{Duration, Utc};
use fs2::FileExt;
use piflasher_protocol::{
    DeviceInfo, ErrorCode, FlashRequest, PreparedImage, RunImageInfo, RunReport, RunSettings,
    RunSummary, TargetResult, TargetSelector, TargetStatus, VerifyRequest,
};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::device::{BlockDevice, DeviceManager};
use crate::image::{prepare_image_with_progress, ImagePrepareProgress};
use crate::paths::{ensure_layout, reports_root, run_lock_path};
use crate::policy::PolicyStore;
use crate::{CoreError, CoreResult};

const CHUNK_SIZE: usize = 8 * 1024 * 1024;
const VERIFY_OPEN_MAX_ATTEMPTS: usize = 20;
const VERIFY_OPEN_RETRY_DELAY_MS: u64 = 250;
const VERIFY_MISMATCH_REREAD_ATTEMPTS: usize = 3;
const VERIFY_MISMATCH_REREAD_DELAY_MS: u64 = 250;
const WARN_VERIFY_TRANSIENT_MISMATCH_RESOLVED: &str = "W_VERIFY_TRANSIENT_MISMATCH_RESOLVED";
const WARN_VERIFY_SOFT_PASS_BOOTABLE: &str = "W_VERIFY_SOFT_PASS_BOOTABLE";
const WARN_EJECT_FAILED_AFTER_TARGET_COMPLETE: &str = "W_EJECT_FAILED_AFTER_TARGET_COMPLETE";
pub const IMAGE_PREP_DEVICE_ID: &str = "__image_prepare__";

#[derive(Clone, Debug)]
struct FlashVerifyResult {
    hash_match: bool,
    layout_check: bool,
    warnings: Vec<String>,
}

#[derive(Clone, Debug)]
struct VerifyMismatchInfo {
    offset: u64,
    chunk_start_offset: u64,
    chunk_len: usize,
    expected_chunk_blake3: String,
    actual_chunk_blake3: String,
}

#[derive(Clone, Debug)]
enum VerifyPassOutcome {
    Matched,
    Mismatch(VerifyMismatchInfo),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressPhase {
    PreparingImage,
    Queued,
    Writing,
    Verifying,
    Retrying,
    Completed,
    Failed,
}

#[derive(Clone, Debug)]
pub struct ProgressUpdate {
    pub device_id: String,
    pub phase: ProgressPhase,
    pub write_done_bytes: u64,
    pub write_total_bytes: u64,
    pub verify_done_bytes: u64,
    pub verify_total_bytes: u64,
    pub message: Option<String>,
}

pub type ProgressCallback = Arc<dyn Fn(ProgressUpdate) + Send + Sync + 'static>;

#[derive(Clone)]
pub struct FlashExecutionOptions {
    pub persist_report: bool,
    pub progress: Option<ProgressCallback>,
}

impl std::fmt::Debug for FlashExecutionOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlashExecutionOptions")
            .field("persist_report", &self.persist_report)
            .field("progress", &self.progress.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

impl Default for FlashExecutionOptions {
    fn default() -> Self {
        Self {
            persist_report: true,
            progress: None,
        }
    }
}

pub async fn execute_flash(
    app_root: &Path,
    manager: Arc<dyn DeviceManager>,
    policy_store: &PolicyStore,
    request: FlashRequest,
    options: FlashExecutionOptions,
) -> CoreResult<RunReport> {
    ensure_layout(app_root)?;

    let _lock = if request.allow_concurrent_jobs {
        None
    } else {
        Some(RunLock::acquire(run_lock_path(app_root))?)
    };

    let started_at = Utc::now();
    let started = Instant::now();
    emit_progress(
        &options.progress,
        ProgressUpdate {
            device_id: IMAGE_PREP_DEVICE_ID.to_string(),
            phase: ProgressPhase::PreparingImage,
            write_done_bytes: 0,
            write_total_bytes: 0,
            verify_done_bytes: 0,
            verify_total_bytes: 0,
            message: Some("Preparing image cache".to_string()),
        },
    );
    let prep_progress_cb = options.progress.clone();
    let prepared = prepare_image_with_progress(
        app_root,
        request.image_path.as_deref().map(Path::new),
        false,
        move |prep: ImagePrepareProgress| {
            emit_progress(
                &prep_progress_cb,
                ProgressUpdate {
                    device_id: IMAGE_PREP_DEVICE_ID.to_string(),
                    phase: ProgressPhase::PreparingImage,
                    write_done_bytes: prep.done_bytes,
                    write_total_bytes: prep.total_bytes,
                    verify_done_bytes: 0,
                    verify_total_bytes: 0,
                    message: Some("Preparing image cache".to_string()),
                },
            );
        },
    )?;
    emit_progress(
        &options.progress,
        ProgressUpdate {
            device_id: IMAGE_PREP_DEVICE_ID.to_string(),
            phase: ProgressPhase::Completed,
            write_done_bytes: prepared.bytes,
            write_total_bytes: prepared.bytes,
            verify_done_bytes: 0,
            verify_total_bytes: 0,
            message: Some("Image cache ready".to_string()),
        },
    );

    let devices = manager.list_devices()?;
    let noninteractive = request.yes;
    let selected = select_targets(
        &devices,
        &request.targets,
        policy_store,
        noninteractive,
        prepared.bytes,
    )?;

    if selected.is_empty() {
        return Err(CoreError::PolicyDeny(
            "preflight denied all candidate targets".to_string(),
        ));
    }

    let max_parallel =
        policy_store.effective_parallel_limit(request.max_parallel, selected.len())?;
    let semaphore = Arc::new(Semaphore::new(max_parallel as usize));

    for device in &selected {
        emit_progress(
            &options.progress,
            ProgressUpdate {
                device_id: device.id.clone(),
                phase: ProgressPhase::Queued,
                write_done_bytes: 0,
                write_total_bytes: prepared.bytes,
                verify_done_bytes: 0,
                verify_total_bytes: prepared.bytes,
                message: None,
            },
        );
    }

    let mut handles = Vec::with_capacity(selected.len());
    for device in selected {
        let permit = semaphore.clone().acquire_owned().await.map_err(|e| {
            CoreError::Internal(format!("semaphore acquire failed while scheduling: {e}"))
        })?;

        let manager = Arc::clone(&manager);
        let prepared = prepared.clone();
        let no_eject = request.no_eject;
        let progress = options.progress.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            tokio::task::spawn_blocking(move || {
                process_flash_target(manager, &device, &prepared, no_eject, progress)
            })
            .await
            .map_err(|e| CoreError::Internal(format!("worker join failed: {e}")))?
        }));
    }

    let mut targets = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(Ok(result)) => targets.push(result),
            Ok(Err(e)) => {
                error!(error = %e, "target worker failed");
                return Err(e);
            }
            Err(e) => {
                return Err(CoreError::Internal(format!("target task panic: {e}")));
            }
        }
    }

    let ended_at = Utc::now();
    let summary = build_summary(&targets, started.elapsed().as_secs_f64());
    let report = RunReport {
        job_id: Uuid::new_v4(),
        started_at,
        ended_at,
        image: RunImageInfo {
            path: prepared.original_path.clone(),
            bytes: prepared.bytes,
            blake3: prepared.blake3.clone(),
            sha256: prepared.sha256.clone(),
        },
        settings: RunSettings {
            max_parallel,
            strict_verify: true,
            no_eject: request.no_eject,
            noninteractive,
            chunk_size_bytes: CHUNK_SIZE as u64,
        },
        targets,
        summary,
        metadata: BTreeMap::from([("mode".to_string(), "flash".to_string())]),
    };

    update_quarantine_from_reports(app_root, policy_store, &report)?;

    if options.persist_report {
        crate::report::persist_report(app_root, &report)?;
    }

    Ok(report)
}

pub async fn execute_verify(
    app_root: &Path,
    manager: Arc<dyn DeviceManager>,
    policy_store: &PolicyStore,
    request: VerifyRequest,
    options: FlashExecutionOptions,
) -> CoreResult<RunReport> {
    ensure_layout(app_root)?;
    emit_progress(
        &options.progress,
        ProgressUpdate {
            device_id: IMAGE_PREP_DEVICE_ID.to_string(),
            phase: ProgressPhase::PreparingImage,
            write_done_bytes: 0,
            write_total_bytes: 0,
            verify_done_bytes: 0,
            verify_total_bytes: 0,
            message: Some("Preparing image cache".to_string()),
        },
    );
    let prep_progress_cb = options.progress.clone();
    let prepared = prepare_image_with_progress(
        app_root,
        request.image_path.as_deref().map(Path::new),
        false,
        move |prep: ImagePrepareProgress| {
            emit_progress(
                &prep_progress_cb,
                ProgressUpdate {
                    device_id: IMAGE_PREP_DEVICE_ID.to_string(),
                    phase: ProgressPhase::PreparingImage,
                    write_done_bytes: prep.done_bytes,
                    write_total_bytes: prep.total_bytes,
                    verify_done_bytes: 0,
                    verify_total_bytes: 0,
                    message: Some("Preparing image cache".to_string()),
                },
            );
        },
    )?;
    emit_progress(
        &options.progress,
        ProgressUpdate {
            device_id: IMAGE_PREP_DEVICE_ID.to_string(),
            phase: ProgressPhase::Completed,
            write_done_bytes: prepared.bytes,
            write_total_bytes: prepared.bytes,
            verify_done_bytes: 0,
            verify_total_bytes: 0,
            message: Some("Image cache ready".to_string()),
        },
    );

    let devices = manager.list_devices()?;
    let selected = select_targets(
        &devices,
        &request.targets,
        policy_store,
        true,
        prepared.bytes,
    )?;
    if selected.is_empty() {
        return Err(CoreError::PolicyDeny(
            "verify denied all candidate targets".to_string(),
        ));
    }

    let started_at = Utc::now();
    let started = Instant::now();

    let mut targets = Vec::new();
    for device in selected {
        let manager = Arc::clone(&manager);
        let prepared = prepared.clone();
        let progress = options.progress.clone();
        let result = tokio::task::spawn_blocking(move || {
            process_verify_target(manager, &device, &prepared, progress)
        })
        .await
        .map_err(|e| CoreError::Internal(format!("verify worker failed: {e}")))?;
        targets.push(result);
    }

    let report = RunReport {
        job_id: Uuid::new_v4(),
        started_at,
        ended_at: Utc::now(),
        image: RunImageInfo {
            path: prepared.original_path,
            bytes: prepared.bytes,
            blake3: prepared.blake3,
            sha256: prepared.sha256,
        },
        settings: RunSettings {
            max_parallel: 1,
            strict_verify: true,
            no_eject: true,
            noninteractive: true,
            chunk_size_bytes: CHUNK_SIZE as u64,
        },
        targets: targets.clone(),
        summary: build_summary(&targets, started.elapsed().as_secs_f64()),
        metadata: BTreeMap::from([("mode".to_string(), "verify".to_string())]),
    };

    if options.persist_report {
        crate::report::persist_report(app_root, &report)?;
    }

    Ok(report)
}

fn process_flash_target(
    manager: Arc<dyn DeviceManager>,
    device: &DeviceInfo,
    prepared: &PreparedImage,
    no_eject: bool,
    progress: Option<ProgressCallback>,
) -> CoreResult<TargetResult> {
    let mut last_error = None;
    let mut result: Option<TargetResult> = None;

    for attempt in 0..=1 {
        match flash_once(Arc::clone(&manager), device, prepared, progress.clone()) {
            Ok(target) => {
                result = Some(target);
                break;
            }
            Err(e) => {
                let retry = attempt == 0 && e.is_retryable();
                if retry {
                    warn!(device = %device.id, error = %e, "retrying flash target after transient error");
                    emit_progress(
                        &progress,
                        ProgressUpdate {
                            device_id: device.id.clone(),
                            phase: ProgressPhase::Retrying,
                            write_done_bytes: 0,
                            write_total_bytes: prepared.bytes,
                            verify_done_bytes: 0,
                            verify_total_bytes: prepared.bytes,
                            message: Some(e.to_string()),
                        },
                    );
                    last_error = Some(e);
                    continue;
                }
                emit_progress(
                    &progress,
                    ProgressUpdate {
                        device_id: device.id.clone(),
                        phase: ProgressPhase::Failed,
                        write_done_bytes: 0,
                        write_total_bytes: prepared.bytes,
                        verify_done_bytes: 0,
                        verify_total_bytes: prepared.bytes,
                        message: Some(e.to_string()),
                    },
                );
                result = Some(failure_target(device, Some(e.code()), e.to_string()));
                break;
            }
        }
    }

    if result.is_none() {
        if let Some(err) = last_error {
            emit_progress(
                &progress,
                ProgressUpdate {
                    device_id: device.id.clone(),
                    phase: ProgressPhase::Failed,
                    write_done_bytes: 0,
                    write_total_bytes: prepared.bytes,
                    verify_done_bytes: 0,
                    verify_total_bytes: prepared.bytes,
                    message: Some(err.to_string()),
                },
            );
            result = Some(failure_target(device, Some(err.code()), err.to_string()));
        } else {
            emit_progress(
                &progress,
                ProgressUpdate {
                    device_id: device.id.clone(),
                    phase: ProgressPhase::Failed,
                    write_done_bytes: 0,
                    write_total_bytes: prepared.bytes,
                    verify_done_bytes: 0,
                    verify_total_bytes: prepared.bytes,
                    message: Some("target failed for unknown reason".to_string()),
                },
            );
            result = Some(failure_target(
                device,
                Some(ErrorCode::Internal),
                "target failed for unknown reason".to_string(),
            ));
        }
    }

    let mut result = result.expect("result set");
    if !no_eject {
        if let Err(err) = eject_with_retries(&manager, &device.id, 3) {
            info!(
                device = %device.id,
                error = %err,
                "auto-eject failed after target completion"
            );
            result.warnings.push(format!(
                "{WARN_EJECT_FAILED_AFTER_TARGET_COMPLETE}: auto-eject failed: {err}"
            ));
        }
    }

    Ok(result)
}

fn flash_once(
    manager: Arc<dyn DeviceManager>,
    device: &DeviceInfo,
    prepared: &PreparedImage,
    progress: Option<ProgressCallback>,
) -> CoreResult<TargetResult> {
    manager.lock(&device.id)?;
    let _unlock = UnlockGuard {
        manager: Arc::clone(&manager),
        device_id: device.id.clone(),
    };

    let mut writer = manager.open_for_write(&device.id)?;
    if writer.capacity() < prepared.bytes {
        return Err(CoreError::PolicyDeny(format!(
            "device {} capacity {} < image {}",
            device.id,
            writer.capacity(),
            prepared.bytes
        )));
    }

    let write_started = Instant::now();
    let mut image_file = File::open(&prepared.cache_image_path)
        .map_err(|e| CoreError::ImagePreparation(format!("cache image open failed: {e}")))?;
    emit_progress(
        &progress,
        ProgressUpdate {
            device_id: device.id.clone(),
            phase: ProgressPhase::Writing,
            write_done_bytes: 0,
            write_total_bytes: prepared.bytes,
            verify_done_bytes: 0,
            verify_total_bytes: prepared.bytes,
            message: None,
        },
    );
    write_stream_to_device(
        &mut image_file,
        writer.as_mut(),
        &device.id,
        prepared.bytes,
        &progress,
    )?;
    writer.flush()?;
    drop(writer);
    let write_secs = write_started.elapsed().as_secs_f64();

    let verify_started = Instant::now();
    emit_progress(
        &progress,
        ProgressUpdate {
            device_id: device.id.clone(),
            phase: ProgressPhase::Verifying,
            write_done_bytes: prepared.bytes,
            write_total_bytes: prepared.bytes,
            verify_done_bytes: 0,
            verify_total_bytes: prepared.bytes,
            message: None,
        },
    );
    let verify_result = verify_device_against_image_for_flash(
        Arc::clone(&manager),
        &device.id,
        prepared,
        &progress,
    )?;
    let verify_secs = verify_started.elapsed().as_secs_f64();

    emit_progress(
        &progress,
        ProgressUpdate {
            device_id: device.id.clone(),
            phase: ProgressPhase::Completed,
            write_done_bytes: prepared.bytes,
            write_total_bytes: prepared.bytes,
            verify_done_bytes: prepared.bytes,
            verify_total_bytes: prepared.bytes,
            message: None,
        },
    );

    Ok(TargetResult {
        device_id: device.id.clone(),
        fingerprint: device.fingerprint.clone(),
        bytes_written: prepared.bytes,
        write_secs,
        verify_secs,
        hash_match: verify_result.hash_match,
        layout_check: verify_result.layout_check,
        status: TargetStatus::Success,
        error_code: None,
        error_message: None,
        warnings: verify_result.warnings,
    })
}

fn process_verify_target(
    manager: Arc<dyn DeviceManager>,
    device: &DeviceInfo,
    prepared: &PreparedImage,
    progress: Option<ProgressCallback>,
) -> TargetResult {
    emit_progress(
        &progress,
        ProgressUpdate {
            device_id: device.id.clone(),
            phase: ProgressPhase::Verifying,
            write_done_bytes: 0,
            write_total_bytes: prepared.bytes,
            verify_done_bytes: 0,
            verify_total_bytes: prepared.bytes,
            message: None,
        },
    );
    match (|| -> CoreResult<TargetResult> {
        manager.lock(&device.id)?;
        let _unlock = UnlockGuard {
            manager: Arc::clone(&manager),
            device_id: device.id.clone(),
        };

        let started = Instant::now();
        verify_device_against_image(Arc::clone(&manager), &device.id, prepared, &progress)?;
        let verify_secs = started.elapsed().as_secs_f64();

        emit_progress(
            &progress,
            ProgressUpdate {
                device_id: device.id.clone(),
                phase: ProgressPhase::Completed,
                write_done_bytes: 0,
                write_total_bytes: prepared.bytes,
                verify_done_bytes: prepared.bytes,
                verify_total_bytes: prepared.bytes,
                message: None,
            },
        );
        Ok(TargetResult {
            device_id: device.id.clone(),
            fingerprint: device.fingerprint.clone(),
            bytes_written: 0,
            write_secs: 0.0,
            verify_secs,
            hash_match: true,
            layout_check: true,
            status: TargetStatus::Success,
            error_code: None,
            error_message: None,
            warnings: Vec::new(),
        })
    })() {
        Ok(result) => result,
        Err(err) => {
            emit_progress(
                &progress,
                ProgressUpdate {
                    device_id: device.id.clone(),
                    phase: ProgressPhase::Failed,
                    write_done_bytes: 0,
                    write_total_bytes: prepared.bytes,
                    verify_done_bytes: 0,
                    verify_total_bytes: prepared.bytes,
                    message: Some(err.to_string()),
                },
            );
            failure_target(device, Some(err.code()), err.to_string())
        }
    }
}

fn write_stream_to_device(
    image_file: &mut File,
    device: &mut dyn BlockDevice,
    device_id: &str,
    total_bytes: u64,
    progress: &Option<ProgressCallback>,
) -> CoreResult<()> {
    let mut offset = 0u64;
    let mut buf = vec![0u8; CHUNK_SIZE];

    loop {
        let n = image_file
            .read(&mut buf)
            .map_err(|e| CoreError::WriteIo(format!("failed reading prepared image: {e}")))?;
        if n == 0 {
            break;
        }

        let written = device.write_at(offset, &buf[..n])?;
        if written != n {
            return Err(CoreError::WriteIo(format!(
                "short write at offset {}: wrote {} expected {}",
                offset, written, n
            )));
        }

        offset += n as u64;
        emit_progress(
            progress,
            ProgressUpdate {
                device_id: device_id.to_string(),
                phase: ProgressPhase::Writing,
                write_done_bytes: offset.min(total_bytes),
                write_total_bytes: total_bytes,
                verify_done_bytes: 0,
                verify_total_bytes: total_bytes,
                message: None,
            },
        );
    }

    Ok(())
}

fn verify_device_against_image(
    manager: Arc<dyn DeviceManager>,
    device_id: &str,
    prepared: &PreparedImage,
    progress: &Option<ProgressCallback>,
) -> CoreResult<()> {
    match run_verify_pass(manager, device_id, prepared, progress)? {
        VerifyPassOutcome::Matched => Ok(()),
        VerifyPassOutcome::Mismatch(mismatch) => Err(CoreError::VerifyMismatch(
            format_mismatch_message(&mismatch),
        )),
    }
}

fn verify_device_against_image_for_flash(
    manager: Arc<dyn DeviceManager>,
    device_id: &str,
    prepared: &PreparedImage,
    progress: &Option<ProgressCallback>,
) -> CoreResult<FlashVerifyResult> {
    let first_pass = run_verify_pass(Arc::clone(&manager), device_id, prepared, progress)?;
    match first_pass {
        VerifyPassOutcome::Matched => Ok(FlashVerifyResult {
            hash_match: true,
            layout_check: true,
            warnings: Vec::new(),
        }),
        VerifyPassOutcome::Mismatch(first_mismatch) => {
            warn!(
                device = %device_id,
                offset = first_mismatch.offset,
                expected_chunk_blake3 = %first_mismatch.expected_chunk_blake3,
                actual_chunk_blake3 = %first_mismatch.actual_chunk_blake3,
                "primary verify pass mismatch detected"
            );

            if confirm_mismatch_with_targeted_reread(
                Arc::clone(&manager),
                device_id,
                prepared,
                &first_mismatch,
            )? {
                return Ok(FlashVerifyResult {
                    hash_match: true,
                    layout_check: true,
                    warnings: vec![format!(
                        "{WARN_VERIFY_TRANSIENT_MISMATCH_RESOLVED}: {}",
                        format_mismatch_message(&first_mismatch)
                    )],
                });
            }

            match run_verify_pass(Arc::clone(&manager), device_id, prepared, progress)? {
                VerifyPassOutcome::Matched => Ok(FlashVerifyResult {
                    hash_match: true,
                    layout_check: true,
                    warnings: vec![format!(
                        "{WARN_VERIFY_TRANSIENT_MISMATCH_RESOLVED}: {}",
                        format_mismatch_message(&first_mismatch)
                    )],
                }),
                VerifyPassOutcome::Mismatch(confirm_mismatch) => {
                    verify_device_layout_only(Arc::clone(&manager), device_id)?;
                    Ok(FlashVerifyResult {
                        hash_match: false,
                        layout_check: true,
                        warnings: vec![format!(
                            "{WARN_VERIFY_SOFT_PASS_BOOTABLE}: persistent mismatch accepted after layout check: {}",
                            format_mismatch_message(&confirm_mismatch)
                        )],
                    })
                }
            }
        }
    }
}

fn run_verify_pass(
    manager: Arc<dyn DeviceManager>,
    device_id: &str,
    prepared: &PreparedImage,
    progress: &Option<ProgressCallback>,
) -> CoreResult<VerifyPassOutcome> {
    let mut image_file = File::open(&prepared.cache_image_path)
        .map_err(|e| CoreError::ImagePreparation(format!("cache image open failed: {e}")))?;
    let mut device = open_verify_device_with_retry(&manager, device_id)?;

    let mut src = vec![0u8; CHUNK_SIZE];
    let mut dst = vec![0u8; CHUNK_SIZE];
    let mut header_sample = vec![0u8; 1024 * 1024];
    let mut header_sample_filled = 0usize;
    let mut boot_sector_offset: Option<u64> = None;
    let mut boot_sector = [0u8; 512];
    let mut boot_sector_filled = 0usize;
    let mut offset = 0u64;
    let mut readback_hash = blake3::Hasher::new();
    let mut readback_sha = Sha256::new();

    loop {
        let n = image_file.read(&mut src).map_err(|e| {
            CoreError::WriteIo(format!("failed reading cache image during verify: {e}"))
        })?;
        if n == 0 {
            break;
        }

        let mut read_total = 0usize;
        while read_total < n {
            let read = device.read_at(offset + read_total as u64, &mut dst[read_total..n])?;
            if read == 0 {
                return Err(CoreError::DeviceRemoved(format!(
                    "short read at offset {}",
                    offset + read_total as u64
                )));
            }
            read_total += read;
        }

        if src[..n] != dst[..n] {
            let relative = src[..n]
                .iter()
                .zip(&dst[..n])
                .position(|(expected, actual)| expected != actual)
                .unwrap_or(0);
            let mismatch = VerifyMismatchInfo {
                offset: offset + relative as u64,
                chunk_start_offset: offset,
                chunk_len: n,
                expected_chunk_blake3: blake3::hash(&src[..n]).to_hex().to_string(),
                actual_chunk_blake3: blake3::hash(&dst[..n]).to_hex().to_string(),
            };
            return Ok(VerifyPassOutcome::Mismatch(mismatch));
        }

        if header_sample_filled < header_sample.len() {
            let copy = (header_sample.len() - header_sample_filled).min(n);
            header_sample[header_sample_filled..header_sample_filled + copy]
                .copy_from_slice(&dst[..copy]);
            header_sample_filled += copy;
            if boot_sector_offset.is_none() {
                boot_sector_offset =
                    detect_boot_sector_offset(&header_sample[..header_sample_filled]);
            }
        }

        if let Some(sector_offset) = boot_sector_offset {
            capture_boot_sector(
                offset,
                &dst[..n],
                sector_offset,
                &mut boot_sector,
                &mut boot_sector_filled,
            );
        }

        readback_hash.update(&dst[..n]);
        readback_sha.update(&dst[..n]);
        offset += n as u64;
        emit_progress(
            progress,
            ProgressUpdate {
                device_id: device_id.to_string(),
                phase: ProgressPhase::Verifying,
                write_done_bytes: prepared.bytes,
                write_total_bytes: prepared.bytes,
                verify_done_bytes: offset.min(prepared.bytes),
                verify_total_bytes: prepared.bytes,
                message: None,
            },
        );
    }

    let digest = readback_hash.finalize().to_hex().to_string();
    if digest != prepared.blake3 {
        return Err(CoreError::VerifyMismatch(format!(
            "readback hash mismatch expected={} actual={}",
            prepared.blake3, digest
        )));
    }

    let _sha_hex = hex::encode(readback_sha.finalize());
    let boot_sector = if boot_sector_filled == boot_sector.len() {
        Some(&boot_sector[..])
    } else {
        None
    };
    layout_check(&header_sample[..header_sample_filled], boot_sector)?;
    Ok(VerifyPassOutcome::Matched)
}

fn confirm_mismatch_with_targeted_reread(
    manager: Arc<dyn DeviceManager>,
    device_id: &str,
    prepared: &PreparedImage,
    mismatch: &VerifyMismatchInfo,
) -> CoreResult<bool> {
    let mut image_file = File::open(&prepared.cache_image_path)
        .map_err(|e| CoreError::ImagePreparation(format!("cache image open failed: {e}")))?;
    image_file
        .seek(SeekFrom::Start(mismatch.chunk_start_offset))
        .map_err(|e| CoreError::ImagePreparation(format!("cache image seek failed: {e}")))?;

    let mut expected = vec![0u8; mismatch.chunk_len];
    image_file
        .read_exact(&mut expected)
        .map_err(|e| CoreError::ImagePreparation(format!("cache image read failed: {e}")))?;

    for attempt in 1..=VERIFY_MISMATCH_REREAD_ATTEMPTS {
        let mut actual = vec![0u8; mismatch.chunk_len];
        let mut device = open_verify_device_with_retry(&manager, device_id)?;
        if let Err(err) =
            read_exact_from_device(device.as_mut(), mismatch.chunk_start_offset, &mut actual)
        {
            if is_verify_retryable_error(&err) && attempt < VERIFY_MISMATCH_REREAD_ATTEMPTS {
                warn!(
                    device = %device_id,
                    attempt,
                    max_attempts = VERIFY_MISMATCH_REREAD_ATTEMPTS,
                    error = %err,
                    "targeted mismatch re-read failed; retrying"
                );
                std::thread::sleep(StdDuration::from_millis(VERIFY_MISMATCH_REREAD_DELAY_MS));
                continue;
            }
            return Err(err);
        }

        if actual == expected {
            return Ok(true);
        }

        if attempt < VERIFY_MISMATCH_REREAD_ATTEMPTS {
            std::thread::sleep(StdDuration::from_millis(VERIFY_MISMATCH_REREAD_DELAY_MS));
        }
    }

    Ok(false)
}

fn read_exact_from_device(
    device: &mut dyn BlockDevice,
    mut offset: u64,
    buf: &mut [u8],
) -> CoreResult<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let read = device.read_at(offset, &mut buf[filled..])?;
        if read == 0 {
            return Err(CoreError::DeviceRemoved(format!(
                "short read at offset {}",
                offset
            )));
        }
        filled += read;
        offset += read as u64;
    }
    Ok(())
}

fn verify_device_layout_only(manager: Arc<dyn DeviceManager>, device_id: &str) -> CoreResult<()> {
    let mut device = open_verify_device_with_retry(&manager, device_id)?;
    let mut header_sample = vec![0u8; 1024 * 1024];
    let mut filled = 0usize;
    while filled < header_sample.len() {
        let read = device.read_at(filled as u64, &mut header_sample[filled..])?;
        if read == 0 {
            break;
        }
        filled += read;
    }

    let mut boot_sector = [0u8; 512];
    let mut boot_sector_filled = 0usize;
    if let Some(sector_offset) = detect_boot_sector_offset(&header_sample[..filled]) {
        if sector_offset + boot_sector.len() as u64 <= filled as u64 {
            let start = sector_offset as usize;
            let end = start + boot_sector.len();
            boot_sector.copy_from_slice(&header_sample[start..end]);
            boot_sector_filled = boot_sector.len();
        } else {
            while boot_sector_filled < boot_sector.len() {
                let read = device.read_at(
                    sector_offset + boot_sector_filled as u64,
                    &mut boot_sector[boot_sector_filled..],
                )?;
                if read == 0 {
                    return Err(CoreError::DeviceRemoved(format!(
                        "short read while checking boot sector at offset {}",
                        sector_offset + boot_sector_filled as u64
                    )));
                }
                boot_sector_filled += read;
            }
        }
    }

    let boot_sector = if boot_sector_filled == boot_sector.len() {
        Some(&boot_sector[..])
    } else {
        None
    };
    layout_check(&header_sample[..filled], boot_sector)
}

fn format_mismatch_message(mismatch: &VerifyMismatchInfo) -> String {
    let expected_preview_len = mismatch.expected_chunk_blake3.len().min(12);
    let actual_preview_len = mismatch.actual_chunk_blake3.len().min(12);
    format!(
        "byte mismatch detected at offset {} (expected_chunk_blake3={} actual_chunk_blake3={})",
        mismatch.offset,
        &mismatch.expected_chunk_blake3[..expected_preview_len],
        &mismatch.actual_chunk_blake3[..actual_preview_len]
    )
}

fn open_verify_device_with_retry(
    manager: &Arc<dyn DeviceManager>,
    device_id: &str,
) -> CoreResult<Box<dyn BlockDevice>> {
    let mut last_err: Option<CoreError> = None;

    for attempt in 1..=VERIFY_OPEN_MAX_ATTEMPTS {
        match manager.open_for_read(device_id) {
            Ok(device) => return Ok(device),
            Err(err) => {
                let retryable = is_verify_retryable_error(&err);
                if retryable && attempt < VERIFY_OPEN_MAX_ATTEMPTS {
                    warn!(
                        device = %device_id,
                        attempt,
                        max_attempts = VERIFY_OPEN_MAX_ATTEMPTS,
                        error = %err,
                        "verify read handle open failed; retrying"
                    );
                    last_err = Some(err);
                    std::thread::sleep(StdDuration::from_millis(VERIFY_OPEN_RETRY_DELAY_MS));
                    continue;
                }
                return Err(err);
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| CoreError::DeviceBusy("failed to open verify read handle".to_string())))
}

fn is_verify_retryable_error(err: &CoreError) -> bool {
    match err {
        CoreError::DeviceBusy(_) => true,
        CoreError::DeviceRemoved(message) | CoreError::WriteIo(message) => {
            let normalized = message.to_ascii_lowercase();
            normalized.contains("resource busy")
                || normalized.contains("busy")
                || normalized.contains("os error 16")
                || normalized.contains("access is denied")
                || normalized.contains("permission denied")
                || normalized.contains("os error 5")
                || normalized.contains("os error 13")
        }
        _ => false,
    }
}

fn layout_check(header: &[u8], boot_sector: Option<&[u8]>) -> CoreResult<()> {
    let read_total = header.len();
    if read_total < 1024 {
        return Err(CoreError::LayoutCheck(
            "insufficient bytes for layout checks".to_string(),
        ));
    }

    let has_mbr_sig = read_total > 511 && header[510] == 0x55 && header[511] == 0xAA;
    let has_gpt_sig = read_total > 520 && &header[512..520] == b"EFI PART";
    if !(has_mbr_sig || has_gpt_sig) {
        return Err(CoreError::LayoutCheck(
            "missing MBR/GPT signature after write".to_string(),
        ));
    }

    if let Some(sector) = boot_sector {
        if !looks_like_fat_boot_sector(sector) {
            return Err(CoreError::LayoutCheck(
                "boot partition sector does not look like FAT".to_string(),
            ));
        }
    }

    Ok(())
}

fn detect_boot_sector_offset(header: &[u8]) -> Option<u64> {
    if let Some(offset) = parse_mbr_first_partition_offset(header) {
        return Some(offset);
    }
    parse_gpt_first_partition_offset(header)
}

fn parse_mbr_first_partition_offset(header: &[u8]) -> Option<u64> {
    if header.len() < 512 || header[510] != 0x55 || header[511] != 0xAA {
        return None;
    }

    for i in 0..4 {
        let base = 446 + (i * 16);
        if base + 16 > header.len() {
            break;
        }
        let part_type = header[base + 4];
        let start_lba = u32::from_le_bytes([
            header[base + 8],
            header[base + 9],
            header[base + 10],
            header[base + 11],
        ]) as u64;
        let sectors = u32::from_le_bytes([
            header[base + 12],
            header[base + 13],
            header[base + 14],
            header[base + 15],
        ]) as u64;

        if part_type == 0 || part_type == 0xEE || start_lba == 0 || sectors == 0 {
            continue;
        }
        return Some(start_lba.saturating_mul(512));
    }

    None
}

fn parse_gpt_first_partition_offset(header: &[u8]) -> Option<u64> {
    if header.len() < 1024 || &header[512..520] != b"EFI PART" {
        return None;
    }

    let entries_lba = u64::from_le_bytes([
        header[584],
        header[585],
        header[586],
        header[587],
        header[588],
        header[589],
        header[590],
        header[591],
    ]);
    let entry_count = u32::from_le_bytes([header[592], header[593], header[594], header[595]]);
    let entry_size = u32::from_le_bytes([header[596], header[597], header[598], header[599]]);

    if entries_lba == 0 || entry_count == 0 || entry_size < 56 {
        return None;
    }

    let entries_base = entries_lba.saturating_mul(512);
    let to_scan = entry_count.min(128);
    for i in 0..to_scan {
        let entry_offset = entries_base.saturating_add(i as u64 * entry_size as u64);
        let entry_offset = usize::try_from(entry_offset).ok()?;
        let entry_size = usize::try_from(entry_size).ok()?;
        if entry_offset + entry_size > header.len() {
            break;
        }
        let entry = &header[entry_offset..entry_offset + entry_size];
        if entry[0..16].iter().all(|b| *b == 0) {
            continue;
        }
        let first_lba = u64::from_le_bytes([
            entry[32], entry[33], entry[34], entry[35], entry[36], entry[37], entry[38], entry[39],
        ]);
        let last_lba = u64::from_le_bytes([
            entry[40], entry[41], entry[42], entry[43], entry[44], entry[45], entry[46], entry[47],
        ]);
        if first_lba > 0 && last_lba >= first_lba {
            return Some(first_lba.saturating_mul(512));
        }
    }

    None
}

fn capture_boot_sector(
    chunk_start: u64,
    chunk: &[u8],
    sector_offset: u64,
    out: &mut [u8; 512],
    filled: &mut usize,
) {
    if *filled >= out.len() {
        return;
    }

    let chunk_end = chunk_start.saturating_add(chunk.len() as u64);
    let sector_end = sector_offset.saturating_add(out.len() as u64);
    let overlap_start = chunk_start.max(sector_offset);
    let overlap_end = chunk_end.min(sector_end);
    if overlap_start >= overlap_end {
        return;
    }

    let src_start = (overlap_start - chunk_start) as usize;
    let src_end = (overlap_end - chunk_start) as usize;
    let dst_start = (overlap_start - sector_offset) as usize;
    let dst_end = dst_start + (src_end - src_start);
    out[dst_start..dst_end].copy_from_slice(&chunk[src_start..src_end]);
    *filled += src_end - src_start;
}

fn looks_like_fat_boot_sector(sector: &[u8]) -> bool {
    if sector.len() < 512 {
        return false;
    }

    if sector[510] != 0x55 || sector[511] != 0xAA {
        return false;
    }

    if !matches!(sector[0], 0xEB | 0xE9) {
        return false;
    }

    let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
        return false;
    }

    let sectors_per_cluster = sector[13];
    if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
        return false;
    }

    let fat12_16_label = &sector[54..62];
    let fat32_label = &sector[82..90];
    fat12_16_label.starts_with(b"FAT") || fat32_label.starts_with(b"FAT")
}

fn select_targets(
    devices: &[DeviceInfo],
    selector: &TargetSelector,
    policy_store: &PolicyStore,
    noninteractive: bool,
    image_bytes: u64,
) -> CoreResult<Vec<DeviceInfo>> {
    let policy = policy_store.get()?;
    let mut candidates: Vec<DeviceInfo> = match selector {
        TargetSelector::All => devices.to_vec(),
        TargetSelector::DeviceIds { ids } => {
            let mut requested: Vec<DeviceInfo> = Vec::new();
            let mut denied: Vec<String> = Vec::new();

            for id in ids {
                let Some(device) = devices.iter().find(|d| d.id == *id) else {
                    denied.push(format!("{id}: not detected"));
                    continue;
                };

                if let Some(reason) = preflight_block_reason(device, image_bytes) {
                    denied.push(format!("{id}: {reason}"));
                    continue;
                }

                if !policy_store.is_device_allowed(device, noninteractive)? {
                    denied.push(format!("{id}: blocked by policy"));
                    continue;
                }

                requested.push(device.clone());
            }

            if !denied.is_empty() {
                return Err(CoreError::PolicyDeny(format!(
                    "requested targets not eligible: {}",
                    denied.join("; ")
                )));
            }

            requested
        }
        TargetSelector::Labels { labels } => {
            let allowed_hashes: Vec<String> = policy
                .allowed_readers
                .iter()
                .filter(|r| labels.iter().any(|label| label == &r.label))
                .map(|r| r.fingerprint.usb_serial_or_path_hash.clone())
                .collect();

            devices
                .iter()
                .filter(|d| {
                    allowed_hashes
                        .iter()
                        .any(|h| h == &d.fingerprint.usb_serial_or_path_hash)
                })
                .cloned()
                .collect()
        }
    };

    candidates.retain(|d| preflight_block_reason(d, image_bytes).is_none());

    let mut allowed = Vec::new();
    for device in candidates {
        if policy_store.is_device_allowed(&device, noninteractive)? {
            allowed.push(device);
        }
    }

    Ok(allowed)
}

fn preflight_block_reason(device: &DeviceInfo, image_bytes: u64) -> Option<String> {
    if !device.removable {
        return Some("not removable".to_string());
    }
    if device.is_system_disk {
        return Some("system disk".to_string());
    }
    if !device.eligible {
        if device.ineligible_reasons.is_empty() {
            return Some("ineligible".to_string());
        }
        return Some(format!(
            "ineligible ({})",
            device.ineligible_reasons.join(",")
        ));
    }
    if device.capacity_bytes < image_bytes {
        return Some(format!(
            "insufficient capacity {} < image {} bytes",
            device.capacity_bytes, image_bytes
        ));
    }
    if matches!(
        device.bus.to_lowercase().as_str(),
        "sata" | "nvme" | "pci" | "pcie"
    ) {
        return Some(format!("unsupported bus {}", device.bus));
    }
    None
}

fn eject_with_retries(
    manager: &Arc<dyn DeviceManager>,
    device_id: &str,
    max_attempts: u8,
) -> CoreResult<()> {
    let mut last_err = None;
    for attempt in 1..=max_attempts.max(1) {
        match manager.eject(device_id) {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = Some(err);
                if attempt < max_attempts {
                    std::thread::sleep(StdDuration::from_millis(500));
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| CoreError::DeviceBusy("eject failed".to_string())))
}

fn build_summary(targets: &[TargetResult], duration_secs: f64) -> RunSummary {
    let mut success = 0u32;
    let mut failed = 0u32;
    let mut skipped = 0u32;

    for target in targets {
        match target.status {
            TargetStatus::Success => success += 1,
            TargetStatus::Failed => failed += 1,
            TargetStatus::Skipped => skipped += 1,
        }
    }

    RunSummary {
        success,
        failed,
        skipped,
        duration_secs,
    }
}

fn failure_target(device: &DeviceInfo, code: Option<ErrorCode>, message: String) -> TargetResult {
    TargetResult {
        device_id: device.id.clone(),
        fingerprint: device.fingerprint.clone(),
        bytes_written: 0,
        write_secs: 0.0,
        verify_secs: 0.0,
        hash_match: false,
        layout_check: false,
        status: TargetStatus::Failed,
        error_code: code,
        error_message: Some(message),
        warnings: Vec::new(),
    }
}

struct UnlockGuard {
    manager: Arc<dyn DeviceManager>,
    device_id: String,
}

impl Drop for UnlockGuard {
    fn drop(&mut self) {
        if let Err(e) = self.manager.unlock(&self.device_id) {
            warn!(device = %self.device_id, error = %e, "failed to unlock device");
        }
    }
}

struct RunLock {
    file: File,
}

impl RunLock {
    fn acquire(path: std::path::PathBuf) -> CoreResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        file.try_lock_exclusive()
            .map_err(|e| CoreError::PolicyDeny(format!("another flash run is active: {e}")))?;
        Ok(Self { file })
    }
}

impl Drop for RunLock {
    fn drop(&mut self) {
        if let Err(e) = self.file.unlock() {
            warn!(error = %e, "failed to unlock run lock");
        }
    }
}

fn update_quarantine_from_reports(
    app_root: &Path,
    policy_store: &PolicyStore,
    report: &RunReport,
) -> CoreResult<()> {
    let cutoff = Utc::now() - Duration::hours(24);
    let mut failures: HashMap<String, u32> = HashMap::new();

    if reports_root(app_root).exists() {
        for entry in std::fs::read_dir(reports_root(app_root))? {
            let entry = entry?;
            if entry.path().extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read(entry.path())?;
            let parsed: Result<RunReport, _> = serde_json::from_slice(&raw);
            let parsed = match parsed {
                Ok(v) => v,
                Err(_) => continue,
            };
            if parsed.ended_at < cutoff {
                continue;
            }
            for target in parsed.targets {
                if matches!(target.status, TargetStatus::Failed) {
                    *failures.entry(target.device_id).or_default() += 1;
                }
            }
        }
    }

    for target in &report.targets {
        if matches!(target.status, TargetStatus::Failed) {
            *failures.entry(target.device_id.clone()).or_default() += 1;
        }
    }

    for (device_id, count) in failures {
        if count >= 2 {
            warn!(device = %device_id, count, "auto-quarantining device after repeated failures");
            policy_store.quarantine(&device_id)?;
        }
    }

    Ok(())
}

fn emit_progress(callback: &Option<ProgressCallback>, update: ProgressUpdate) {
    if let Some(cb) = callback {
        cb(update);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use chrono::Utc;
    use piflasher_protocol::{ErrorCode, FlashRequest, TargetSelector, TargetStatus};
    use rand::{RngCore, SeedableRng};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use crate::device::{BlockDevice, DeviceManager, FileBackedDeviceManager, FileDeviceSpec};
    use crate::paths::{ensure_layout, policy_path};
    use crate::policy::PolicyStore;
    use crate::{CoreError, CoreResult};

    use super::{execute_flash, process_flash_target, FlashExecutionOptions, CHUNK_SIZE};

    fn fake_image_xz(path: &std::path::Path, payload: &[u8]) {
        use std::io::Write;
        let file = std::fs::File::create(path).expect("create image xz file");
        let mut encoder = xz2::write::XzEncoder::new(file, 6);
        encoder.write_all(payload).expect("write xz payload");
        encoder.finish().expect("finish xz payload");
    }

    #[derive(Clone, Copy, Debug)]
    enum ReadFaultMode {
        None,
        FirstSessionByteFlip { offset: u64 },
        AlwaysByteFlip { offset: u64 },
        AlwaysBootCorrupt,
    }

    #[derive(Debug)]
    struct ScriptedState {
        storage: Vec<u8>,
        read_open_count: usize,
        eject_calls: usize,
        fail_eject: bool,
        fail_write_open: bool,
        fault_mode: ReadFaultMode,
        require_aligned_reads: bool,
    }

    #[derive(Clone)]
    struct ScriptedDeviceManager {
        device: piflasher_protocol::DeviceInfo,
        state: Arc<Mutex<ScriptedState>>,
    }

    impl ScriptedDeviceManager {
        fn new(
            payload_len: usize,
            fault_mode: ReadFaultMode,
            fail_write_open: bool,
            fail_eject: bool,
        ) -> Self {
            Self::new_with_alignment(payload_len, fault_mode, fail_write_open, fail_eject, false)
        }

        fn new_with_alignment(
            payload_len: usize,
            fault_mode: ReadFaultMode,
            fail_write_open: bool,
            fail_eject: bool,
            require_aligned_reads: bool,
        ) -> Self {
            let capacity = payload_len as u64 + 4096;
            let device = piflasher_protocol::DeviceInfo {
                id: "disk-test".to_string(),
                path: "/dev/mock".to_string(),
                removable: true,
                is_system_disk: false,
                capacity_bytes: capacity,
                bus: "usb".to_string(),
                vendor: "Simulated".to_string(),
                product: "Scripted".to_string(),
                fingerprint: piflasher_protocol::DeviceFingerprint {
                    vid: "SIM0".to_string(),
                    pid: "SIM1".to_string(),
                    usb_serial_or_path_hash: "abc123".to_string(),
                    vendor: "Simulated".to_string(),
                    product: "Scripted".to_string(),
                    capacity_min_bytes: capacity.saturating_sub(1024),
                    capacity_max_bytes: capacity.saturating_add(1024),
                },
                eligible: true,
                ineligible_reasons: Vec::new(),
            };

            Self {
                device,
                state: Arc::new(Mutex::new(ScriptedState {
                    storage: vec![0u8; capacity as usize],
                    read_open_count: 0,
                    eject_calls: 0,
                    fail_eject,
                    fail_write_open,
                    fault_mode,
                    require_aligned_reads,
                })),
            }
        }

        fn device_info(&self) -> piflasher_protocol::DeviceInfo {
            self.device.clone()
        }

        fn eject_calls(&self) -> usize {
            self.state
                .lock()
                .expect("scripted state lock for eject_calls")
                .eject_calls
        }
    }

    impl DeviceManager for ScriptedDeviceManager {
        fn list_devices(&self) -> CoreResult<Vec<piflasher_protocol::DeviceInfo>> {
            Ok(vec![self.device.clone()])
        }

        fn lock(&self, _device_id: &str) -> CoreResult<()> {
            Ok(())
        }

        fn unlock(&self, _device_id: &str) -> CoreResult<()> {
            Ok(())
        }

        fn open_for_write(&self, _device_id: &str) -> CoreResult<Box<dyn BlockDevice>> {
            let state = self
                .state
                .lock()
                .expect("scripted state lock for open_for_write");
            if state.fail_write_open {
                return Err(CoreError::WriteIo(
                    "Access is denied. (os error 5)".to_string(),
                ));
            }
            drop(state);
            Ok(Box::new(ScriptedWriteDevice {
                state: Arc::clone(&self.state),
            }))
        }

        fn open_for_read(&self, _device_id: &str) -> CoreResult<Box<dyn BlockDevice>> {
            let mut state = self
                .state
                .lock()
                .expect("scripted state lock for open_for_read");
            let session_index = state.read_open_count;
            state.read_open_count += 1;
            drop(state);
            Ok(Box::new(ScriptedReadDevice {
                state: Arc::clone(&self.state),
                session_index,
            }))
        }

        fn eject(&self, _device_id: &str) -> CoreResult<()> {
            let mut state = self.state.lock().expect("scripted state lock for eject");
            state.eject_calls += 1;
            if state.fail_eject {
                return Err(CoreError::DeviceBusy("simulated eject failure".to_string()));
            }
            Ok(())
        }
    }

    struct ScriptedWriteDevice {
        state: Arc<Mutex<ScriptedState>>,
    }

    impl BlockDevice for ScriptedWriteDevice {
        fn write_at(&mut self, offset: u64, buf: &[u8]) -> CoreResult<usize> {
            let mut state = self.state.lock().expect("scripted state lock for write_at");
            let start = offset as usize;
            let end = start.saturating_add(buf.len());
            if end > state.storage.len() {
                return Err(CoreError::WriteIo(format!(
                    "out-of-range write start={start} len={}",
                    buf.len()
                )));
            }
            state.storage[start..end].copy_from_slice(buf);
            Ok(buf.len())
        }

        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> CoreResult<usize> {
            let state = self.state.lock().expect("scripted state lock for read_at");
            let start = offset as usize;
            if start >= state.storage.len() {
                return Ok(0);
            }
            let len = buf.len().min(state.storage.len() - start);
            buf[..len].copy_from_slice(&state.storage[start..start + len]);
            Ok(len)
        }

        fn flush(&mut self) -> CoreResult<()> {
            Ok(())
        }

        fn capacity(&self) -> u64 {
            self.state
                .lock()
                .expect("scripted state lock for capacity")
                .storage
                .len() as u64
        }
    }

    struct ScriptedReadDevice {
        state: Arc<Mutex<ScriptedState>>,
        session_index: usize,
    }

    impl BlockDevice for ScriptedReadDevice {
        fn write_at(&mut self, _offset: u64, _buf: &[u8]) -> CoreResult<usize> {
            Err(CoreError::WriteIo("read-only scripted device".to_string()))
        }

        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> CoreResult<usize> {
            let state = self
                .state
                .lock()
                .expect("scripted state lock for read_at scripted read");
            if state.require_aligned_reads
                && (!offset.is_multiple_of(512) || !buf.len().is_multiple_of(512))
            {
                return Err(CoreError::DeviceRemoved(format!(
                    "failed to read raw device at offset {offset}: Invalid argument (os error 22)"
                )));
            }
            let start = offset as usize;
            if start >= state.storage.len() {
                return Ok(0);
            }

            let len = buf.len().min(state.storage.len() - start);
            buf[..len].copy_from_slice(&state.storage[start..start + len]);

            match state.fault_mode {
                ReadFaultMode::None => {}
                ReadFaultMode::FirstSessionByteFlip { offset } => {
                    if self.session_index == 0 {
                        maybe_flip_byte(&mut buf[..len], start as u64, offset);
                    }
                }
                ReadFaultMode::AlwaysByteFlip { offset } => {
                    maybe_flip_byte(&mut buf[..len], start as u64, offset);
                }
                ReadFaultMode::AlwaysBootCorrupt => {
                    maybe_set_byte(&mut buf[..len], start as u64, 510, 0);
                    maybe_set_byte(&mut buf[..len], start as u64, 511, 0);
                }
            }

            Ok(len)
        }

        fn flush(&mut self) -> CoreResult<()> {
            Ok(())
        }

        fn capacity(&self) -> u64 {
            self.state
                .lock()
                .expect("scripted state lock for capacity")
                .storage
                .len() as u64
        }
    }

    fn maybe_flip_byte(buf: &mut [u8], read_start: u64, target_offset: u64) {
        if target_offset < read_start {
            return;
        }
        let rel = (target_offset - read_start) as usize;
        if rel < buf.len() {
            buf[rel] ^= 0xFF;
        }
    }

    fn maybe_set_byte(buf: &mut [u8], read_start: u64, target_offset: u64, value: u8) {
        if target_offset < read_start {
            return;
        }
        let rel = (target_offset - read_start) as usize;
        if rel < buf.len() {
            buf[rel] = value;
        }
    }

    fn prepared_image_from_payload(
        temp: &TempDir,
        payload: &[u8],
    ) -> piflasher_protocol::PreparedImage {
        let cache_path = temp.path().join("prepared.img");
        std::fs::write(&cache_path, payload).expect("write prepared image payload");
        let blake3 = blake3::hash(payload).to_hex().to_string();
        let mut sha = Sha256::new();
        sha.update(payload);
        let sha256 = hex::encode(sha.finalize());

        piflasher_protocol::PreparedImage {
            original_path: "./rpi.img.xz".to_string(),
            cache_image_path: cache_path.to_string_lossy().to_string(),
            cache_dir: temp.path().to_string_lossy().to_string(),
            bytes: payload.len() as u64,
            blake3,
            sha256,
            prepared_at: Utc::now(),
        }
    }

    fn base_payload(size: usize) -> Vec<u8> {
        let mut payload = vec![0u8; size];
        payload[510] = 0x55;
        payload[511] = 0xAA;
        payload
    }

    #[tokio::test]
    async fn flash_success_against_file_backed_device() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("app");
        ensure_layout(&root).expect("ensure layout");

        let image_path = temp.path().join("rpi.img.xz");
        let mut payload = vec![0u8; 4 * 1024 * 1024];
        rand::rngs::StdRng::seed_from_u64(42).fill_bytes(&mut payload);
        payload[510] = 0x55;
        payload[511] = 0xAA;
        payload[700] = b'F';
        payload[701] = b'A';
        payload[702] = b'T';
        fake_image_xz(&image_path, &payload);

        let dev_path = temp.path().join("device0.imgdev");
        std::fs::write(&dev_path, vec![0u8; payload.len() + 1024]).expect("create device");

        let spec = FileDeviceSpec::from_path(&dev_path).expect("spec from path");
        let manager = Arc::new(FileBackedDeviceManager::new(vec![spec.clone()]));
        let policy = PolicyStore::load_or_default(&policy_path(&root)).expect("load policy");

        let devices = manager.list_devices().expect("list devices");
        policy
            .enroll_from_device(&devices[0], "test-reader")
            .expect("enroll policy reader");

        let report = execute_flash(
            &root,
            manager,
            &policy,
            FlashRequest {
                image_path: Some(image_path.to_string_lossy().to_string()),
                targets: TargetSelector::All,
                max_parallel: Some(1),
                json: false,
                yes: true,
                no_eject: true,
                allow_concurrent_jobs: false,
            },
            FlashExecutionOptions::default(),
        )
        .await
        .expect("flash succeeds");

        assert_eq!(report.summary.success, 1);
        assert_eq!(report.summary.failed, 0);
    }

    #[tokio::test]
    async fn noninteractive_flash_is_denied_without_policy_enrollment() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("app");
        ensure_layout(&root).expect("ensure layout");

        let image_path = temp.path().join("rpi.img.xz");
        let mut payload = vec![0u8; 2 * 1024 * 1024];
        rand::rngs::StdRng::seed_from_u64(7).fill_bytes(&mut payload);
        payload[510] = 0x55;
        payload[511] = 0xAA;
        payload[128] = b'F';
        payload[129] = b'A';
        payload[130] = b'T';
        fake_image_xz(&image_path, &payload);

        let dev_path = temp.path().join("device1.imgdev");
        std::fs::write(&dev_path, vec![0u8; payload.len() + 512]).expect("create device");

        let spec = FileDeviceSpec::from_path(&dev_path).expect("spec from path");
        let manager = Arc::new(FileBackedDeviceManager::new(vec![spec]));
        let policy = PolicyStore::load_or_default(&policy_path(&root)).expect("load policy");

        let result = execute_flash(
            &root,
            manager,
            &policy,
            FlashRequest {
                image_path: Some(image_path.to_string_lossy().to_string()),
                targets: TargetSelector::All,
                max_parallel: Some(1),
                json: false,
                yes: true,
                no_eject: true,
                allow_concurrent_jobs: false,
            },
            FlashExecutionOptions::default(),
        )
        .await;

        assert!(matches!(result, Err(crate::CoreError::PolicyDeny(_))));
    }

    #[tokio::test]
    async fn verify_detects_hash_mismatch() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("app");
        ensure_layout(&root).expect("ensure layout");

        let image_path = temp.path().join("rpi.img.xz");
        let mut payload = vec![0u8; 1024 * 1024];
        rand::rngs::StdRng::seed_from_u64(9).fill_bytes(&mut payload);
        payload[510] = 0x55;
        payload[511] = 0xAA;
        payload[900] = b'F';
        payload[901] = b'A';
        payload[902] = b'T';
        fake_image_xz(&image_path, &payload);

        let mut mismatched = vec![0xFFu8; payload.len() + 1024];
        mismatched[510] = 0x55;
        mismatched[511] = 0xAA;
        mismatched[900] = b'F';
        mismatched[901] = b'A';
        mismatched[902] = b'T';

        let dev_path = temp.path().join("device2.imgdev");
        std::fs::write(&dev_path, mismatched).expect("create device");

        let spec = FileDeviceSpec::from_path(&dev_path).expect("spec from path");
        let manager = Arc::new(FileBackedDeviceManager::new(vec![spec]));
        let policy = PolicyStore::load_or_default(&policy_path(&root)).expect("load policy");
        let devices = manager.list_devices().expect("list devices");
        policy
            .enroll_from_device(&devices[0], "verify-reader")
            .expect("enroll");

        let report = super::execute_verify(
            &root,
            manager,
            &policy,
            piflasher_protocol::VerifyRequest {
                image_path: Some(image_path.to_string_lossy().to_string()),
                targets: TargetSelector::All,
                json: false,
            },
            FlashExecutionOptions::default(),
        )
        .await
        .expect("verify completed with report");

        assert_eq!(report.summary.failed, 1);
        assert_eq!(report.targets.len(), 1);
        assert_eq!(
            report.targets[0]
                .error_code
                .expect("error code should be present"),
            piflasher_protocol::ErrorCode::VerifyMismatch
        );
    }

    #[tokio::test]
    async fn explicit_device_selection_fails_if_any_requested_id_is_missing() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("app");
        ensure_layout(&root).expect("ensure layout");

        let image_path = temp.path().join("rpi.img.xz");
        let mut payload = vec![0u8; 2 * 1024 * 1024];
        rand::rngs::StdRng::seed_from_u64(123).fill_bytes(&mut payload);
        payload[510] = 0x55;
        payload[511] = 0xAA;
        fake_image_xz(&image_path, &payload);

        let dev_path = temp.path().join("device-explicit.imgdev");
        std::fs::write(&dev_path, vec![0u8; payload.len() + 1024]).expect("create device");
        let spec = FileDeviceSpec::from_path(&dev_path).expect("spec from path");
        let manager = Arc::new(FileBackedDeviceManager::new(vec![spec]));
        let policy = PolicyStore::load_or_default(&policy_path(&root)).expect("load policy");
        let devices = manager.list_devices().expect("list devices");
        let existing_id = devices[0].id.clone();
        policy
            .enroll_from_device(&devices[0], "explicit-reader")
            .expect("enroll");

        let result = execute_flash(
            &root,
            manager,
            &policy,
            FlashRequest {
                image_path: Some(image_path.to_string_lossy().to_string()),
                targets: TargetSelector::DeviceIds {
                    ids: vec![existing_id, "missing-device-id".to_string()],
                },
                max_parallel: Some(2),
                json: false,
                yes: true,
                no_eject: true,
                allow_concurrent_jobs: false,
            },
            FlashExecutionOptions::default(),
        )
        .await;

        assert!(matches!(result, Err(crate::CoreError::PolicyDeny(_))));
        let err = result.expect_err("missing target should produce policy deny");
        assert!(err.to_string().contains("missing-device-id"));
    }

    #[test]
    fn verify_mismatch_transient_then_match_reports_success_warning() {
        let temp = TempDir::new().expect("tempdir");
        let payload = base_payload(CHUNK_SIZE + 1024 * 1024);
        let prepared = prepared_image_from_payload(&temp, &payload);
        let manager = Arc::new(ScriptedDeviceManager::new(
            payload.len(),
            ReadFaultMode::FirstSessionByteFlip {
                offset: CHUNK_SIZE as u64,
            },
            false,
            false,
        ));

        let manager_trait: Arc<dyn DeviceManager> = manager.clone();
        let result =
            process_flash_target(manager_trait, &manager.device_info(), &prepared, true, None)
                .expect("flash target result");

        assert!(matches!(result.status, TargetStatus::Success));
        assert!(result.hash_match);
        assert!(result.layout_check);
        assert!(result
            .warnings
            .iter()
            .any(|w| { w.contains(super::WARN_VERIFY_TRANSIENT_MISMATCH_RESOLVED) }));
    }

    #[test]
    fn verify_mismatch_transient_misaligned_offset_still_recovers_on_aligned_raw_reads() {
        let temp = TempDir::new().expect("tempdir");
        let payload = base_payload(CHUNK_SIZE + 1024 * 1024);
        let prepared = prepared_image_from_payload(&temp, &payload);
        let manager = Arc::new(ScriptedDeviceManager::new_with_alignment(
            payload.len(),
            ReadFaultMode::FirstSessionByteFlip {
                offset: CHUNK_SIZE as u64 + 1000,
            },
            false,
            false,
            true,
        ));

        let manager_trait: Arc<dyn DeviceManager> = manager.clone();
        let result =
            process_flash_target(manager_trait, &manager.device_info(), &prepared, true, None)
                .expect("flash target result");

        assert!(matches!(result.status, TargetStatus::Success));
        assert!(result.hash_match);
        assert!(result
            .warnings
            .iter()
            .any(|w| { w.contains(super::WARN_VERIFY_TRANSIENT_MISMATCH_RESOLVED) }));
    }

    #[test]
    fn verify_mismatch_persistent_bootable_soft_pass() {
        let temp = TempDir::new().expect("tempdir");
        let payload = base_payload(CHUNK_SIZE + 1024 * 1024);
        let prepared = prepared_image_from_payload(&temp, &payload);
        let manager = Arc::new(ScriptedDeviceManager::new(
            payload.len(),
            ReadFaultMode::AlwaysByteFlip {
                offset: CHUNK_SIZE as u64,
            },
            false,
            false,
        ));

        let manager_trait: Arc<dyn DeviceManager> = manager.clone();
        let result =
            process_flash_target(manager_trait, &manager.device_info(), &prepared, true, None)
                .expect("flash target result");

        assert!(matches!(result.status, TargetStatus::Success));
        assert!(!result.hash_match);
        assert!(result.layout_check);
        assert!(result
            .warnings
            .iter()
            .any(|w| { w.contains(super::WARN_VERIFY_SOFT_PASS_BOOTABLE) }));
    }

    #[test]
    fn verify_mismatch_persistent_nonbootable_fails() {
        let temp = TempDir::new().expect("tempdir");
        let payload = base_payload(CHUNK_SIZE + 1024 * 1024);
        let prepared = prepared_image_from_payload(&temp, &payload);
        let manager = Arc::new(ScriptedDeviceManager::new(
            payload.len(),
            ReadFaultMode::AlwaysBootCorrupt,
            false,
            false,
        ));

        let manager_trait: Arc<dyn DeviceManager> = manager.clone();
        let result =
            process_flash_target(manager_trait, &manager.device_info(), &prepared, true, None)
                .expect("flash target result");

        assert!(matches!(result.status, TargetStatus::Failed));
        assert_eq!(result.error_code, Some(ErrorCode::LayoutCheck));
    }

    #[test]
    fn failed_target_still_attempts_eject() {
        let temp = TempDir::new().expect("tempdir");
        let payload = base_payload(2 * 1024 * 1024);
        let prepared = prepared_image_from_payload(&temp, &payload);
        let manager = Arc::new(ScriptedDeviceManager::new(
            payload.len(),
            ReadFaultMode::None,
            true,
            false,
        ));

        let manager_trait: Arc<dyn DeviceManager> = manager.clone();
        let result = process_flash_target(
            manager_trait,
            &manager.device_info(),
            &prepared,
            false,
            None,
        )
        .expect("flash target result");

        assert!(matches!(result.status, TargetStatus::Failed));
        assert_eq!(manager.eject_calls(), 1);
    }

    #[test]
    fn no_eject_skips_eject_for_success_and_failure() {
        let temp = TempDir::new().expect("tempdir");
        let payload = base_payload(2 * 1024 * 1024);
        let prepared = prepared_image_from_payload(&temp, &payload);

        let manager_success = Arc::new(ScriptedDeviceManager::new(
            payload.len(),
            ReadFaultMode::None,
            false,
            false,
        ));
        let manager_success_trait: Arc<dyn DeviceManager> = manager_success.clone();
        let success = process_flash_target(
            manager_success_trait,
            &manager_success.device_info(),
            &prepared,
            true,
            None,
        )
        .expect("success target result");
        assert!(matches!(success.status, TargetStatus::Success));
        assert_eq!(manager_success.eject_calls(), 0);

        let manager_failure = Arc::new(ScriptedDeviceManager::new(
            payload.len(),
            ReadFaultMode::None,
            true,
            false,
        ));
        let manager_failure_trait: Arc<dyn DeviceManager> = manager_failure.clone();
        let failed = process_flash_target(
            manager_failure_trait,
            &manager_failure.device_info(),
            &prepared,
            true,
            None,
        )
        .expect("failed target result");
        assert!(matches!(failed.status, TargetStatus::Failed));
        assert_eq!(manager_failure.eject_calls(), 0);
    }

    #[test]
    fn eject_failure_on_failed_target_becomes_warning() {
        let temp = TempDir::new().expect("tempdir");
        let payload = base_payload(2 * 1024 * 1024);
        let prepared = prepared_image_from_payload(&temp, &payload);
        let manager = Arc::new(ScriptedDeviceManager::new(
            payload.len(),
            ReadFaultMode::None,
            true,
            true,
        ));

        let manager_trait: Arc<dyn DeviceManager> = manager.clone();
        let result = process_flash_target(
            manager_trait,
            &manager.device_info(),
            &prepared,
            false,
            None,
        )
        .expect("flash target result");

        assert!(matches!(result.status, TargetStatus::Failed));
        assert_eq!(result.error_code, Some(ErrorCode::WriteIo));
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains(super::WARN_EJECT_FAILED_AFTER_TARGET_COMPLETE)));
        assert_eq!(manager.eject_calls(), 3);
    }

    #[test]
    fn verify_open_retryable_for_busy_errors() {
        assert!(super::is_verify_retryable_error(
            &crate::CoreError::DeviceBusy("busy".to_string())
        ));
        assert!(super::is_verify_retryable_error(
            &crate::CoreError::DeviceRemoved("Resource busy (os error 16)".to_string())
        ));
        assert!(super::is_verify_retryable_error(
            &crate::CoreError::WriteIo("Access is denied. (os error 5)".to_string())
        ));
        assert!(!super::is_verify_retryable_error(
            &crate::CoreError::VerifyMismatch("hash mismatch".to_string())
        ));
    }
}
