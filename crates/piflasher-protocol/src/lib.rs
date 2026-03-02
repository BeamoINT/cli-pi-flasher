use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcEnvelope {
    pub protocol_version: u16,
    pub request_id: Uuid,
    pub payload: RpcRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RpcRequest {
    Ping,
    ListDevices,
    PolicyList,
    PolicyEnroll {
        device_id: String,
        label: String,
    },
    PolicyClearQuarantine {
        device_id: String,
    },
    ImagePrepare {
        image_path: Option<String>,
        force: bool,
    },
    Flash(FlashRequest),
    Verify(VerifyRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcEnvelopeResponse {
    pub protocol_version: u16,
    pub request_id: Uuid,
    pub payload: RpcResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RpcResponse {
    Pong {
        agent_version: String,
        ts: DateTime<Utc>,
    },
    Devices {
        devices: Vec<DeviceInfo>,
    },
    Policy {
        policy: PolicyConfig,
    },
    ImagePrepared {
        prepared: PreparedImage,
    },
    JobReport {
        report: RunReport,
    },
    Ack {
        message: String,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    PolicyDeny,
    DeviceBusy,
    WriteIo,
    VerifyMismatch,
    DeviceRemoved,
    LayoutCheck,
    AgentUnavailable,
    ImagePreparation,
    InvalidRequest,
    Internal,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::PolicyDeny => "E_POLICY_DENY",
            ErrorCode::DeviceBusy => "E_DEVICE_BUSY",
            ErrorCode::WriteIo => "E_WRITE_IO",
            ErrorCode::VerifyMismatch => "E_VERIFY_MISMATCH",
            ErrorCode::DeviceRemoved => "E_DEVICE_REMOVED",
            ErrorCode::LayoutCheck => "E_LAYOUT_CHECK",
            ErrorCode::AgentUnavailable => "E_AGENT_UNAVAILABLE",
            ErrorCode::ImagePreparation => "E_IMAGE_PREPARATION",
            ErrorCode::InvalidRequest => "E_INVALID_REQUEST",
            ErrorCode::Internal => "E_INTERNAL",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    pub vid: String,
    pub pid: String,
    pub usb_serial_or_path_hash: String,
    pub vendor: String,
    pub product: String,
    pub capacity_min_bytes: u64,
    pub capacity_max_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub path: String,
    pub removable: bool,
    pub is_system_disk: bool,
    pub capacity_bytes: u64,
    pub bus: String,
    pub vendor: String,
    pub product: String,
    pub fingerprint: DeviceFingerprint,
    pub eligible: bool,
    pub ineligible_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyReader {
    pub label: String,
    #[serde(flatten)]
    pub fingerprint: DeviceFingerprint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub version: u32,
    pub max_parallel: u8,
    pub require_fingerprint_noninteractive: bool,
    pub allowed_readers: Vec<PolicyReader>,
    pub quarantined_readers: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            version: 1,
            max_parallel: 10,
            require_fingerprint_noninteractive: true,
            allowed_readers: Vec::new(),
            quarantined_readers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedImage {
    pub original_path: String,
    pub cache_image_path: String,
    pub cache_dir: String,
    pub bytes: u64,
    pub blake3: String,
    pub sha256: String,
    pub prepared_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashRequest {
    pub image_path: Option<String>,
    pub targets: TargetSelector,
    pub max_parallel: Option<u8>,
    pub json: bool,
    pub yes: bool,
    pub no_eject: bool,
    pub allow_concurrent_jobs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub image_path: Option<String>,
    pub targets: TargetSelector,
    pub json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum TargetSelector {
    All,
    DeviceIds { ids: Vec<String> },
    Labels { labels: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSettings {
    pub max_parallel: u8,
    pub strict_verify: bool,
    pub no_eject: bool,
    pub noninteractive: bool,
    pub chunk_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunImageInfo {
    pub path: String,
    pub bytes: u64,
    pub blake3: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetStatus {
    Success,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetResult {
    pub device_id: String,
    pub fingerprint: DeviceFingerprint,
    pub bytes_written: u64,
    pub write_secs: f64,
    pub verify_secs: f64,
    pub hash_match: bool,
    pub layout_check: bool,
    pub status: TargetStatus,
    pub error_code: Option<ErrorCode>,
    pub error_message: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub success: u32,
    pub failed: u32,
    pub skipped: u32,
    pub duration_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub job_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub image: RunImageInfo,
    pub settings: RunSettings,
    pub targets: Vec<TargetResult>,
    pub summary: RunSummary,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_type: String,
    pub job_id: Uuid,
    pub device_id: Option<String>,
    pub ts: DateTime<Utc>,
    pub payload: serde_json::Value,
}

#[derive(Debug, Error)]
pub enum ProtocolIoError {
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(u32),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

pub async fn write_framed_json<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<(), ProtocolIoError> {
    let bytes = serde_json::to_vec(value)?;
    let len = u32::try_from(bytes.len()).map_err(|_| ProtocolIoError::FrameTooLarge(u32::MAX))?;
    if len > MAX_FRAME_SIZE {
        return Err(ProtocolIoError::FrameTooLarge(len));
    }
    writer.write_u32_le(len).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_framed_json<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
) -> Result<T, ProtocolIoError> {
    let len = reader.read_u32_le().await?;
    if len > MAX_FRAME_SIZE {
        return Err(ProtocolIoError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}
