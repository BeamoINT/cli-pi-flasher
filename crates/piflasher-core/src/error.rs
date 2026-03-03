use piflasher_protocol::ErrorCode;
use thiserror::Error;

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("policy denied operation: {0}")]
    PolicyDeny(String),
    #[error("device busy: {0}")]
    DeviceBusy(String),
    #[error("write io failed: {0}")]
    WriteIo(String),
    #[error("verification mismatch: {0}")]
    VerifyMismatch(String),
    #[error("device removed: {0}")]
    DeviceRemoved(String),
    #[error("layout check failed: {0}")]
    LayoutCheck(String),
    #[error("agent unavailable: {0}")]
    AgentUnavailable(String),
    #[error("image preparation failed: {0}")]
    ImagePreparation(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("toml decode error: {0}")]
    TomlDecode(#[from] toml::de::Error),
    #[error("toml encode error: {0}")]
    TomlEncode(#[from] toml::ser::Error),
    #[error("internal: {0}")]
    Internal(String),
}

impl CoreError {
    pub fn code(&self) -> ErrorCode {
        match self {
            CoreError::PolicyDeny(_) => ErrorCode::PolicyDeny,
            CoreError::DeviceBusy(_) => ErrorCode::DeviceBusy,
            CoreError::WriteIo(_) => ErrorCode::WriteIo,
            CoreError::VerifyMismatch(_) => ErrorCode::VerifyMismatch,
            CoreError::DeviceRemoved(_) => ErrorCode::DeviceRemoved,
            CoreError::LayoutCheck(_) => ErrorCode::LayoutCheck,
            CoreError::AgentUnavailable(_) => ErrorCode::AgentUnavailable,
            CoreError::ImagePreparation(_) => ErrorCode::ImagePreparation,
            CoreError::InvalidRequest(_) => ErrorCode::InvalidRequest,
            CoreError::Io(_)
            | CoreError::SerdeJson(_)
            | CoreError::TomlDecode(_)
            | CoreError::TomlEncode(_)
            | CoreError::Internal(_) => ErrorCode::Internal,
        }
    }

    pub fn is_retryable(&self) -> bool {
        match self {
            CoreError::DeviceBusy(_) | CoreError::DeviceRemoved(_) => true,
            CoreError::WriteIo(message) => {
                let normalized = message.to_ascii_lowercase();
                !(normalized.contains("access is denied")
                    || normalized.contains("permission denied")
                    || normalized.contains("os error 5")
                    || normalized.contains("os error 13"))
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CoreError;

    #[test]
    fn write_io_access_denied_is_not_retryable() {
        let err = CoreError::WriteIo("Access is denied. (os error 5)".to_string());
        assert!(!err.is_retryable());
    }

    #[test]
    fn write_io_other_errors_remain_retryable() {
        let err = CoreError::WriteIo("The semaphore timeout period has expired.".to_string());
        assert!(err.is_retryable());
    }
}
