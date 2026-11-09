use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Serialize, Deserialize)]
pub(crate) enum DeviceRkpError {
    #[error(
        "only some devices support this feature and only RKP certificates can be issued; pass --acknowledge-limitations to continue"
    )]
    AcknowledgementRequired,
    #[error("device prerequisites are not met: {0}")]
    UnsupportedDevice(String),
    #[error("KeyMint worker exceeded its 30 second timeout")]
    Timeout,
    #[error("KeyMint transport failed: {0}")]
    Transport(String),
    #[error("KeyMint rejected the CSR request with status {status}: {detail}")]
    RejectedWithDetail {
        status: i32,
        detail: String,
    },
    #[error("KeyMint rejected the CSR request with status {0}")]
    Rejected(i32),
    #[error("invalid KeyMint response: {0}")]
    InvalidResponse(String),
    #[error("CSR validation failed: {0}")]
    InvalidCsr(String),
    #[error("the issued certificate does not match the generated P-256 key")]
    CertificateMismatch,
    #[error("all available issuance methods failed: {0}")]
    AllMethodsFailed(String),
}

pub(crate) fn code_of(error: &anyhow::Error) -> &'static str {
    for cause in error.chain() {
        if let Some(error) = cause.downcast_ref::<DeviceRkpError>() {
            return match error {
                DeviceRkpError::AcknowledgementRequired => "acknowledgement_required",
                DeviceRkpError::UnsupportedDevice(_) => "unsupported_device",
                DeviceRkpError::Timeout => "ta_timeout",
                DeviceRkpError::Transport(_) => "ta_transport_error",
                DeviceRkpError::RejectedWithDetail { .. } | DeviceRkpError::Rejected(_) => {
                    "ta_rejected"
                }
                DeviceRkpError::InvalidResponse(_) => "invalid_ta_response",
                DeviceRkpError::InvalidCsr(_) => "invalid_device_csr",
                DeviceRkpError::CertificateMismatch => "certificate_key_mismatch",
                DeviceRkpError::AllMethodsFailed(_) => "all_methods_failed",
            };
        }
    }
    duck_rkp::error::code_of(error)
}
