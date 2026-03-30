use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use thiserror::Error;

pub type CliResult<T> = std::result::Result<T, CliError>;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{source}")]
    Sandbox {
        #[from]
        source: heel::Error,
    },

    #[error("I/O error: {source}")]
    Io {
        #[from]
        source: io::Error,
    },

    #[error("failed to read config file {path}: {source}")]
    ReadConfig { path: PathBuf, source: io::Error },

    #[error("failed to parse config file {path}: {source}")]
    ParseConfig {
        path: PathBuf,
        source: toml::de::Error,
    },

    #[error("invalid network mode in config: {value}")]
    InvalidNetworkMode { value: String },

    #[error("invalid env format (expected KEY=VALUE): {value}")]
    InvalidEnvFormat { value: String },

    #[error("--network allow-list requires at least one --allow-domain")]
    MissingAllowDomains,

    #[error("HEEL_IPC_ENDPOINT environment variable not set")]
    MissingIpcEndpoint,

    #[error("IPC request serialization failed: {source}")]
    SerializeIpcRequest {
        #[from]
        source: rmp_serde::encode::Error,
    },

    #[error("IPC response decode failed: {source}")]
    DecodeIpcResponse {
        #[from]
        source: rmp_serde::decode::Error,
    },

    #[error("IPC JSON rendering failed: {source}")]
    RenderIpcJson {
        #[from]
        source: serde_json::Error,
    },

    #[error("IPC transport error on {endpoint}: {source}")]
    IpcTransport { endpoint: String, source: io::Error },

    #[error("invalid IPC response length: {length}")]
    InvalidIpcResponseLength { length: usize },

    #[cfg(not(unix))]
    #[error("unsupported IPC endpoint: {endpoint}")]
    UnsupportedIpcEndpoint { endpoint: String },

    #[error("{message}")]
    Message { message: String },
}

/// Convert a CliResult to an ExitCode, printing errors to stderr
pub fn to_exit_code(result: CliResult<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
