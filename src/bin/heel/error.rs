use std::io;
use std::path::PathBuf;

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

    /// The parse error carries the source span and is by far the largest thing
    /// this enum holds, so it is boxed rather than widening every `CliResult`.
    #[error("failed to parse config file {path}: {source}")]
    ParseConfig {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },

    #[error("invalid --env value (expected KEY=VALUE): {value}")]
    InvalidEnvFormat { value: String },

    #[error("--network allow-list requires at least one --allow-domain")]
    MissingAllowDomains,

    #[error(
        "HEEL_IPC_ENDPOINT is not set; `heel ipc` runs inside a sandbox that has IPC configured"
    )]
    MissingIpcEndpoint,

    #[error("IPC error: {source}")]
    Ipc {
        #[from]
        source: heel::IpcError,
    },

    #[error("failed to encode IPC arguments: {source}")]
    EncodeIpcArgs {
        #[from]
        source: rmp_serde::encode::Error,
    },

    #[error("failed to decode the IPC response: {source}")]
    DecodeIpcResponse {
        #[from]
        source: rmp_serde::decode::Error,
    },

    #[error("failed to render the IPC response: {source}")]
    RenderIpcResponse {
        #[from]
        source: serde_json::Error,
    },

    #[error("{command} takes no positional argument here: {value}")]
    UnexpectedPositional { command: String, value: String },

    #[error("{command} received an argument that is not --name or --name=value: {value}")]
    UnexpectedArgument { command: String, value: String },
}
