//! Wire protocol for IPC between a sandboxed process and the host.
//!
//! Both directions are length-prefixed frames carrying MessagePack:
//!
//! ```text
//! Request:  [u32 BE body length][u8 0x00][u8 protocol version]
//!           [u8 method length][method UTF-8]
//!           [u16 BE directory length][working directory UTF-8][params MessagePack]
//! Response: [u32 BE body length][u8 success flag][payload MessagePack]
//! ```
//!
//! On success the payload is the command's response; on failure it is a
//! MessagePack string describing the error.
//!
//! A request body starts with a zero byte and the protocol version
//! ([`PROTOCOL_VERSION`], bumped whenever the request frame changes). Frames
//! from before versioning began with the method length, which is never zero,
//! so a leading non-zero byte identifies a client older than the version
//! byte. The response frame is unchanged, so every client can read the host's
//! refusal.

use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// The version of the request frame this build speaks.
pub const PROTOCOL_VERSION: u8 = 1;

/// The byte that opens a versioned request body.
const VERSIONED_MARKER: u8 = 0;

/// Largest frame either side will read, to bound the memory one request can
/// make the peer allocate.
pub(crate) const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Errors raised while serving or issuing an IPC request.
#[derive(Debug, Error)]
pub enum IpcError {
    /// The requested method is not registered.
    #[error("unknown method: {0}")]
    UnknownMethod(String),

    /// A response could not be encoded.
    #[error("serialization error: {0}")]
    Serialization(#[from] rmp_serde::encode::Error),

    /// Request arguments could not be decoded.
    #[error("deserialization error: {0}")]
    Deserialization(#[from] rmp_serde::decode::Error),

    /// The transport failed.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// The peer sent something that is not a valid frame.
    #[error("invalid protocol: {0}")]
    InvalidProtocol(String),

    /// The host handler reported a failure.
    #[error("{0}")]
    Remote(String),
}

impl IpcError {
    /// A failure reported by the host handler.
    pub fn remote(error: impl std::fmt::Display) -> Self {
        Self::Remote(error.to_string())
    }
}

/// A decoded request.
#[derive(Debug, PartialEq, Eq)]
pub struct IpcRequest {
    /// Method name.
    pub method: String,
    /// The working directory of the process that sent the request, read when
    /// the request was made.
    pub working_dir: PathBuf,
    /// MessagePack-encoded arguments.
    pub params: Vec<u8>,
}

impl IpcRequest {
    /// Decode a request body, excluding the length prefix.
    pub fn decode(body: &[u8]) -> Result<Self, IpcError> {
        let (&marker, rest) = body
            .split_first()
            .ok_or_else(|| IpcError::InvalidProtocol("empty request".to_string()))?;
        if marker != VERSIONED_MARKER {
            return Err(IpcError::InvalidProtocol(format!(
                "the client speaks an unversioned protocol older than version 1, \
                 the host speaks protocol version {PROTOCOL_VERSION}; \
                 the heel binary the sandbox runs is out of date"
            )));
        }
        let (&version, rest) = rest
            .split_first()
            .ok_or_else(|| IpcError::InvalidProtocol("missing protocol version".to_string()))?;
        if version != PROTOCOL_VERSION {
            return Err(IpcError::InvalidProtocol(format!(
                "the client speaks protocol version {version}, \
                 the host speaks protocol version {PROTOCOL_VERSION}; \
                 the heel binary the sandbox runs does not match the library"
            )));
        }
        let (&method_len, rest) = rest
            .split_first()
            .ok_or_else(|| IpcError::InvalidProtocol("missing method".to_string()))?;
        let method_len = usize::from(method_len);

        if rest.len() < method_len {
            return Err(IpcError::InvalidProtocol("truncated method".to_string()));
        }
        let (method, rest) = rest.split_at(method_len);

        let method = std::str::from_utf8(method)
            .map_err(|e| IpcError::InvalidProtocol(format!("invalid method UTF-8: {e}")))?
            .to_string();

        let (dir_len, rest) = rest
            .split_first_chunk::<2>()
            .ok_or_else(|| IpcError::InvalidProtocol("missing working directory".to_string()))?;
        let dir_len = usize::from(u16::from_be_bytes(*dir_len));
        if rest.len() < dir_len {
            return Err(IpcError::InvalidProtocol(
                "truncated working directory".to_string(),
            ));
        }
        let (working_dir, params) = rest.split_at(dir_len);
        let working_dir = std::str::from_utf8(working_dir)
            .map_err(|e| IpcError::InvalidProtocol(format!("invalid directory UTF-8: {e}")))?;

        Ok(Self {
            method,
            working_dir: PathBuf::from(working_dir),
            params: params.to_vec(),
        })
    }

    /// Encode a request frame, including the length prefix.
    pub fn encode(method: &str, working_dir: &Path, params: &[u8]) -> Result<Vec<u8>, IpcError> {
        let method = method.as_bytes();
        let method_len = u8::try_from(method.len())
            .map_err(|_| IpcError::InvalidProtocol("method name too long".to_string()))?;
        let working_dir = working_dir
            .to_str()
            .ok_or_else(|| {
                IpcError::InvalidProtocol("working directory is not valid UTF-8".to_string())
            })?
            .as_bytes();
        let dir_len = u16::try_from(working_dir.len())
            .map_err(|_| IpcError::InvalidProtocol("working directory too long".to_string()))?;

        let body_len = 2 + 1 + method.len() + 2 + working_dir.len() + params.len();
        if body_len > MAX_FRAME_BYTES {
            return Err(IpcError::InvalidProtocol(format!(
                "request of {body_len} bytes exceeds the {MAX_FRAME_BYTES} byte limit"
            )));
        }

        let mut frame = Vec::with_capacity(4 + body_len);
        frame.extend_from_slice(&(body_len as u32).to_be_bytes());
        frame.push(VERSIONED_MARKER);
        frame.push(PROTOCOL_VERSION);
        frame.push(method_len);
        frame.extend_from_slice(method);
        frame.extend_from_slice(&dir_len.to_be_bytes());
        frame.extend_from_slice(working_dir);
        frame.extend_from_slice(params);
        Ok(frame)
    }
}

/// A response to a request.
#[derive(Debug, PartialEq, Eq)]
pub struct IpcResponse {
    /// Whether the command succeeded.
    pub success: bool,
    /// The command's response, or a MessagePack error string.
    pub payload: Vec<u8>,
}

impl IpcResponse {
    /// A successful response carrying an already-encoded payload.
    pub fn success(payload: Vec<u8>) -> Self {
        Self {
            success: true,
            payload,
        }
    }

    /// A failure response carrying `message`.
    pub fn error(message: &str) -> Self {
        Self {
            success: false,
            // Encoding a string cannot fail; an empty payload still decodes as
            // a failure, so there is no error path worth propagating here.
            payload: rmp_serde::to_vec(&message).unwrap_or_default(),
        }
    }

    /// Encode a response frame, including the length prefix.
    pub fn encode(&self) -> Vec<u8> {
        let body_len = 1 + self.payload.len();
        let mut frame = Vec::with_capacity(4 + body_len);
        frame.extend_from_slice(&(body_len as u32).to_be_bytes());
        frame.push(u8::from(self.success));
        frame.extend_from_slice(&self.payload);
        frame
    }

    /// Decode a response body, excluding the length prefix.
    pub fn decode(body: &[u8]) -> Result<Self, IpcError> {
        let (&flag, payload) = body
            .split_first()
            .ok_or_else(|| IpcError::InvalidProtocol("empty response".to_string()))?;

        Ok(Self {
            success: flag != 0,
            payload: payload.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Params {
        query: String,
    }

    #[test]
    fn requests_round_trip() {
        let params = rmp_serde::to_vec_named(&Params {
            query: "hello".to_string(),
        })
        .unwrap();

        let frame = IpcRequest::encode("search", Path::new("/work/sub"), &params).unwrap();
        let body_len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(body_len, frame.len() - 4);

        let request = IpcRequest::decode(&frame[4..]).unwrap();
        assert_eq!(request.method, "search");
        assert_eq!(request.working_dir, Path::new("/work/sub"));
        assert_eq!(
            rmp_serde::from_slice::<Params>(&request.params).unwrap(),
            Params {
                query: "hello".to_string()
            }
        );
    }

    #[test]
    fn responses_round_trip() {
        let payload = rmp_serde::to_vec_named(&Params {
            query: "ok".to_string(),
        })
        .unwrap();
        let frame = IpcResponse::success(payload.clone()).encode();
        let response = IpcResponse::decode(&frame[4..]).unwrap();

        assert!(response.success);
        assert_eq!(response.payload, payload);
    }

    #[test]
    fn error_responses_round_trip() {
        let frame = IpcResponse::error("something went wrong").encode();
        let response = IpcResponse::decode(&frame[4..]).unwrap();

        assert!(!response.success);
        assert_eq!(
            rmp_serde::from_slice::<String>(&response.payload).unwrap(),
            "something went wrong"
        );
    }

    #[test]
    fn truncated_requests_are_rejected() {
        assert!(matches!(
            IpcRequest::decode(&[]),
            Err(IpcError::InvalidProtocol(_))
        ));
        // Claims a 9-byte method but carries 3 bytes.
        let v = PROTOCOL_VERSION;
        assert!(matches!(
            IpcRequest::decode(&[0, v, 9, b'a', b'b', b'c']),
            Err(IpcError::InvalidProtocol(_))
        ));
        // A method with no directory field after it.
        assert!(matches!(
            IpcRequest::decode(&[0, v, 1, b'a']),
            Err(IpcError::InvalidProtocol(_))
        ));
        // Claims a 5-byte directory but carries 1 byte.
        assert!(matches!(
            IpcRequest::decode(&[0, v, 1, b'a', 0, 5, b'/']),
            Err(IpcError::InvalidProtocol(_))
        ));
    }

    fn protocol_error(body: &[u8]) -> String {
        match IpcRequest::decode(body) {
            Err(IpcError::InvalidProtocol(message)) => message,
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }

    #[test]
    fn other_protocol_versions_are_refused_naming_both() {
        let mut frame = IpcRequest::encode("search", Path::new("/"), &[]).unwrap();
        let other = PROTOCOL_VERSION + 1;
        frame[5] = other;

        let message = protocol_error(&frame[4..]);
        assert!(
            message.contains(&format!("client speaks protocol version {other}"))
                && message.contains(&format!("host speaks protocol version {PROTOCOL_VERSION}")),
            "{message}"
        );
    }

    #[test]
    fn unversioned_clients_are_told_they_are_out_of_date() {
        // The frame an older client sends: the method length leads, and the
        // working directory field may be absent altogether.
        let message = protocol_error(&[6, b's', b'e', b'a', b'r', b'c', b'h']);
        assert!(message.contains("unversioned"), "{message}");
        assert!(!message.contains("truncated"), "{message}");
    }

    #[test]
    fn overlong_working_directories_are_rejected() {
        let dir = "d".repeat(usize::from(u16::MAX) + 1);
        assert!(matches!(
            IpcRequest::encode("m", Path::new(&dir), &[]),
            Err(IpcError::InvalidProtocol(_))
        ));
    }

    #[test]
    fn overlong_method_names_are_rejected() {
        let method = "a".repeat(256);
        assert!(matches!(
            IpcRequest::encode(&method, Path::new("/"), &[]),
            Err(IpcError::InvalidProtocol(_))
        ));
    }

    #[test]
    fn oversized_requests_are_rejected() {
        let params = vec![0u8; MAX_FRAME_BYTES];
        assert!(matches!(
            IpcRequest::encode("big", Path::new("/"), &params),
            Err(IpcError::InvalidProtocol(_))
        ));
    }
}
