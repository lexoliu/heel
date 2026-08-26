//! Wire protocol for IPC between a sandboxed process and the host.
//!
//! Both directions are length-prefixed frames carrying MessagePack:
//!
//! ```text
//! Request:  [u32 BE body length][u8 method length][method UTF-8][params MessagePack]
//! Response: [u32 BE body length][u8 success flag][payload MessagePack]
//! ```
//!
//! On success the payload is the command's response; on failure it is a
//! MessagePack string describing the error.

use std::io;

use thiserror::Error;

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

/// A decoded request.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct IpcRequest {
    /// Method name.
    pub method: String,
    /// MessagePack-encoded arguments.
    pub params: Vec<u8>,
}

impl IpcRequest {
    /// Decode a request body, excluding the length prefix.
    pub(crate) fn decode(body: &[u8]) -> Result<Self, IpcError> {
        let (&method_len, rest) = body
            .split_first()
            .ok_or_else(|| IpcError::InvalidProtocol("empty request".to_string()))?;
        let method_len = usize::from(method_len);

        if rest.len() < method_len {
            return Err(IpcError::InvalidProtocol("truncated method".to_string()));
        }
        let (method, params) = rest.split_at(method_len);

        let method = std::str::from_utf8(method)
            .map_err(|e| IpcError::InvalidProtocol(format!("invalid method UTF-8: {e}")))?
            .to_string();

        Ok(Self {
            method,
            params: params.to_vec(),
        })
    }

    /// Encode a request frame, including the length prefix.
    pub(crate) fn encode(method: &str, params: &[u8]) -> Result<Vec<u8>, IpcError> {
        let method = method.as_bytes();
        let method_len = u8::try_from(method.len())
            .map_err(|_| IpcError::InvalidProtocol("method name too long".to_string()))?;

        let body_len = 1 + method.len() + params.len();
        if body_len > MAX_FRAME_BYTES {
            return Err(IpcError::InvalidProtocol(format!(
                "request of {body_len} bytes exceeds the {MAX_FRAME_BYTES} byte limit"
            )));
        }

        let mut frame = Vec::with_capacity(4 + body_len);
        frame.extend_from_slice(&(body_len as u32).to_be_bytes());
        frame.push(method_len);
        frame.extend_from_slice(method);
        frame.extend_from_slice(params);
        Ok(frame)
    }
}

/// A response to a request.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct IpcResponse {
    /// Whether the command succeeded.
    pub success: bool,
    /// The command's response, or a MessagePack error string.
    pub payload: Vec<u8>,
}

impl IpcResponse {
    /// A successful response carrying an already-encoded payload.
    pub(crate) fn success(payload: Vec<u8>) -> Self {
        Self {
            success: true,
            payload,
        }
    }

    /// A failure response carrying `message`.
    pub(crate) fn error(message: &str) -> Self {
        Self {
            success: false,
            // Encoding a string cannot fail; an empty payload still decodes as
            // a failure, so there is no error path worth propagating here.
            payload: rmp_serde::to_vec(&message).unwrap_or_default(),
        }
    }

    /// Encode a response frame, including the length prefix.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let body_len = 1 + self.payload.len();
        let mut frame = Vec::with_capacity(4 + body_len);
        frame.extend_from_slice(&(body_len as u32).to_be_bytes());
        frame.push(u8::from(self.success));
        frame.extend_from_slice(&self.payload);
        frame
    }

    /// Decode a response body, excluding the length prefix.
    pub(crate) fn decode(body: &[u8]) -> Result<Self, IpcError> {
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

        let frame = IpcRequest::encode("search", &params).unwrap();
        let body_len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(body_len, frame.len() - 4);

        let request = IpcRequest::decode(&frame[4..]).unwrap();
        assert_eq!(request.method, "search");
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
        assert!(matches!(
            IpcRequest::decode(&[9, b'a', b'b', b'c']),
            Err(IpcError::InvalidProtocol(_))
        ));
    }

    #[test]
    fn overlong_method_names_are_rejected() {
        let method = "a".repeat(256);
        assert!(matches!(
            IpcRequest::encode(&method, &[]),
            Err(IpcError::InvalidProtocol(_))
        ));
    }

    #[test]
    fn oversized_requests_are_rejected() {
        let params = vec![0u8; MAX_FRAME_BYTES];
        assert!(matches!(
            IpcRequest::encode("big", &params),
            Err(IpcError::InvalidProtocol(_))
        ));
    }
}
