use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use serde::{Deserialize, Serialize};

use crate::cli::IpcArgs;
use crate::error::{CliError, CliResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CommandPayload {
    Text { content: String },
    Json { value: serde_json::Value },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommandEnvelope {
    ok: bool,
    #[serde(default)]
    payload: Option<CommandPayload>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LooseCommandEnvelope {
    ok: bool,
    #[serde(default)]
    payload: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<String>,
}

pub async fn execute(args: IpcArgs) -> CliResult<()> {
    let endpoint = env::var("HEEL_IPC_ENDPOINT").map_err(|_| CliError::MissingIpcEndpoint)?;
    let payload = build_payload(&args)?;
    let response = send_request(&endpoint, &args.command, &payload)?;
    if !response.is_empty() {
        print!("{response}");
    }
    Ok(())
}

fn build_payload(args: &IpcArgs) -> CliResult<Vec<u8>> {
    if args.args.is_empty() {
        return Ok(rmp_serde::to_vec(&serde_json::json!({}))?);
    }

    let args_array = args
        .args
        .iter()
        .cloned()
        .map(serde_json::Value::String)
        .collect();
    let mut map = HashMap::new();
    map.insert("args".to_string(), serde_json::Value::Array(args_array));
    Ok(rmp_serde::to_vec(&map)?)
}

fn send_request(endpoint: &str, method: &str, params: &[u8]) -> CliResult<String> {
    if let Some(address) = endpoint.strip_prefix("tcp://") {
        let mut stream = TcpStream::connect(address).map_err(|source| CliError::IpcTransport {
            endpoint: endpoint.to_string(),
            source,
        })?;
        return send_request_with_stream(&mut stream, method, params);
    }

    #[cfg(unix)]
    {
        let mut stream =
            UnixStream::connect(endpoint).map_err(|source| CliError::IpcTransport {
                endpoint: endpoint.to_string(),
                source,
            })?;
        send_request_with_stream(&mut stream, method, params)
    }

    #[cfg(not(unix))]
    {
        let _ = (method, params);
        Err(CliError::UnsupportedIpcEndpoint {
            endpoint: endpoint.to_string(),
        })
    }
}

fn send_request_with_stream<S: Read + Write>(
    stream: &mut S,
    method: &str,
    params: &[u8],
) -> CliResult<String> {
    let method_bytes = method.as_bytes();
    if method_bytes.len() > 255 {
        return Err(CliError::Message {
            message: "method name too long (max 255 bytes)".to_string(),
        });
    }

    let body_len = 1 + method_bytes.len() + params.len();
    let mut request = Vec::with_capacity(4 + body_len);
    request.extend_from_slice(&(body_len as u32).to_be_bytes());
    request.push(method_bytes.len() as u8);
    request.extend_from_slice(method_bytes);
    request.extend_from_slice(params);

    stream
        .write_all(&request)
        .map_err(|source| CliError::IpcTransport {
            endpoint: "request-write".to_string(),
            source,
        })?;

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|source| CliError::IpcTransport {
            endpoint: "response-length".to_string(),
            source,
        })?;
    let response_len = u32::from_be_bytes(len_buf) as usize;

    if response_len == 0 || response_len > 16 * 1024 * 1024 {
        return Err(CliError::InvalidIpcResponseLength {
            length: response_len,
        });
    }

    let mut body = vec![0u8; response_len];
    stream
        .read_exact(&mut body)
        .map_err(|source| CliError::IpcTransport {
            endpoint: "response-body".to_string(),
            source,
        })?;

    if body.is_empty() {
        return Err(CliError::Message {
            message: "empty IPC response".to_string(),
        });
    }

    let success = body[0] != 0;
    let payload = &body[1..];

    if success {
        match rmp_serde::from_slice::<CommandEnvelope>(payload) {
            Ok(envelope) => render_success_response(envelope),
            Err(decode_error) => {
                if let Ok(loose_envelope) = rmp_serde::from_slice::<LooseCommandEnvelope>(payload) {
                    if !loose_envelope.ok {
                        return Err(CliError::Message {
                            message: loose_envelope_error(loose_envelope),
                        });
                    }
                    if let Some(message) = loose_envelope.error {
                        return Err(CliError::Message { message });
                    }
                    if let Some(serde_json::Value::String(message)) = loose_envelope.payload {
                        return Err(CliError::Message { message });
                    }
                }
                if let Ok(message) = rmp_serde::from_slice::<String>(payload) {
                    return Err(CliError::Message { message });
                }
                Err(CliError::Message {
                    message: format!("failed to decode IPC response: {decode_error}"),
                })
            }
        }
    } else {
        let error = rmp_serde::from_slice::<String>(payload)
            .unwrap_or_else(|_| String::from_utf8_lossy(payload).to_string());
        Err(CliError::Message { message: error })
    }
}

fn render_success_response(envelope: CommandEnvelope) -> CliResult<String> {
    if !envelope.ok {
        return Err(CliError::Message {
            message: command_envelope_error(envelope),
        });
    }

    match envelope.payload {
        None => Ok(String::new()),
        Some(CommandPayload::Text { content }) => Ok(content),
        Some(CommandPayload::Json { value }) => Ok(serde_json::to_string_pretty(&value)?),
    }
}

fn payload_error_text(payload: Option<CommandPayload>) -> Option<String> {
    match payload {
        Some(CommandPayload::Text { content }) if !content.trim().is_empty() => Some(content),
        Some(CommandPayload::Json { value }) => Some(value.to_string()),
        _ => None,
    }
}

fn loose_payload_error_text(payload: Option<serde_json::Value>) -> Option<String> {
    match payload {
        Some(serde_json::Value::String(message)) if !message.trim().is_empty() => Some(message),
        Some(value) => Some(value.to_string()),
        None => None,
    }
}

fn command_envelope_error(envelope: CommandEnvelope) -> String {
    envelope
        .error
        .filter(|message| !message.trim().is_empty())
        .or_else(|| payload_error_text(envelope.payload))
        .unwrap_or_else(|| "IPC command failed".to_string())
}

fn loose_envelope_error(envelope: LooseCommandEnvelope) -> String {
    envelope
        .error
        .filter(|message| !message.trim().is_empty())
        .or_else(|| loose_payload_error_text(envelope.payload))
        .unwrap_or_else(|| "IPC command failed".to_string())
}
