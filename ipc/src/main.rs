//! CLI tool for IPC communication with leash sandbox
//!
//! Usage:
//!   leash-ipc <command> [args...]
//!   leash-ipc search --query "rust async"
//!   leash-ipc search -q "rust async"

use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use clap::Parser;
use serde::{Deserialize, Serialize};

/// CLI tool for IPC communication with leash sandbox
#[derive(Parser)]
#[command(name = "leash-ipc")]
#[command(about = "Send IPC commands to leash sandbox")]
struct Cli {
    /// Command name to invoke
    command: String,

    /// Arguments forwarded to the IPC command
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

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

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Get socket path from environment
    let socket_path = match env::var("LEASH_IPC_SOCKET") {
        Ok(path) => path,
        Err(_) => {
            eprintln!("error: LEASH_IPC_SOCKET environment variable not set");
            return ExitCode::FAILURE;
        }
    };

    // Build the payload
    let payload = match build_payload(&cli) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Connect and send request
    match send_request(&socket_path, &cli.command, &payload) {
        Ok(response) => {
            if !response.is_empty() {
                print!("{response}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn build_payload(cli: &Cli) -> Result<Vec<u8>, String> {
    if !cli.args.is_empty() {
        let args_array: Vec<serde_json::Value> = cli
            .args
            .iter()
            .map(|s| serde_json::Value::String(s.clone()))
            .collect();
        let mut map: HashMap<String, serde_json::Value> = HashMap::new();
        map.insert("args".to_string(), serde_json::Value::Array(args_array));
        rmp_serde::to_vec(&map).map_err(|e| format!("serialization failed: {e}"))
    } else {
        // Empty payload
        rmp_serde::to_vec(&serde_json::json!({})).map_err(|e| format!("serialization failed: {e}"))
    }
}

fn send_request(socket_path: &str, method: &str, params: &[u8]) -> Result<String, String> {
    if let Some(address) = socket_path.strip_prefix("tcp://") {
        let mut stream =
            TcpStream::connect(address).map_err(|e| format!("failed to connect: {e}"))?;
        return send_request_with_stream(&mut stream, method, params);
    }

    #[cfg(unix)]
    {
        let mut stream =
            UnixStream::connect(socket_path).map_err(|e| format!("failed to connect: {e}"))?;
        return send_request_with_stream(&mut stream, method, params);
    }

    #[cfg(not(unix))]
    {
        let _ = (method, params);
        Err(format!(
            "unix socket transport is not supported on this platform: {socket_path}"
        ))
    }
}

fn send_request_with_stream<S: Read + Write>(
    stream: &mut S,
    method: &str,
    params: &[u8],
) -> Result<String, String> {
    // Build the request:
    // [4 bytes: total length (u32 BE)]
    // [1 byte: method length (u8)]
    // [method bytes (UTF-8)]
    // [params bytes (MessagePack)]
    let method_bytes = method.as_bytes();
    if method_bytes.len() > 255 {
        return Err("method name too long (max 255 bytes)".to_string());
    }

    let body_len = 1 + method_bytes.len() + params.len();
    let mut request = Vec::with_capacity(4 + body_len);
    request.extend_from_slice(&(body_len as u32).to_be_bytes());
    request.push(method_bytes.len() as u8);
    request.extend_from_slice(method_bytes);
    request.extend_from_slice(params);

    // Send the request
    stream
        .write_all(&request)
        .map_err(|e| format!("failed to send request: {e}"))?;

    // Read the response length
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("failed to read response length: {e}"))?;
    let response_len = u32::from_be_bytes(len_buf) as usize;

    if response_len == 0 || response_len > 16 * 1024 * 1024 {
        return Err(format!("invalid response length: {response_len}"));
    }

    // Read the response body
    let mut body = vec![0u8; response_len];
    stream
        .read_exact(&mut body)
        .map_err(|e| format!("failed to read response: {e}"))?;

    // Parse the response:
    // [1 byte: success flag (0 or 1)]
    // [payload bytes (MessagePack result or error string)]
    if body.is_empty() {
        return Err("empty response".to_string());
    }

    let success = body[0] != 0;
    let payload = &body[1..];

    if success {
        // Deserialize MessagePack to JSON value
        let envelope: CommandEnvelope = rmp_serde::from_slice(payload)
            .map_err(|e| format!("failed to decode response: {e}"))?;
        render_success_response(envelope)
    } else {
        // Error message is in payload
        let error: String = rmp_serde::from_slice(payload)
            .unwrap_or_else(|_| String::from_utf8_lossy(payload).to_string());
        Err(error)
    }
}

fn render_success_response(envelope: CommandEnvelope) -> Result<String, String> {
    if !envelope.ok {
        return Err(envelope
            .error
            .unwrap_or_else(|| "IPC command failed".to_string()));
    }

    match envelope.payload {
        None => Ok(String::new()),
        Some(CommandPayload::Text { content }) => Ok(content),
        Some(CommandPayload::Json { value }) => {
            serde_json::to_string_pretty(&value).map_err(|e| format!("JSON encoding failed: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::{CommandEnvelope, CommandPayload, render_success_response, send_request};

    fn start_mock_tcp_server(response: CommandEnvelope) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("read listener address");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept test client");

            let mut len_buf = [0u8; 4];
            stream
                .read_exact(&mut len_buf)
                .expect("read request length");
            let request_len = u32::from_be_bytes(len_buf) as usize;
            let mut request_body = vec![0u8; request_len];
            stream
                .read_exact(&mut request_body)
                .expect("read request body");

            let method_len = request_body[0] as usize;
            let method = std::str::from_utf8(&request_body[1..1 + method_len])
                .expect("decode request method");
            assert_eq!(method, "webfetch");

            let payload = rmp_serde::to_vec(&response).expect("encode response envelope");
            let mut body = Vec::with_capacity(payload.len() + 1);
            body.push(1);
            body.extend_from_slice(&payload);
            stream
                .write_all(&(body.len() as u32).to_be_bytes())
                .expect("write response length");
            stream.write_all(&body).expect("write response body");
        });
        format!("tcp://{address}")
    }

    #[test]
    fn raw_text_payload_is_not_json_quoted() {
        let rendered = render_success_response(CommandEnvelope {
            ok: true,
            payload: Some(CommandPayload::Text {
                content: "plain text".to_string(),
            }),
            error: None,
        })
        .expect("text payload should render");
        assert_eq!(rendered, "plain text");
    }

    #[test]
    fn json_payload_is_pretty_rendered() {
        let rendered = render_success_response(CommandEnvelope {
            ok: true,
            payload: Some(CommandPayload::Json {
                value: serde_json::json!({ "ok": true }),
            }),
            error: None,
        })
        .expect("json payload should render");
        assert!(rendered.contains("\"ok\": true"));
    }

    #[test]
    fn command_error_becomes_process_error() {
        let error = render_success_response(CommandEnvelope {
            ok: false,
            payload: None,
            error: Some("boom".to_string()),
        })
        .expect_err("error envelope must fail");
        assert_eq!(error, "boom");
    }

    #[test]
    fn tcp_transport_renders_raw_text_without_quotes() {
        let address = start_mock_tcp_server(CommandEnvelope {
            ok: true,
            payload: Some(CommandPayload::Text {
                content: "plain tcp text".to_string(),
            }),
            error: None,
        });
        let rendered = send_request(address.as_str(), "webfetch", &[])
            .expect("tcp success response should render");
        assert_eq!(rendered, "plain tcp text");
    }

    #[test]
    fn tcp_transport_surfaces_command_failures() {
        let address = start_mock_tcp_server(CommandEnvelope {
            ok: false,
            payload: None,
            error: Some("tcp boom".to_string()),
        });
        let error = send_request(address.as_str(), "webfetch", &[])
            .expect_err("tcp error response should fail");
        assert_eq!(error, "tcp boom");
    }
}
