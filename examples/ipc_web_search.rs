//! IPC example with WebSearch command
//!
//! This example demonstrates how to:
//! 1. Define an IPC command (WebSearch)
//! 2. Register it with IpcRouter
//! 3. Create a sandbox with IPC enabled
//! 4. Call the command from within the sandbox
//!
//! Run with: cargo run --example ipc_web_search

use heel::{IpcCommand, IpcRouter, Sandbox, SandboxConfig};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CommandPayload {
    Text { content: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommandEnvelope {
    ok: bool,
    payload: Option<CommandPayload>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CliArgsPayload {
    args: Vec<String>,
}

/// WebSearch command - sent from sandbox to host
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct WebSearch {
    query: String,
}

/// WebSearch response - returned from host to sandbox
#[derive(Debug, Serialize, Deserialize)]
struct WebSearchResult {
    items: Vec<SearchItem>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SearchItem {
    title: String,
    url: String,
}

impl IpcCommand for WebSearch {
    type Response = CommandEnvelope;

    fn name(&self) -> String {
        "web_search".to_string()
    }

    fn positional_args(&self) -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[Cow::Borrowed("query")])
    }

    fn apply_args(&mut self, params: &[u8]) -> Result<(), heel::rmp_serde::decode::Error> {
        let payload: CliArgsPayload = heel::rmp_serde::from_slice(params)?;
        let mut args = payload.args.into_iter();
        while let Some(arg) = args.next() {
            if arg == "--query" {
                self.query = args.next().unwrap_or_default();
            }
        }
        Ok(())
    }

    async fn handle(&mut self) -> CommandEnvelope {
        println!("[Host] Received web_search: {:?}", self.query);

        // Mock results (real implementation would call a search API)
        let result = WebSearchResult {
            items: vec![
                SearchItem {
                    title: format!("Result 1 for '{}'", self.query),
                    url: "https://example.com/1".to_string(),
                },
                SearchItem {
                    title: format!("Result 2 for '{}'", self.query),
                    url: "https://example.com/2".to_string(),
                },
            ],
        };
        let content = result
            .items
            .iter()
            .map(|item| format!("{} | {}", item.title, item.url))
            .collect::<Vec<_>>()
            .join("\n");

        CommandEnvelope {
            ok: true,
            payload: Some(CommandPayload::Text { content }),
            error: None,
        }
    }
}

#[tokio::main]
async fn main() -> heel::Result<()> {
    tracing_subscriber::fmt::init();

    // Create router and register WebSearch command
    let router = IpcRouter::new().register(WebSearch::default());

    // Create sandbox with IPC enabled, using tokio executor
    let config = SandboxConfig::builder().ipc(router).build()?;
    let sandbox =
        Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal).await?;

    println!("Sandbox: {}", sandbox.working_dir().display());

    // Call web_search from sandbox via the generated IPC wrapper command.
    let output = sandbox
        .command("web_search")
        .arg("--query")
        .arg("rust async programming")
        .output()
        .await?;

    println!("\nExit: {:?}", output.status);
    println!("stdout:\n{}", String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        eprintln!("stderr:\n{}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}
