//! Expose host functionality to sandboxed code over IPC.
//!
//! The sandbox denies network access, but the host can still offer a narrow,
//! typed interface. Each registered command appears inside the sandbox as an
//! ordinary executable on `PATH`.

// Examples report what the sandbox did, so printing is the point here.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::sync::atomic::{AtomicUsize, Ordering};

use heel::ipc::{IpcCommand, IpcRouter};
use heel::{Sandbox, SandboxConfig};
use serde::{Deserialize, Serialize};

/// A search command holding whatever state the handler needs.
struct WebSearch {
    /// Stands in for a client or API key; state lives on the command itself and
    /// is set up once rather than rebuilt per request.
    calls: AtomicUsize,
}

#[derive(Deserialize)]
struct WebSearchArgs {
    query: String,
}

#[derive(Serialize)]
struct WebSearchResult {
    query: String,
    call_number: usize,
    items: Vec<String>,
}

impl IpcCommand for WebSearch {
    const NAME: &'static str = "web_search";
    // Lets sandboxed code write `web_search "rust"` instead of
    // `web_search --query rust`.
    const POSITIONAL_ARGS: &'static [&'static str] = &["query"];

    type Args = WebSearchArgs;
    type Response = WebSearchResult;

    async fn handle(&self, args: WebSearchArgs) -> WebSearchResult {
        let call_number = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
        WebSearchResult {
            items: vec![format!("result for {}", args.query)],
            query: args.query,
            call_number,
        }
    }
}

/// A command that reads piped standard input.
struct Summarize;

#[derive(Deserialize)]
struct SummarizeArgs {
    text: String,
}

impl IpcCommand for Summarize {
    const NAME: &'static str = "summarize";
    const STDIN_ARG: Option<&'static str> = Some("text");

    type Args = SummarizeArgs;
    type Response = String;

    async fn handle(&self, args: SummarizeArgs) -> String {
        format!("{} characters of input", args.text.len())
    }
}

#[tokio::main]
async fn main() -> heel::Result<()> {
    tracing_subscriber::fmt::init();

    let router = IpcRouter::new()
        .register(WebSearch {
            calls: AtomicUsize::new(0),
        })
        .register(Summarize);

    let config = SandboxConfig::builder().ipc(router).build();
    let sandbox =
        Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal).await?;

    // Positional arguments, twice, to show that handler state persists.
    for query in ["rust sandboxing", "landlock"] {
        let output = sandbox.command("web_search").arg(query).output().await?;
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }

    // Piped standard input.
    let output = sandbox
        .command("/bin/sh")
        .arg("-c")
        .arg("echo 'some text to summarize' | summarize")
        .output()
        .await?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));

    Ok(())
}
