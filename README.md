# heel

A cross-platform Rust library for running LLM-generated code in secure sandboxes with native OS-level isolation.

## Why heel
Docker is a great tool for running containers, with isolation provided by the Linux kernel. However, it has to rely on virtualization to provide isolation on non-Linux platforms, which blocks it to provide GPU and NPU access.

Heel is built at the top of native OS-level isolation mechanisms, such as `sandbox-exec` on macOS, `landlock` on Linux, and `AppContainer` on Windows. It reduces some security, but more lightweight and powerful.

## Heel is not designed to be a general sandbox for running untrusted code.

Heel is designed to be a sandbox for running LLM-generated code in a secure environment. It is not designed to be a general sandbox for running untrusted code.

We provide three tier isolation level

- Strict: Most restricted, only allow read/write within sandbox's workdir.
- Default: Allow read/write within sandbox's workdir, and allow read-only access outside sandbox's workdir.
- Permissive: Least restricted, allow read/write access to all directories.


## Platform Support

| Platform | Backend | Status |
|----------|---------|--------|
| macOS | `sandbox-exec` with SBPL profiles | Fully implemented |
| Linux | Landlock (ABI v4) + Seccomp | Implemented (kernel 6.7+) |
| Windows | AppContainer | First-phase implemented: execution, strict filesystem, DenyAll network |

## Features

- **Native OS sandboxing** - Uses platform-specific isolation mechanisms for maximum security
- **Network policy enforcement** - All traffic routes through a local proxy with configurable filtering
- **Type-safe network policies** - Generic `Sandbox<N: NetworkPolicy>` enables compile-time policy composition
- **Fine-grained security controls** - Protect home directories, credentials, cloud configs, and more
- **IPC support** - Type-safe communication between sandboxed processes and the host
- **Python virtual environment support** - Built-in venv creation and management
- **Async-first, runtime-agnostic** - Works with any `executor-core` compatible runtime (smol, tokio)
- **Automatic cleanup** - Working directories and child processes are cleaned up on drop

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
heel = "0.1"
```

Install the CLI from the same crate:

```bash
cargo install heel
```

## Quick Start

```rust
use heel::Sandbox;

#[tokio::main]
async fn main() -> heel::Result<()> {
    // Create a sandbox with default configuration (network denied)
    let sandbox = Sandbox::new().await?;

    // Run a command in the sandbox
    let output = sandbox
        .command("echo")
        .arg("Hello from sandbox!")
        .output()
        .await?;

    println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}
```

## Network Policies

By default, all network access is denied. Configure access using built-in policies:

```rust
use heel::{AllowList, AllowAll, Sandbox, SandboxConfig};

// Allow specific domains (supports wildcards)
let policy = AllowList::new(["api.example.com", "*.github.com"]);

let config = SandboxConfig::builder()
    .network(policy)
    .build()?;

let sandbox = Sandbox::with_config(config).await?;
```

Available policies:
- `DenyAll` - Block all network access (default)
- `AllowAll` - Allow all network access
- `AllowList` - Allow specific domains with wildcard support
- `CustomPolicy<F>` - Custom async handler for dynamic filtering

## Security Configuration

Fine-grained control over what the sandbox can access:

```rust
use heel::{SandboxConfig, SecurityConfig};

let security = SecurityConfig::builder()
    .protect_user_home(true)      // Block ~/
    .protect_credentials(true)    // Block ~/.ssh, ~/.gnupg, keychains
    .protect_cloud_config(true)   // Block ~/.aws, ~/.azure, etc.
    .allow_gpu(false)             // Block GPU access
    .build();

let config = SandboxConfig::builder()
    .security(security)
    .build()?;
```

## IPC Communication

Enable sandboxed processes to call host-registered commands:

```rust
use heel::{IpcCommand, IpcRouter, Sandbox, SandboxConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct WebSearch {
    query: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SearchResult {
    items: Vec<String>,
}

impl IpcCommand for WebSearch {
    type Response = SearchResult;

    fn name(&self) -> String {
        "web_search".to_string()
    }

    fn apply_args(&mut self, params: &[u8]) -> Result<(), heel::rmp_serde::decode::Error> {
        *self = heel::rmp_serde::from_slice(params)?;
        Ok(())
    }

    async fn handle(&mut self) -> SearchResult {
        // Handle the search request from sandbox
        SearchResult { items: vec!["result1".into()] }
    }
}

// Register command and create sandbox
let router = IpcRouter::new().register(WebSearch::default());
let config = SandboxConfig::builder().ipc(router).build()?;
let sandbox = Sandbox::with_config(config).await?;
```

Sandboxed processes use the `heel ipc` subcommand to call registered commands.

## Python Support

Built-in virtual environment management:

```rust
use heel::{PythonConfig, Sandbox, SandboxConfig, VenvConfig, VenvManager};

// Create a venv with packages
let venv_config = VenvConfig::builder()
    .path("/tmp/my-venv")
    .packages(["requests", "numpy"])
    .build();

VenvManager::create(&venv_config).await?;

// Create sandbox with Python configured
let config = SandboxConfig::builder()
    .python(PythonConfig::builder().venv(venv_config).build())
    .build()?;

let sandbox = Sandbox::with_config(config).await?;

// Run Python code
let output = sandbox
    .run_python("import sys; print(sys.version)")
    .await?;
```

## CLI

The `heel` crate also ships the `heel` CLI:

```bash
# Run a command in sandbox
heel run echo hello

# Interactive shell in sandbox
heel shell

# Run Python script with venv
heel python script.py
```

## License

MIT OR Apache-2.0
