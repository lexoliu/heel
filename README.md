# heel

A cross-platform Rust library for running LLM-generated code in secure sandboxes with native OS-level isolation.

## Why heel

Docker is a great tool for running containers, with isolation provided by the Linux kernel. However, it has to rely on virtualization to provide isolation on non-Linux platforms, which blocks it from providing GPU and NPU access.

Heel is built on top of native OS-level isolation mechanisms: `sandbox-exec` on macOS, Landlock and Seccomp on Linux, and AppContainer on Windows. It gives up some isolation strength in exchange for being lightweight and for keeping hardware access available.

## Heel is not designed to be a general sandbox for running untrusted code.

Heel is designed for running LLM-generated code in a secure environment. It is not designed to be a general sandbox for arbitrary untrusted code.

## Platform Support

| Platform | Backend | Status |
|----------|---------|--------|
| macOS | `sandbox-exec` with SBPL profiles | ✅ Fully implemented |
| Linux | Landlock (ABI v4) + Seccomp | ✅ Implemented (kernel 6.7+) |
| Windows | AppContainer + job objects | ✅ Implemented (Windows 10+) |

## What the sandbox enforces

- **The working directory is the only writable place.** It is created for the sandbox and removed when the sandbox is dropped. Temporary files are directed into it through `TMPDIR` on Unix and `TEMP`/`TMP` on Windows, where an AppContainer is additionally given a private temporary directory of its own that nothing outside the container can read.
- **Nothing writable is executable.** The working directory, configured writable paths and the shared temp directories are all denied execute, so sandboxed code cannot drop a payload and run it. Each backend spells that differently: SBPL and Landlock withhold execute directly, while on NTFS "run this file" and "enter this directory" are one bit, so directories and files are granted separately. The one exception is an explicit executable grant, which — like every explicit grant — beats the default protection: a path passed to `executable_path` may name a file or a directory, and a directory grant covers everything beneath it on all three backends. Listing the same directory as writable *and* executable is therefore a deliberate choice to give up the write-then-execute guarantee for that directory, and only for it. A build cache such as Cargo's `target/`, which writes test binaries under hashed names and runs them immediately, is what this is for.
- **Network access goes through a policy.** Under the default `DenyAll` no proxy exists and the kernel refuses outbound connections; any other policy routes every connection through a local proxy that applies the policy per request.
- **Reads are opt-in above a baseline.** Configured paths are granted explicitly, and an explicit grant always beats a default protection.
- **Resource limits apply to the whole process tree**, installed with `setrlimit` between fork and exec on Unix, and carried by a job object on Windows.

### Isolation levels

The CLI exposes three levels through `--isolation`:

| Level | Reads | Writes | Exec |
|-------|-------|--------|------|
| `strict` | System files only; all user data and shared temp denied | Working directory only | Not from writable locations |
| `default` | System files, unprotected user files, shared temp | Working directory only | Not from writable locations |
| `permissive` | Everything | Everything | Unrestricted apart from shared temp |

The shared temp directories are never writable outside `permissive`: the sandbox
has its own writable directory and exports it as `TMPDIR`, so nothing needs to
write there. `permissive` gives up the write-then-execute guarantee by
definition — that is what makes it permissive.

On macOS, `strict` denies `/Users`, `/home`, `/Volumes`, `/Network` and the shared temp directories outright. System files stay readable in every level because the macOS runtime layout — dyld caches, cryptexes, sealed system volumes — is not stably enumerable across releases, so an allow list of system paths would break on the next OS update. On Linux, Landlock is default-deny and only the listed paths are granted at all.

## Features

- **Native OS sandboxing** - platform isolation mechanisms rather than a VM
- **Network policy enforcement** - all traffic routes through a local proxy with configurable filtering
- **Type-safe network policies** - `Sandbox<N: NetworkPolicy>` composes policies at compile time
- **Fine-grained protections** - home directories, credentials, cloud configs, browser data, keychains
- **Typed IPC** - a narrow, audited escape hatch from the sandbox to the host
- **Python virtual environments** - created on the host before the sandbox starts
- **Async-first, runtime-agnostic** - works with any `executor-core` runtime (smol, tokio)
- **Automatic cleanup** - working directories and child processes are released on drop

## Installation

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
    // Network access is denied by default.
    let sandbox = Sandbox::new().await?;

    let output = sandbox
        .command("/bin/echo")
        .arg("Hello from the sandbox")
        .output()
        .await?;

    println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}
```

## Network Policies

```rust
use heel::{AllowList, Sandbox, SandboxConfig};

// Wildcards match subdomains: *.github.com covers api.github.com but not github.com.
let config = SandboxConfig::builder()
    .network(AllowList::new(["api.example.com", "*.github.com"]))
    .build();

let sandbox = Sandbox::with_config(config).await?;
```

Available policies:

- `DenyAll` — deny everything (default). No proxy runs; the kernel does the denying.
- `AllowAll` — allow everything
- `AllowList` — allow specific domains, matched case-insensitively, with `*.example.com` wildcards
- `CustomPolicy<F>` — decide per request with an async handler
- `Audited<N>` — wrap any policy to record every decision as JSON lines, into one file (`NetworkAuditLog::file`) or a daily-rotated set of them (`NetworkAuditLog::rolling_daily`)

The proxy refuses to forward to addresses local to the host, so a policy that allows a hostname cannot be used to reach services on the machine running the sandbox.

## Security Configuration

```rust
use heel::{SandboxConfig, SecurityConfig};

let security = SecurityConfig::builder()
    .protect_user_home(true)      // Deny ~/
    .protect_credentials(true)    // Deny ~/.ssh, ~/.gnupg
    .protect_cloud_config(true)   // Deny ~/.aws, ~/.azure, ...
    .allow_gpu(false)             // Deny GPU access
    .build();

let config = SandboxConfig::builder().security(security).build();
```

`SecurityOverrides` carries a partial set of the same toggles, for layering a config file and command-line flags onto a preset without restating every switch.

## IPC

Registered commands appear inside the sandbox as ordinary executables on `PATH`. The command value holds host-side state; each request carries typed arguments.

```rust
use heel::ipc::{IpcCommand, IpcRouter};
use heel::{Sandbox, SandboxConfig};
use serde::Deserialize;

struct WebSearch {
    client: SearchClient,
}

#[derive(Deserialize)]
struct WebSearchArgs {
    query: String,
}

impl IpcCommand for WebSearch {
    const NAME: &'static str = "web_search";
    // Lets sandboxed code write `web_search "rust"` for `--query rust`.
    const POSITIONAL_ARGS: &'static [&'static str] = &["query"];

    type Args = WebSearchArgs;
    type Response = Vec<String>;

    async fn handle(&self, args: WebSearchArgs) -> Vec<String> {
        self.client.search(&args.query).await
    }
}

let router = IpcRouter::new().register(WebSearch { client });
let config = SandboxConfig::builder().ipc(router).build();
let sandbox = Sandbox::with_config(config).await?;
```

Transport is a Unix domain socket with owner-only permissions, in a private directory outside the working directory so that sandboxed code cannot unlink the endpoint it depends on. IPC opens no network port.

## Python Support

```rust
use heel::{PythonConfig, Sandbox, SandboxConfig, VenvConfig, VenvManager};

let venv = VenvConfig::builder()
    .path("/tmp/my-venv")
    .packages(["requests", "numpy"])
    .build();

// Created on the host: installing packages needs the network the sandbox denies.
VenvManager::create(&venv).await?;

let config = SandboxConfig::builder()
    .python(PythonConfig::builder().venv(venv).build())
    .build();

let sandbox = Sandbox::with_config(config).await?;
let output = sandbox.run_python("import sys; print(sys.version)").await?;
```

The environment is read-and-execute only inside the sandbox unless `allow_pip_install(true)` is set, so sandboxed code cannot mutate an environment that outlives it.

## CLI

```bash
# Run a command in the sandbox
heel run echo hello

# Interactive shell
heel shell

# Python script with a virtual environment
heel python script.py

# Tighten or loosen isolation
heel run --isolation strict cat /etc/hosts
heel run --network allow-list --allow-domain '*.crates.io' cargo fetch

# Record this run's network decisions as JSON lines. It needs a policy that runs
# the proxy: under the default deny-all the kernel refuses connections and there
# is nothing to record.
heel run --network allow-list --allow-domain example.com \
  --audit-log ./run.jsonl curl https://example.com

# A directory that is written and then executed: both grants, deliberately
heel run --writable ./target --executable ./target cargo test

# Protections take an optional value, so a config file can be overridden either way
heel run --protect-credentials=false ssh-add -l
```

Configuration can also come from a TOML file passed with `--config`; command-line arguments take precedence, and list settings concatenate.

## License

MIT OR Apache-2.0
