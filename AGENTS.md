# AGENTS.md

This file provides guidance to Codex and other coding agents when working with code in this repository.

## Project Overview

**heel** is a cross-platform Rust library for running untrusted code in secure sandboxes with native OS-level isolation.

Platform support:
- **macOS**: `sandbox-exec` with SBPL profiles (fully implemented)
- **Linux**: Landlock (ABI v4, kernel 6.7+) + Seccomp (implemented, requires kernel support)
- **Windows**: AppContainer backend under active implementation and validation. Real AppContainer behavior must be built and tested on Windows, not inferred from macOS cross-checks.

## Workspace Structure

```
.
├── Cargo.toml      # Main library package and `heel` CLI binary
├── src/bin/heel/  # CLI sources: `heel run`, `heel shell`, `heel python`, `heel ipc`
├── ipc/            # IPC support library used by the `heel ipc` subcommand
└── nodejs/         # Node.js bindings via NAPI-RS (heel-nodejs)
```

## Build Commands

```bash
cargo build                                  # Debug build (all workspace members)
cargo build --release                        # Release build
cargo test                                   # Run all tests
cargo test -p heel                          # Run tests for main library only
cargo test test_name                         # Run specific test by name
cargo run --example basic                    # Run an example
cargo run --example python_sandbox           # Python venv example
RUST_LOG=debug cargo run --example basic     # With debug logging
```

### CLI usage

```bash
cargo run --bin heel -- run echo hello      # Run command in sandbox
cargo run --bin heel -- shell               # Interactive shell in sandbox
cargo run --bin heel -- python script.py    # Run Python in sandbox with venv
```

### Platform-specific testing

- **macOS**: Works out of the box, tests run directly
- **Linux**: Requires kernel 6.7+ with Landlock ABI v4. CI uses ubuntu-24.04. Run `cargo run --example debug_sandbox` to test isolation
- **Windows**: Requires a Windows Rust/MSVC toolchain and local NTFS validation roots. Use `docs/windows-sandbox-validation.md` and `scripts/windows-sandbox-validation.ps1` for AppContainer validation; do not use a shared `G:` mount as the sandbox isolation root.

## Architecture

### Core Components

- **Sandbox<N: NetworkPolicy>** (`src/sandbox.rs`) - Main entry point, generic over network policy. Manages lifecycle: creates backend, starts proxy and IPC server, tracks child processes, cleans up on drop.

- **Command** (`src/command.rs`) - Builder for executing programs in sandbox. Automatically sets HTTP_PROXY/HTTPS_PROXY to route through sandbox proxy.

- **NetworkProxy** (`src/network/proxy.rs`) - Local HTTP proxy using hyper with executor-agnostic async. All sandboxed network traffic routes through this for policy enforcement.

- **NetworkPolicy** (`src/network/policy.rs`) - Trait for async network filtering. Implementations: `DenyAll` (default), `AllowAll`, `AllowList` (domain whitelist with wildcards), `CustomPolicy<F>`.

- **Backend trait** (`src/platform/mod.rs`) - Platform-specific sandbox execution. macOS uses `sandbox-exec` + SBPL templates (`templates/`); Linux uses Landlock + Seccomp applied via `pre_exec`.

- **SecurityConfig** (`src/security.rs`) - Fine-grained protection toggles (protect_user_home, protect_credentials, protect_cloud_config, etc.) and hardware access flags (allow_gpu, allow_npu, allow_hardware).

- **IpcRouter** (`src/ipc/`) - Type-safe IPC over Unix domain sockets with MessagePack. Sandboxed processes can call host-registered commands via `IpcCommand` trait.

### Key Patterns

- **Generic network policy**: `Sandbox<N: NetworkPolicy>` enables type-safe policy composition
- **Builder pattern**: All configuration via builders (SandboxConfigBuilder, SecurityConfigBuilder, etc.)
- **Compile-time templates**: SBPL profiles use Askama templates in `templates/`
- **Executor agnostic**: Works with any `executor-core` compatible runtime (smol default, tokio via feature)
- **Drop-based cleanup**: Sandbox drop kills child processes and removes working directory
- **pre_exec sandbox application**: On Linux, Landlock and Seccomp are applied in `pre_exec` hook after fork, before exec

## Code Standards

<important>
- Follow fast fail principle: if an unexpected case is encountered, crash early with a clear error message rather than fallback.
- Utilize rust's type system to enforce invariants at compile time rather than runtime checks.
- Use struct, trait and generic abstractions rather than enum and type-erasure when possible.
- No embedded string literal for text assets.
- Do not write duplicated code. If you find yourself copying and pasting code, consider refactoring it into a shared function or module.
- You are not allowed to revert or restore files or hide problems. If you find a bug, fix it properly rather than working around it.
- Do not leave legacy code for fallback. If a feature is deprecated, remove all related code.
- No simplify, no stub, no fallback, no patch.
- Really important: Import third-party crates instead of writing your own implementation. Less code is better.
- Async first and runtime agnostic.
- Be respectful to lints, do not disable lints without strong reason.
</important>
