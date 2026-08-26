# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**heel** is a cross-platform Rust library for running untrusted code in secure sandboxes with native OS-level isolation.

Platform support:
- **macOS**: `sandbox-exec` with SBPL profiles (fully implemented)
- **Linux**: Landlock (ABI v4, kernel 6.7+) + Seccomp (implemented, requires kernel support)
- **Windows**: AppContainer (declared but not yet implemented)

## Workspace Structure

```
.
├── Cargo.toml       # Library package and `heel` CLI binary
├── src/bin/heel/    # CLI sources: `heel run`, `heel shell`, `heel python`, `heel ipc`
├── src/ipc/         # IPC: command trait, router, transport, command shims
├── src/platform/    # Per-platform backends behind the `Backend` trait
├── templates/       # Askama templates: the SBPL profile and the command shims
├── tests/           # Integration tests that assert the sandbox denies things
└── nodejs/          # Node.js bindings via NAPI-RS (heel-nodejs)
```

## Build Commands

```bash
cargo build                                  # Debug build (all workspace members)
cargo build --release                        # Release build
cargo test                                   # Run all tests
cargo test -p heel                          # Run tests for main library only
cargo test test_name                         # Run specific test by name
cargo run --example basic                    # Run an example
cargo run --example python_venv              # Python venv example
cargo run --example ipc_commands             # Host commands callable from the sandbox
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
- **Linux**: Requires kernel 6.7+ with Landlock ABI v4. CI uses ubuntu-24.04

`tests/isolation.rs` and `tests/ipc.rs` run real programs in real sandboxes and
assert that forbidden operations fail. A change to a profile template, a
ruleset, or a syscall filter is not verified until those pass: asserting on
generated profile text only proves the generator wrote what it was told to.

## Architecture

### Core Components

- **Sandbox<N: NetworkPolicy>** (`src/sandbox.rs`) - Main entry point, generic over network policy. Manages lifecycle: creates backend, starts proxy and IPC server, tracks child processes, cleans up on drop. `N::DENIES_ALL` decides at compile time whether a proxy runs at all.

- **Command** (`src/command.rs`) - Builder for executing programs in sandbox. Automatically sets HTTP_PROXY/HTTPS_PROXY to route through sandbox proxy.

- **NetworkProxy** (`src/network/proxy.rs`) - Local HTTP proxy using hyper with executor-agnostic async. All sandboxed network traffic routes through this for policy enforcement.

- **NetworkPolicy** (`src/network/policy.rs`) - Trait for async network filtering. Implementations: `DenyAll` (default), `AllowAll`, `AllowList` (domain whitelist with wildcards), `CustomPolicy<F>`.

- **Backend trait** (`src/platform/mod.rs`) - Platform-specific sandbox execution, taking a `SpawnRequest`. macOS uses `sandbox-exec` + SBPL templates (`templates/`); Linux uses Landlock + Seccomp applied via `pre_exec`. Resource limits are installed with `setrlimit` in `pre_exec` on both.

- **SecurityConfig** (`src/security.rs`) - Fine-grained protection toggles (protect_user_home, protect_credentials, protect_cloud_config, etc.) and hardware access flags (allow_gpu, allow_npu, allow_hardware).

- **IpcRouter** (`src/ipc/`) - Type-safe IPC over a Unix domain socket with MessagePack. Commands implement `IpcCommand`, whose name and argument shape are associated constants and whose per-request data is a separate `Args` type. Sandboxed processes see each command as a shim on `PATH` that execs `heel ipc`; all argument parsing happens there, in Rust.

### Key Patterns

- **Generic network policy**: `Sandbox<N: NetworkPolicy>` enables type-safe policy composition
- **Builder pattern**: All configuration via builders (SandboxConfigBuilder, SecurityConfigBuilder, etc.)
- **Compile-time templates**: SBPL profiles use Askama templates in `templates/`
- **Executor agnostic**: Works with any `executor-core` compatible runtime (smol default, tokio via feature)
- **Drop-based cleanup**: Sandbox drop kills child processes and removes working directory
- **pre_exec sandbox application**: On Linux, Landlock and Seccomp are applied in a `pre_exec` hook after fork, before exec. Everything that hook needs is built beforehand, so the post-fork path only issues syscalls
- **SBPL rule order**: macOS resolves an operation with the LAST matching rule. `templates/sandbox.txt` is laid out in three passes — baseline, protections, then user-configured paths — so an explicit allow always beats a default protection. Moving a rule between passes changes what the sandbox enforces
- **No exec where the sandbox can write**: the working directory, configured writable paths and shared temp are all denied execute, so sandboxed code cannot write a payload and run it

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
