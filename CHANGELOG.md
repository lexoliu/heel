# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/lexoliu/leash/compare/leash-v0.0.1...leash-v0.1.0) - 2026-03-25

### Added

- enhance IPC command handling and add TTY write access configuration
- enhance IPC wrapper generation and argument handling

### Fixed

- *(ci)* handle unsupported platforms and fix windows build
- *(ci)* update ubuntu runner to 24.04 and improve debug logging
- resolve clippy warnings and unused dependency checks

### Other

- Use smol in async policy tests
- Integrate IPC into leash CLI
- Update workspace metadata for integrated IPC
- Add release asset publishing workflow
- Support TCP IPC and refine IPC wrappers
- Refactor isolation tiers: implement Strict, Default, Permissive presets
- *(ipc)* use stdin wrapper for IPC and update sandbox logic
- add typos config to ignore ANE acronym
- modernize workflows and add system check
- Simplify seccomp syscall blocking
- Add context to Linux pre_exec errors
- Add README and expand documentation for CLAUDE.md
- Log Linux pre_exec failures
- Handle DenyAll network without Landlock net
- Fix Landlock non-exhaustive match
- Improve Linux sandbox error propagation
- Fix Linux sandbox pre_exec
- Fix Landlock strict paths iteration
- Fix Landlock strict path allowlist type
- Tighten strict filesystem mode and add macOS CI
- Build Landlock/Seccomp inside pre_exec to avoid fd inheritance issues
- Test raw execution without any sandbox
- Add detailed Landlock error output
- Test with empty pre_exec hook
- Add Node.js binding with NAPI-RS
- Test with Landlock only (no Seccomp)
- Temporarily disable sandbox to test basic spawn
- Add debug output to pre_exec to trace sandbox application
- Add execute permission to system binary paths in Landlock rules
- Fix seccomp always-block rules using MaskedEq(0) trick
- Fix seccomp rule construction for "always block" syscalls
- Fix seccomp filter: swap mismatch/match actions for default-allow policy
- Gate pty module for macOS only
- Fix GitHub Actions workflow: use correct rust-toolchain action
- Merge Linux sandbox implementation (Landlock + Seccomp)
- Implement Linux sandbox with Landlock + Seccomp
- Add type-safe IPC for sandboxed process communication
- Update CLAUDE.md
- Rename to leash
- Rewrite NetworkProxy with hyper and executor-core
- Restrict network to proxy port only and add Homebrew access
- Integrate NetworkProxy and always route traffic through proxy
- Update words list
- Add GPU, NPU, and hardware access configuration
- Add automatic cleanup on Sandbox drop
- Add WorkingDir with random name generation and rename error types
- Add composable SecurityConfig for configurable sandbox protections
- Improve sandbox security with deny-list approach
- Replace writeln! macros with askama compile-time templates
- Add network proxy for async callback-based filtering
- Add Python venv management and integration
- initial commit
