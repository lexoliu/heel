# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.1](https://github.com/lexoliu/heel/compare/heel-v0.7.0...heel-v0.7.1) - 2026-10-29

### Fixed

- *(windows)* run a named identity's deny-all sandboxes under a profile that is never loopback-exempt

## [0.7.0](https://github.com/lexoliu/heel/compare/heel-v0.6.0...heel-v0.7.0) - 2026-10-29

### Added

- [**breaking**] report the broker's host preconditions as typed errors

## [0.6.0](https://github.com/lexoliu/heel/compare/heel-v0.5.1...heel-v0.6.0) - 2026-10-29

### Added

- deny credential reads and persistence writes on Linux through a seccomp broker

### Fixed

- *(test)* number O_TMPFILE per architecture and allow Linux interface names in typos
- *(windows)* honour filesystem_strict and refuse writable_file_system

### Other

- Merge remote-tracking branch 'origin/dev' into feat/106-credential-read-policy
- skip the build and audit jobs on a version-only diff

## [0.5.1](https://github.com/lexoliu/heel/compare/heel-v0.5.0...heel-v0.5.1) - 2026-10-22

### Added

- *(windows)* stable AppContainer identity with persistent grants ([#91](https://github.com/lexoliu/heel/pull/91))

### Fixed

- *(windows)* serialize concurrent opens of one named profile across processes
- *(windows)* keep auto-inheritance on this-object ACL writes
- *(windows)* keep AppContainer temp paths in profile ([#89](https://github.com/lexoliu/heel/pull/89))
- *(windows)* respect AppContainer ACE trustees ([#90](https://github.com/lexoliu/heel/pull/90))
- *(windows)* serialize ACL updates ([#69](https://github.com/lexoliu/heel/pull/69))
- *(windows)* name the PATH and PATHEXT an unresolvable program was searched with
- *(windows)* honor env_passthroughs and match PATH without case

### Other

- *(windows)* share the inherited-ACE test helper ([#91](https://github.com/lexoliu/heel/pull/91))
- *(windows)* make persistent-grant ACL fixtures auto-inherited ([#91](https://github.com/lexoliu/heel/pull/91))
- compare macOS profile paths canonically ([#91](https://github.com/lexoliu/heel/pull/91))
- *(windows)* build the auto-inherited directory the ACL test needs ([#95](https://github.com/lexoliu/heel/pull/95))
- Merge pull request #94 from lexoliu/fix/89-container-temp
- let typos skip SDDL entries
- *(windows)* share one environment-name matcher across launch and PATH selection

## [0.5.0](https://github.com/lexoliu/heel/compare/heel-v0.4.2...heel-v0.5.0) - 2026-10-18

### Fixed

- *(windows)* decide a grant by the container's effective rights, not the path
- *(windows)* skip system directories and remove grant entries on drop

### Other

- [**breaking**] update the IpcCommand example for fallible handlers ([#80](https://github.com/lexoliu/heel/pull/80))
- let commands take argv verbatim and make handlers fallible ([#78](https://github.com/lexoliu/heel/pull/78))
- *(windows)* strip the Program Files child's inheritance before writing its probe
- *(windows)* prove readability by reading a file, not with dir
- *(windows)* list ACLs with icacls in failure messages

## [0.4.2](https://github.com/lexoliu/heel/compare/heel-v0.4.1...heel-v0.4.2) - 2026-10-16

### Other

- End heel ipc quietly when its reader closes the pipe

## [0.4.1](https://github.com/lexoliu/heel/compare/heel-v0.4.0...heel-v0.4.1) - 2026-10-12

### Fixed

- heel no longer requires exactly `http` 1.3.1, which forced every consumer's lockfile down to that version.
- Release assets are optimized builds, and Windows ARM64 (`aarch64-pc-windows-msvc`) now has one.

## [0.4.0](https://github.com/lexoliu/heel/compare/heel-v0.3.1...heel-v0.4.0) - 2026-10-12

### Breaking

- `SandboxConfigBuilder` has a second type parameter for its IPC route. `ipc()` returns the builder in the configured state, so `builder = builder.ipc(router)` no longer compiles; bind the result to a new variable instead. Configuring both a local router and an external endpoint is a compile error.
- `DEFAULT_SANDBOX_PATH` exists only on Unix. Use `default_sandbox_path()`, which also covers Windows.

### Added

- `SandboxConfigBuilder::external_ipc` and `TcpIpcEndpoint`: the sandbox's IPC commands reach one TCP endpoint on the host. heel relays to it from outside the sandbox, so the sandboxed process gets no TCP access.
- `IpcRequest`, `IpcResponse` and `default_sandbox_path` are public.

### Fixed

- Windows 11 ARM64: sandboxes without network access failed to launch with `ERROR_INVALID_PARAMETER`.
- Windows: IPC commands were written as shell scripts, which native Windows programs cannot run. They are now `.exe` entrypoints found through the sandbox `PATH`.
- Windows: a child joins its job object, with the memory limit and priority already applied, at creation rather than after it has started.
- Windows: `StdioConfig::Inherit` passes the parent's standard handles to the child.
- Windows: reading an access control list no longer fails when the descriptor changes during the read.
- Sandbox creation no longer blocks async executor threads.
- The IPC server is stopped once on drop instead of twice.

### Removed

- The `rappct` dependency. The Windows backend calls Win32 directly.

## [0.3.1](https://github.com/lexoliu/heel/compare/heel-v0.3.0...heel-v0.3.1) - 2026-10-11

### Fixed

- retain IPC commands with explicit PATH
- *(windows)* let one ACL write cover a granted tree ([#46](https://github.com/lexoliu/heel/pull/46))
- *(windows)* reach the pipe list through a WRITE_DAC client
- *(windows)* grant the pipe through its object name
- *(windows)* wrap the descriptor out-parameter in Some
- *(windows)* open the IPC pipe to the container
- *(windows)* let a write grant rename and remove what it wrote
- *(windows)* open the null device to the container so children can spawn ([#43](https://github.com/lexoliu/heel/pull/43))
- *(windows)* grant ACLs through verbatim paths past MAX_PATH ([#42](https://github.com/lexoliu/heel/pull/42))
- *(windows)* open the existing contents of granted directories to the container ([#41](https://github.com/lexoliu/heel/pull/41))
- *(network)* write audit records before the connection proceeds ([#39](https://github.com/lexoliu/heel/pull/39))
- *(windows)* make Sandbox/Child Send+Sync again ([#36](https://github.com/lexoliu/heel/pull/36))

### Other

- Make a nice level relative to the host
- Add scheduling priority for sandboxed processes
- run the workflow once per pull request commit ([#47](https://github.com/lexoliu/heel/pull/47))
- *(windows)* probe each filesystem operation from inside the container
- *(windows)* dump the container view of the grant on denial
- *(windows)* name the operation a write grant denies
- track crate-ci/typos by its v1 tag ([#40](https://github.com/lexoliu/heel/pull/40))
- run tests with cargo nextest ([#37](https://github.com/lexoliu/heel/pull/37))

## [0.3.0](https://github.com/lexoliu/heel/compare/heel-v0.2.0...heel-v0.3.0) - 2026-09-13

### Other

- Gate fix + Windows which fix ([#32](https://github.com/lexoliu/heel/pull/32))
- Release heel 0.3.0 ([#27](https://github.com/lexoliu/heel/pull/27))

## [0.2.0](https://github.com/lexoliu/heel/compare/heel-v0.1.1...heel-v0.2.0) - 2026-08-26

### Added

- *(workdir)* expose random_in for hosts that own their sandbox roots
- *(ipc)* [**breaking**] take command name and argument shape from the value, not the type
- *(macos)* allow sandboxed processes to bind loopback ports
- *(network)* record policy decisions in a rolling audit log

### Fixed

- *(linux)* refuse clone3 with ENOSYS so sandboxed code can use threads
- *(spelling)* correct the spellings the typos lint rejects
- *(linux)* stop granting execute where the sandbox can write
- *(ipc)* short-circuit help flags before stdin capture
- *(platform)* kill the whole sandboxed process group
- *(network)* strip hop-by-hop headers and close CONNECT tunnels

### Other

- Merge pull request #12 from lexoliu/release-0.2.0
- allow CI to be started by hand
- *(sandbox)* compile the sandbox tests only where a backend exists
- *(cli)* carry pass-through errors in tuple variants
- [**breaking**] rework the sandbox core, IPC transport and enforcement rules
- use supported intel macOS release runner

## [0.1.1](https://github.com/lexoliu/heel/compare/heel-v0.1.0...heel-v0.1.1) - 2026-03-30

### Other

- always evaluate release asset upload gate
- allow release backfill dispatch to resolve tag
- add release asset backfill dispatch
- upload release assets from release workflow

## [0.1.0](https://github.com/lexoliu/heel/compare/heel-v0.0.1...heel-v0.1.0) - 2026-03-25

### Added

- enhance IPC command handling and add TTY write access configuration
- enhance IPC wrapper generation and argument handling

### Fixed

- *(ci)* handle unsupported platforms and fix windows build
- *(ci)* update ubuntu runner to 24.04 and improve debug logging
- resolve clippy warnings and unused dependency checks

### Other

- Unify heel library and CLI crate
- Use smol in async policy tests
- Integrate IPC into heel CLI
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
- Rename to heel
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
