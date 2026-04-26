# Windows sandbox validation guide

This document describes how to validate Heel's Windows AppContainer backend on
a real Windows machine. AppContainer behavior must be tested on Windows and
should not be inferred from macOS or Linux runs.

Example repository and validation roots:

- Source checkout: `G:\MyCodeRepo\Heel`
- Recommended validation root: a local NTFS directory, such as
  `$env:TEMP\heel-win-validation`

Validation principles:

- Validate security boundaries before usability. A command that runs
  successfully is not enough.
- AppContainer file access depends on Windows ACLs. Use local NTFS directories
  for read/write isolation checks. Do not use a shared `G:` mount as the
  sandbox working directory or as a protected isolation root.
- Administrator privileges should not be required. If a step only passes as an
  administrator, treat that as a design issue unless the capability explicitly
  requires elevation.
- For each negative case, check both the command failure and the protected
  file state. Protected files must not be created, modified, or leaked in
  output.
- If the Windows backend is still in a fail-closed phase, execution tests
  should return a clear unsupported error. After real execution lands, use the
  full acceptance matrix below.

## Computer Use conventions

Windows controls in cloud desktops may not expose the same accessibility tree
as native macOS applications. Prefer a PowerShell-driven, non-interactive flow
for stable validation.

Recommended workflow:

- Keep the cloud computer window size and position stable during validation.
  Avoid frequent resizing, moving, or display-scale changes.
- Use PowerShell for test execution. Use File Explorer only to locate the
  repository, open folders, or confirm that files exist.
- Put multi-step validation into idempotent PowerShell scripts and run them in
  one pass instead of typing long command sequences interactively.
- Print clear step markers, such as `=== STEP: network deny-all ===`, and end
  with `PASS` or a specific error.
- Use `Start-Transcript` or an explicit log file so results can be reviewed
  later without relying on terminal screenshots.
- Create and delete test files only under a dedicated directory such as
  `$env:TEMP\heel-win-validation`. Do not recursively delete repository
  directories, user directories, or the `G:` root. Do not apply bulk ACL
  changes outside the validation root.
- For ACL and AppContainer isolation checks, place the test roots on local
  NTFS, such as `$env:TEMP\heel-win-validation`. A `G:` host mount is useful
  for reading source and building, but it is not a reliable isolation root.
- Run commands with non-interactive flags, for example
  `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ...`, so profiles,
  execution policy prompts, and dialogs do not affect results.
- If a user manually interacts with the cloud desktop window, inspect the
  current screen state again before clicking or typing.
- If keyboard shortcuts are unreliable, click the target input area first and
  then type plain text. Pointer clicks and normal text input have been observed
  to work, while some shortcuts may be intercepted by the host or cloud client.

Prefer the scripted validation entrypoint in this repository:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File G:\MyCodeRepo\Heel\scripts\windows-sandbox-validation.ps1 -Mode Auto
```

The script resolves the repository root from its own path, creates a unique
validation directory under `$env:TEMP\heel-win-validation\run-*`, and prints
the transcript log and Markdown report paths. Use `-Mode Full` to force the
complete AppContainer acceptance path. Use `-Mode FailClosed` to validate the
older unsupported contract.

The Windows support branch is expected to use the complete AppContainer
acceptance path: execution, strict filesystem boundaries, `DenyAll` network,
and background process tree cleanup should pass. `FailClosed` is only for
manual regression checks of the previous contract.

Suggested PowerShell wrapper:

```powershell
$ErrorActionPreference = "Stop"
$RunId = Get-Date -Format "yyyyMMdd-HHmmss"
$Root = Join-Path $env:TEMP "heel-win-validation"
$Log = Join-Path $Root "validation-$RunId.log"
New-Item -ItemType Directory -Force $Root | Out-Null

Start-Transcript -Path $Log -Force
try {
    Write-Host "=== STEP: environment ==="
    Set-Location "G:\MyCodeRepo\Heel"
    git status --short
    rustc --version
    cargo --version

    Write-Host "=== STEP: validation commands ==="
    # Run the checks from this document here.

    Write-Host "PASS"
} finally {
    Stop-Transcript
    Write-Host "log: $Log"
}
```

## 1. Environment setup

Run this from Windows PowerShell:

```powershell
$ErrorActionPreference = "Stop"

$Repo = "G:\MyCodeRepo\Heel"
$Root = Join-Path $env:TEMP "heel-win-validation"
$Sandbox = Join-Path $Root "sandbox"
$Readable = Join-Path $Root "readable"
$Writable = Join-Path $Root "writable"
$Outside = Join-Path $Root "outside"

Set-Location $Repo
New-Item -ItemType Directory -Force $Root, $Sandbox, $Readable, $Writable, $Outside | Out-Null

"readable-secret" | Set-Content -Encoding UTF8 (Join-Path $Readable "readable.txt")
"outside-secret" | Set-Content -Encoding UTF8 (Join-Path $Outside "secret.txt")
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Outside "blocked-write.txt")
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Readable "blocked-write.txt")
```

Record the baseline environment:

```powershell
git status --short
rustc --version
cargo --version
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber
```

Pass criteria:

- `$Repo` is accessible.
- The Rust toolchain is available.
- The repository state is recorded.

## 2. Build and unit tests

```powershell
cargo test -p heel --lib
cargo test -p heel --bins
cargo build -p heel --bin heel

$Heel = Join-Path $Repo "target\debug\heel.exe"
& $Heel --version
```

Pass criteria:

- `cargo test -p heel --lib` and `cargo test -p heel --bins` pass, or the only
  assertion changes match the current Windows fail-closed contract.
- `target\debug\heel.exe` builds successfully.
- `heel --version` prints a version.

## 3. Fail-closed contract

When `src/platform/windows/process.rs` still returns `UnsupportedPlatform` and
`platform_capabilities().execution_supported == false`, commands must not
fall back to unsandboxed host execution.

```powershell
& $Heel run --working-dir $Sandbox cmd.exe /C "echo should-not-run"
if ($LASTEXITCODE -eq 0) {
    throw "Windows backend unexpectedly executed a command while capability contract is fail-closed."
}
```

Pass criteria:

- The command fails.
- The error clearly points to an unsupported platform or unsupported Windows
  AppContainer capability.
- `should-not-run` must not appear as the output of a successful sandboxed
  command.

After Windows execution support lands, stop treating this section as an
expected failure path and run the full acceptance matrix below.

## 4. Execution smoke test

Prerequisite: `platform_capabilities().execution_supported == true`.

```powershell
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Sandbox "hello.txt")

& $Heel run --working-dir $Sandbox cmd.exe /C "cd && echo heel-ok>hello.txt && type hello.txt"
if ($LASTEXITCODE -ne 0) {
    throw "sandbox command failed"
}

Get-Content (Join-Path $Sandbox "hello.txt")
```

Pass criteria:

- Output contains `heel-ok`.
- `hello.txt` is created only inside `$Sandbox`.
- The current directory is `$Sandbox`, not the repository directory or the
  PowerShell launch directory.

## 5. Filesystem isolation matrix

### 5.1 Default strict mode denies outside reads and writes

```powershell
& $Heel run --working-dir $Sandbox cmd.exe /C "type `"$Outside\secret.txt`""
if ($LASTEXITCODE -eq 0) {
    throw "sandbox read outside root unexpectedly succeeded"
}

& $Heel run --working-dir $Sandbox cmd.exe /C "echo blocked>`"$Outside\blocked-write.txt`""
if ($LASTEXITCODE -eq 0) {
    throw "sandbox write outside root unexpectedly succeeded"
}

if (Test-Path (Join-Path $Outside "blocked-write.txt")) {
    throw "outside write left a file behind"
}
```

Pass criteria:

- Outside read fails.
- Outside write fails.
- `$Outside\blocked-write.txt` does not exist.

### 5.2 `--readable` permits reads but not writes

```powershell
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Readable "blocked-write.txt")

& $Heel run --working-dir $Sandbox --readable $Readable cmd.exe /C "type `"$Readable\readable.txt`""
if ($LASTEXITCODE -ne 0) {
    throw "readable root could not be read"
}

& $Heel run --working-dir $Sandbox --readable $Readable cmd.exe /C "echo blocked>`"$Readable\blocked-write.txt`""
if ($LASTEXITCODE -eq 0) {
    throw "readable root unexpectedly accepted writes"
}

if (Test-Path (Join-Path $Readable "blocked-write.txt")) {
    throw "readable root write left a file behind"
}
```

Pass criteria:

- `$Readable\readable.txt` can be read.
- `$Readable\blocked-write.txt` cannot be created.

### 5.3 `--writable` permits reads and writes for the selected directory

```powershell
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Writable "created.txt")

& $Heel run --working-dir $Sandbox --writable $Writable cmd.exe /C "echo writable-ok>`"$Writable\created.txt`" && type `"$Writable\created.txt`""
if ($LASTEXITCODE -ne 0) {
    throw "writable root could not be written"
}

Get-Content (Join-Path $Writable "created.txt")
```

Pass criteria:

- Output contains `writable-ok`.
- The file appears only under `$Writable`.
- `$Outside` has no new files.

## 6. Network policy

The first Windows AppContainer release only accepts `DenyAll`. `AllowAll` and
`AllowList` must fail closed until there is a strong Windows network isolation
design.

### 6.1 Default network access is denied

```powershell
& $Heel run --working-dir $Sandbox powershell.exe -NoProfile -Command "try { Invoke-WebRequest https://example.com -UseBasicParsing -TimeoutSec 5 | Out-Null; exit 10 } catch { exit 0 }"
if ($LASTEXITCODE -ne 0) {
    throw "default DenyAll network policy was bypassed"
}
```

Pass criteria: the in-sandbox request fails and the outer command exits with 0.

### 6.2 Non-`DenyAll` policies are rejected explicitly

```powershell
& $Heel run --working-dir $Sandbox --network allow cmd.exe /C "echo should-not-run"
if ($LASTEXITCODE -eq 0) {
    throw "--network allow unexpectedly ran on Windows"
}

& $Heel run --working-dir $Sandbox --network allow-list --allow-domain example.com cmd.exe /C "echo should-not-run"
if ($LASTEXITCODE -eq 0) {
    throw "--network allow-list unexpectedly ran on Windows"
}
```

Pass criteria:

- Both commands fail.
- The error includes Windows network policy semantics, such as
  `windows-appcontainer-network`.
- `HTTP_PROXY` or `HTTPS_PROXY` injection must not turn an allowlist into a
  security boundary.

## 7. Python scenarios

First validate scripts that do not depend on third-party packages. Package
installation and virtual environment preparation are host-side setup steps and
must not grant extra network capability inside the sandbox.

```powershell
$Python = (Get-ChildItem (Join-Path $env:LOCALAPPDATA "Programs\Python") -Recurse -Filter python.exe | Select-Object -First 1).FullName
if ([string]::IsNullOrWhiteSpace($Python)) {
    throw "real python.exe was not found; Microsoft Store aliases are not valid for this validation"
}
$Probe = Join-Path $Sandbox "probe.py"

@"
from pathlib import Path
root = Path.cwd()
(root / "python-ok.txt").write_text("python-ok", encoding="utf-8")
print((root / "python-ok.txt").read_text(encoding="utf-8"))
"@ | Set-Content -Encoding UTF8 $Probe

& $Heel python --working-dir $Sandbox --python $Python $Probe
if ($LASTEXITCODE -ne 0) {
    throw "heel python smoke test failed"
}

Get-Content (Join-Path $Sandbox "python-ok.txt")
```

Pass criteria:

- Output contains `python-ok`.
- Writes happen only inside `$Sandbox`.
- Reads and writes to unauthorized external paths fail from inside Python, and
  protected file contents do not appear in output.
- Python socket and HTTP network access fail. Host proxies and environment
  variables must not bypass `DenyAll`.
- The Windows backend treats the Python interpreter and runtime root as
  runtime or executable roots. It must not implement this by broadening access
  to the user directory.
- On Windows, `heel python --venv <path>` without `--python` should skip
  Microsoft Store `WindowsApps` aliases, resolve a real Python installation,
  create the virtual environment, import packages from venv `site-packages`,
  and keep external filesystem and network denial intact.

Known behavior: CPython 3.14 may print a warning like
`Failed to find real location of ...\python.exe` to stderr inside an
AppContainer. Current testing indicates this comes from CPython Windows path
initialization when `GetFinalPathNameByHandleW(..., VOLUME_NAME_DOS)` returns
`ERROR_ACCESS_DENIED`. The same process can still execute scripts and resolve
`sys.executable` and `sys.prefix`. Treat exit code and isolation assertions as
the validation source of truth, not this CPython realpath warning alone.

## 8. Environment variables and current directory

```powershell
& $Heel run --working-dir $Sandbox --env HEEL_VALIDATION=ok cmd.exe /C "echo %CD% && echo %HEEL_VALIDATION%"
if ($LASTEXITCODE -ne 0) {
    throw "env/current-dir test failed"
}
```

Pass criteria:

- The first output line points to `$Sandbox`.
- Output contains `ok`.
- Sensitive environment variables that were not passed explicitly must not be
  required for the test to pass.

## 9. Process tree cleanup

Prerequisite: the Windows backend declares
`background_process_tree_cleanup == true`.

```powershell
$Loop = Join-Path $Sandbox "loop.ps1"
$Marker = Join-Path $Sandbox "loop-marker.txt"
Remove-Item -Force -ErrorAction SilentlyContinue $Marker

@"
while (`$true) {
    Add-Content -Encoding UTF8 "$Marker" "tick"
    Start-Sleep -Seconds 1
}
"@ | Set-Content -Encoding UTF8 $Loop

& $Heel run --working-dir $Sandbox powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File', '$Loop'; Start-Sleep -Seconds 2"
if ($LASTEXITCODE -ne 0) {
    throw "background process setup command failed"
}

$Before = if (Test-Path $Marker) { (Get-Content $Marker).Count } else { 0 }
Start-Sleep -Seconds 4
$After = if (Test-Path $Marker) { (Get-Content $Marker).Count } else { 0 }

if ($After -gt $Before) {
    throw "background child process survived sandbox cleanup"
}
```

Pass criteria:

- The background child stops writing the marker after the parent command exits.
- No sandbox child process is left running.
- Job Object assignment failure causes the command to fail. It must not
  degrade into foreground-process-only cleanup.

## 10. Fail-closed checks for unsupported capabilities

Until the corresponding capabilities are designed and implemented, these cases
must be rejected explicitly:

```powershell
& $Heel run --working-dir $Sandbox --permissive cmd.exe /C "echo should-not-run"
if ($LASTEXITCODE -eq 0) {
    throw "--permissive unexpectedly ran on Windows"
}
```

Pass criteria:

- `--permissive` fails, and the error points to unsupported non-strict or
  globally writable filesystem policy.
- IPC-related unit tests still prove that the Windows backend rejects IPC.
- Any unsupported case fails before launching an unsandboxed child process.

Recommended unit tests:

```powershell
cargo test -p heel windows_policy_rejects_non_deny_all_network
cargo test -p heel windows_policy_rejects_non_strict_filesystem
cargo test -p heel windows_policy_rejects_globally_writable_filesystem
cargo test -p heel windows_policy_rejects_ipc
```

## 11. Validation record template

After each real Windows validation run, record the following information. A
suggested location is `docs/windows-validation-runs/YYYY-MM-DD.md`.

```markdown
# Windows Heel Validation - YYYY-MM-DD

- Repo commit:
- Windows version:
- Rust version:
- Heel binary:
- Validation root:
- Execution capability:
- Filesystem strict:
- Network deny-all:
- Process tree cleanup:

## Results

| Area | Result | Evidence |
| --- | --- | --- |
| Build and unit tests | PASS/FAIL | command output summary |
| Current fail-closed or execution smoke | PASS/FAIL | command output summary |
| Default outside read/write denied | PASS/FAIL | command output summary |
| Readable root read-only | PASS/FAIL | command output summary |
| Writable root read/write | PASS/FAIL | command output summary |
| Network DenyAll | PASS/FAIL | command output summary |
| Non-DenyAll rejected | PASS/FAIL | command output summary |
| Python smoke | PASS/FAIL | command output summary |
| Python venv smoke | PASS/FAIL | command output summary |
| Env and cwd | PASS/FAIL | command output summary |
| Process tree cleanup | PASS/FAIL/NA | command output summary |

## Notes

- Unexpected behavior:
- Follow-up fixes:
```

## 12. Release readiness criteria

Windows support should not be released only because
`heel run cmd.exe /C echo ok` succeeds. At minimum:

- Build and Windows-related unit tests pass.
- Default strict filesystem mode only permits access to the working directory.
- `--readable`, `--writable`, `--executable`, and runtime grants match the
  documented semantics.
- Default `DenyAll` network cannot be bypassed.
- Non-`DenyAll` network policies fail closed until strong network isolation is
  implemented.
- IPC fails closed until a Windows security design is complete.
- Background process trees are cleaned up by Job Objects, or the capability
  flag remains false and product integrations do not rely on it.
- Every unsupported case fails before launching an unsandboxed child process.
- Validation records include commit, Windows version, command summaries, and
  failure evidence.
