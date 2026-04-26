param(
    [ValidateSet("Auto", "Full", "FailClosed")]
    [string] $Mode = "Auto",
    [string] $Repo,
    [string] $ValidationBase,
    [string] $Cargo,
    [string] $Rustc,
    [string] $Git,
    [string] $Python,
    [string] $VsDevCmd,
    [switch] $SkipCargoTests,
    [switch] $SkipIgnoredCargoTests,
    [switch] $SkipPython
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$global:LASTEXITCODE = 0

if ([string]::IsNullOrWhiteSpace($Repo)) {
    $Repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
if ([string]::IsNullOrWhiteSpace($ValidationBase)) {
    $ValidationBase = Join-Path $env:TEMP "heel-win-validation"
}

$RunId = Get-Date -Format "yyyyMMdd-HHmmss"
$Root = Join-Path $ValidationBase "run-$RunId-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$Sandbox = Join-Path $Root "sandbox"
$Readable = Join-Path $Root "readable"
$Writable = Join-Path $Root "writable"
$Outside = Join-Path $Root "outside"
$Log = Join-Path $Root "validation-$RunId.log"
$Report = Join-Path $Root "validation-$RunId.md"
$Results = New-Object System.Collections.Generic.List[object]

New-Item -ItemType Directory -Force $Root, $Sandbox, $Readable, $Writable, $Outside | Out-Null

function Write-Step {
    param([string] $Name)
    Write-Host ""
    Write-Host "=== STEP: $Name ==="
}

function Add-Result {
    param([string] $Area, [string] $Result, [string] $Evidence)
    $Results.Add([pscustomobject]@{ Area = $Area; Result = $Result; Evidence = $Evidence }) | Out-Null
}

function Quote-Arg {
    param([string] $Arg)
    if ($Arg -match '\s|"') {
        return '"' + ($Arg -replace '"', '\"') + '"'
    }
    return $Arg
}

function Run-Command {
    param(
        [string] $FilePath,
        [string[]] $ArgumentList = @(),
        [int[]] $ExpectedExitCodes = @(0),
        [switch] $AllowAnyExit
    )

    $cmd = (@($FilePath) + ($ArgumentList | ForEach-Object { Quote-Arg $_ })) -join " "
    Write-Host ">>> $cmd"

    $global:LASTEXITCODE = 0
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $outputObjects = & $FilePath @ArgumentList 2>&1
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $exitCode = if ($null -eq $global:LASTEXITCODE) { 0 } else { [int] $global:LASTEXITCODE }
    $output = ($outputObjects | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) {
            $_.Exception.Message
        } else {
            $_.ToString()
        }
    }) -join [Environment]::NewLine

    if (-not [string]::IsNullOrWhiteSpace($output)) {
        Write-Host $output
    }
    Write-Host "<<< exit $exitCode"

    if (-not $AllowAnyExit -and ($ExpectedExitCodes -notcontains $exitCode)) {
        throw "Command exited with $exitCode, expected one of $($ExpectedExitCodes -join ', '): $cmd"
    }

    return [pscustomobject]@{ ExitCode = $exitCode; Output = $output; CommandLine = $cmd }
}

function Run-Heel {
    param(
        [string[]] $ArgumentList,
        [int[]] $ExpectedExitCodes = @(0),
        [switch] $AllowAnyExit
    )
    if ($AllowAnyExit) {
        return Run-Command -FilePath $script:Heel -ArgumentList $ArgumentList -AllowAnyExit
    }
    return Run-Command -FilePath $script:Heel -ArgumentList $ArgumentList -ExpectedExitCodes $ExpectedExitCodes
}

function Cmd-Path {
    param([string] $Path)
    return '"' + $Path + '"'
}

function Assert-Contains {
    param([string] $Text, [string] $Needle, [string] $Context)
    if (-not $Text.Contains($Needle)) {
        throw "$Context did not contain expected text '$Needle'. Output: $Text"
    }
}

function Assert-NotContains {
    param([string] $Text, [string] $Needle, [string] $Context)
    if ($Text.Contains($Needle)) {
        throw "$Context unexpectedly contained '$Needle'. Output: $Text"
    }
}

function Assert-Missing {
    param([string] $Path, [string] $Context)
    if (Test-Path $Path) {
        throw "$Context left unexpected path behind: $Path"
    }
}

function Resolve-Tool {
    param(
        [string] $Name,
        [string] $Override,
        [string[]] $FallbackPaths = @()
    )

    if (-not [string]::IsNullOrWhiteSpace($Override)) {
        if (-not (Test-Path $Override)) {
            throw "$Name override was not found: $Override"
        }
        return (Resolve-Path $Override).Path
    }

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    foreach ($candidate in $FallbackPaths) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }

    $searched = if ($FallbackPaths.Count -gt 0) { $FallbackPaths -join ", " } else { "no fallback paths" }
    throw "$Name was not found on PATH and no fallback matched ($searched)."
}

function Test-PythonCandidate {
    param([string] $Candidate)

    if ([string]::IsNullOrWhiteSpace($Candidate) -or -not (Test-Path $Candidate)) {
        return $false
    }
    if ($Candidate -like "*\Microsoft\WindowsApps\python*.exe") {
        return $false
    }

    $global:LASTEXITCODE = 0
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $outputObjects = & $Candidate --version 2>&1
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $exitCode = if ($null -eq $global:LASTEXITCODE) { 0 } else { [int] $global:LASTEXITCODE }
    $output = ($outputObjects | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
    return $exitCode -eq 0 -and $output -match '^Python\s+\d+\.'
}

function Resolve-Python {
    param([string] $Override)

    if (-not [string]::IsNullOrWhiteSpace($Override)) {
        if (-not (Test-PythonCandidate $Override)) {
            throw "Python override was not a runnable Python interpreter: $Override"
        }
        return (Resolve-Path $Override).Path
    }

    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($name in @("python.exe", "python3.exe")) {
        foreach ($command in @(Get-Command $name -All -ErrorAction SilentlyContinue)) {
            if ($null -ne $command.Source) {
                $candidates.Add($command.Source) | Out-Null
            }
        }
    }

    foreach ($root in @(
        (Join-Path $env:LOCALAPPDATA "Programs\Python"),
        "C:\Program Files",
        "C:\Program Files (x86)"
    )) {
        if (Test-Path $root) {
            foreach ($candidate in @(Get-ChildItem -Path $root -Recurse -Filter "python.exe" -ErrorAction SilentlyContinue)) {
                $candidates.Add($candidate.FullName) | Out-Null
            }
        }
    }

    foreach ($candidate in @($candidates | Select-Object -Unique)) {
        if (Test-PythonCandidate $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }

    throw "A real python.exe was not found. Install Python from python.org/winget or pass -Python <path>; Microsoft Store aliases are ignored."
}

function Add-ToolDirectory-ToPath {
    param([string] $ToolPath)

    $directory = Split-Path -Parent $ToolPath
    $pathParts = $env:PATH -split ';'
    if ($pathParts -notcontains $directory) {
        $env:PATH = "$directory;$env:PATH"
    }
}

function Resolve-VsDevCmd {
    param([string] $Override)

    if (-not [string]::IsNullOrWhiteSpace($Override)) {
        if (-not (Test-Path $Override)) {
            throw "VsDevCmd override was not found: $Override"
        }
        return (Resolve-Path $Override).Path
    }

    $vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $installationPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        if (-not [string]::IsNullOrWhiteSpace($installationPath)) {
            $candidate = Join-Path $installationPath "Common7\Tools\VsDevCmd.bat"
            if (Test-Path $candidate) {
                return (Resolve-Path $candidate).Path
            }
        }
    }

    $fallbacks = @(
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
    )
    foreach ($candidate in $fallbacks) {
        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }

    throw "VsDevCmd.bat was not found. Install Visual Studio Build Tools with the C++ workload before running Windows validation."
}

function Import-VsDevCmdEnvironment {
    param([string] $Path)

    $commandLine = "`"$Path`" -arch=x64 -host_arch=x64 >nul && set"
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $envLines = & cmd.exe /d /s /c $commandLine 2>&1
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    if ($LASTEXITCODE -ne 0) {
        $output = ($envLines | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                $_.Exception.Message
            } else {
                $_.ToString()
            }
        }) -join [Environment]::NewLine
        throw "VsDevCmd.bat failed with exit code $LASTEXITCODE. Output: $output"
    }

    foreach ($line in $envLines) {
        $text = $line.ToString()
        $separator = $text.IndexOf("=")
        if ($separator -le 0) {
            continue
        }

        $key = $text.Substring(0, $separator)
        $value = $text.Substring($separator + 1)
        Set-Item -Path "Env:$key" -Value $value
    }
}

function Assert-FileContains {
    param([string] $Path, [string] $Needle, [string] $Context)
    if (-not (Test-Path $Path)) {
        throw "$Context did not create expected file: $Path"
    }
    $content = Get-Content -Raw $Path
    if (-not $content.Contains($Needle)) {
        throw "$Context file did not contain '$Needle': $Path"
    }
}

function Line-Count {
    param([string] $Path)
    if (-not (Test-Path $Path)) {
        return 0
    }
    return @((Get-Content $Path)).Count
}

function Network-Probe {
    return @(
        '$ProgressPreference = ''SilentlyContinue''',
        '$ErrorActionPreference = ''Stop''',
        'try {',
        '    Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 -Uri ''http://example.com/'' -ErrorAction Stop | Out-Null',
        '    Write-Output ''HEEL_PROBE_ALLOWED:http''',
        '    exit 0',
        '} catch {',
        '    Write-Output (''HEEL_PROBE_DENIED:http:'' + $_.Exception.GetType().FullName + '':'' + $_.Exception.Message)',
        '    exit 86',
        '}'
    ) -join [Environment]::NewLine
}

function Write-Report {
    param([string] $Commit, [string] $WindowsVersion, [string] $RustVersion, [string] $HeelVersion, [string] $EffectiveMode)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# Windows Heel Validation - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("- Repo commit: $Commit") | Out-Null
    $lines.Add("- Windows version: $WindowsVersion") | Out-Null
    $lines.Add("- Rust version: $RustVersion") | Out-Null
    $lines.Add("- Heel binary: $script:Heel") | Out-Null
    $lines.Add("- Validation root: $Root") | Out-Null
    $lines.Add("- Requested mode: $Mode") | Out-Null
    $lines.Add("- Effective mode: $EffectiveMode") | Out-Null
    $lines.Add("- Transcript: $Log") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("## Results") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("| Area | Result | Evidence |") | Out-Null
    $lines.Add("| --- | --- | --- |") | Out-Null
    foreach ($entry in $Results) {
        $evidence = $entry.Evidence -replace '\|', '\|' -replace "`r?`n", "<br>"
        $lines.Add("| $($entry.Area) | $($entry.Result) | $evidence |") | Out-Null
    }
    Set-Content -Encoding UTF8 -Path $Report -Value $lines
}

Start-Transcript -Path $Log -Force | Out-Null

try {
    Write-Step "environment"
    Push-Location $Repo
    try {
        Write-Host "repo: $Repo"
        Write-Host "validation root: $Root"

        $script:Git = Resolve-Tool -Name "git" -Override $Git
        $script:Cargo = Resolve-Tool -Name "cargo" -Override $Cargo -FallbackPaths @((Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"))
        $script:Rustc = Resolve-Tool -Name "rustc" -Override $Rustc -FallbackPaths @((Join-Path $env:USERPROFILE ".cargo\bin\rustc.exe"))
        if (-not $SkipPython) {
            $script:Python = Resolve-Python -Override $Python
        }
        $script:VsDevCmd = Resolve-VsDevCmd -Override $VsDevCmd
        Import-VsDevCmdEnvironment $script:VsDevCmd
        Add-ToolDirectory-ToPath $script:Cargo
        Add-ToolDirectory-ToPath $script:Rustc

        $gitStatus = Run-Command -FilePath $script:Git -ArgumentList @("status", "--short")
        $gitCommit = Run-Command -FilePath $script:Git -ArgumentList @("rev-parse", "--short", "HEAD")
        $rustVersion = Run-Command -FilePath $script:Rustc -ArgumentList @("--version")
        $cargoVersion = Run-Command -FilePath $script:Cargo -ArgumentList @("--version")
        if (-not $SkipPython) {
            $pythonVersion = Run-Command -FilePath $script:Python -ArgumentList @("--version")
        }
        $win = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber
        $windowsVersion = "$($win.WindowsProductName) $($win.WindowsVersion) build $($win.OsBuildNumber)"
        Write-Host $windowsVersion
        Add-Result "Environment" "PASS" "commit $($gitCommit.Output.Trim()); rust $($rustVersion.Output.Trim()); cargo $($cargoVersion.Output.Trim()); vsdevcmd $script:VsDevCmd; windows $windowsVersion; git status chars $($gitStatus.Output.Length)"

        Set-Content -Encoding UTF8 -Path (Join-Path $Readable "readable.txt") -Value "readable-secret"
        Set-Content -Encoding UTF8 -Path (Join-Path $Outside "secret.txt") -Value "outside-secret"

        Write-Step "build and unit tests"
        if ($SkipCargoTests) {
            Add-Result "Build and unit tests" "SKIP" "-SkipCargoTests was provided"
        } else {
            Run-Command -FilePath $script:Cargo -ArgumentList @("test", "-p", "heel", "--lib")
            Run-Command -FilePath $script:Cargo -ArgumentList @("test", "-p", "heel", "--bins")
            Add-Result "Build and unit tests" "PASS" "cargo test -p heel --lib and --bins exited 0"
        }
        Run-Command -FilePath $script:Cargo -ArgumentList @("build", "-p", "heel", "--bin", "heel")
        $script:Heel = Join-Path $Repo "target\debug\heel.exe"
        $heelVersion = Run-Command -FilePath $script:Heel -ArgumentList @("--version")
        Add-Result "Heel binary" "PASS" "$($heelVersion.Output.Trim()) at $script:Heel"

        Write-Step "execution smoke"
        $helloFile = Join-Path $Sandbox "hello.txt"
        $smoke = Run-Heel -ArgumentList @("run", "--working-dir", $Sandbox, "cmd.exe", "/C", "cd && echo heel-ok>$(Cmd-Path $helloFile) && type $(Cmd-Path $helloFile)") -AllowAnyExit

        $effectiveMode = $Mode
        if ($Mode -eq "Auto") {
            if ($smoke.ExitCode -eq 0 -and $smoke.Output.Contains("heel-ok")) {
                $effectiveMode = "Full"
            } else {
                $effectiveMode = "FailClosed"
            }
        }

        if ($effectiveMode -eq "FailClosed") {
            if ($smoke.ExitCode -eq 0) {
                throw "FailClosed mode expected command launch to fail, but smoke exited 0."
            }
            Assert-Missing $helloFile "FailClosed smoke"
            Add-Result "Current fail-closed execution" "PASS" "smoke command exited $($smoke.ExitCode) without creating $helloFile"
            Write-Report $gitCommit.Output.Trim() $windowsVersion $rustVersion.Output.Trim() $heelVersion.Output.Trim() $effectiveMode
            Write-Host "PASS"
            Write-Host "report: $Report"
            return
        }

        if ($smoke.ExitCode -ne 0) {
            throw "Full mode expected execution smoke to succeed, but it exited $($smoke.ExitCode)."
        }
        Assert-Contains $smoke.Output "heel-ok" "execution smoke"
        Assert-FileContains $helloFile "heel-ok" "execution smoke"
        Add-Result "Execution smoke" "PASS" "heel run cmd.exe wrote and read $helloFile"

        if ($SkipIgnoredCargoTests) {
            Add-Result "Ignored AppContainer tests" "SKIP" "-SkipIgnoredCargoTests was provided"
        } else {
            Write-Step "ignored Windows AppContainer tests"
            $ignoredTests = @(
                "windows_backend_executes_cmd_echo_in_appcontainer",
                "windows_appcontainer_file_boundaries",
                "windows_job_kills_process_tree",
                "windows_wait_closes_job_after_root_exits_with_background_descendant",
                "windows_output_closes_job_before_joining_piped_background_descendant",
                "windows_appcontainer_network_deny_all_blocks_outbound_http",
                "windows_appcontainer_network_deny_all_blocks_dns_lookup",
                "windows_appcontainer_network_deny_all_blocks_loopback_connection"
            )
            foreach ($testName in $ignoredTests) {
                Run-Command -FilePath $script:Cargo -ArgumentList @("test", "-p", "heel", $testName, "--", "--ignored", "--nocapture")
            }
            Add-Result "Ignored AppContainer tests" "PASS" "$($ignoredTests.Count) ignored Windows tests exited 0"
        }

        Write-Step "filesystem default strict outside read/write"
        $outsideSecret = Join-Path $Outside "secret.txt"
        $outsideBlocked = Join-Path $Outside "blocked-write.txt"
        $outsideRead = Run-Heel -ArgumentList @("run", "--working-dir", $Sandbox, "cmd.exe", "/C", "type $(Cmd-Path $outsideSecret)") -AllowAnyExit
        if ($outsideRead.ExitCode -eq 0) {
            throw "outside read unexpectedly succeeded."
        }
        Assert-NotContains $outsideRead.Output "outside-secret" "outside read"
        $outsideWrite = Run-Heel -ArgumentList @("run", "--working-dir", $Sandbox, "cmd.exe", "/C", "echo blocked>$(Cmd-Path $outsideBlocked)") -AllowAnyExit
        if ($outsideWrite.ExitCode -eq 0) {
            throw "outside write unexpectedly succeeded."
        }
        Assert-Missing $outsideBlocked "outside write"
        Add-Result "Default outside read/write denied" "PASS" "outside read exit $($outsideRead.ExitCode), outside write exit $($outsideWrite.ExitCode), no blocked file"

        Write-Step "readable root read-only"
        $readableFile = Join-Path $Readable "readable.txt"
        $readableBlocked = Join-Path $Readable "blocked-write.txt"
        $readableRead = Run-Heel -ArgumentList @("run", "--working-dir", $Sandbox, "--readable", $Readable, "cmd.exe", "/C", "type $(Cmd-Path $readableFile)")
        Assert-Contains $readableRead.Output "readable-secret" "readable root read"
        $readableWrite = Run-Heel -ArgumentList @("run", "--working-dir", $Sandbox, "--readable", $Readable, "cmd.exe", "/C", "echo blocked>$(Cmd-Path $readableBlocked)") -AllowAnyExit
        if ($readableWrite.ExitCode -eq 0) {
            throw "readable root unexpectedly accepted writes."
        }
        Assert-Missing $readableBlocked "readable root write"
        Add-Result "Readable root read-only" "PASS" "readable read exit $($readableRead.ExitCode), write exit $($readableWrite.ExitCode), no blocked file"

        Write-Step "writable root"
        $writableFile = Join-Path $Writable "created.txt"
        $writableWrite = Run-Heel -ArgumentList @("run", "--working-dir", $Sandbox, "--writable", $Writable, "cmd.exe", "/C", "echo writable-ok>$(Cmd-Path $writableFile) && type $(Cmd-Path $writableFile)")
        Assert-Contains $writableWrite.Output "writable-ok" "writable root write"
        Assert-FileContains $writableFile "writable-ok" "writable root write"
        Add-Result "Writable root read/write" "PASS" "writable root created $writableFile"

        Write-Step "network deny-all"
        $networkProbe = Network-Probe
        $hostNetwork = Run-Command -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-NonInteractive", "-Command", $networkProbe)
        Assert-Contains $hostNetwork.Output "HEEL_PROBE_ALLOWED:http" "host network positive control"
        $sandboxNetwork = Run-Heel -ArgumentList @("run", "--working-dir", $Sandbox, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", $networkProbe) -ExpectedExitCodes @(86)
        Assert-Contains $sandboxNetwork.Output "HEEL_PROBE_DENIED:http" "sandbox network deny-all"
        Add-Result "Network DenyAll" "PASS" "host allowed token observed; sandbox returned denied token with exit 86"

        Write-Step "non-DenyAll rejected"
        $allowNetwork = Run-Heel -ArgumentList @("run", "--working-dir", $Sandbox, "--network", "allow", "cmd.exe", "/C", "echo should-not-run") -AllowAnyExit
        if ($allowNetwork.ExitCode -eq 0) {
            throw "--network allow unexpectedly ran on Windows."
        }
        Assert-Contains $allowNetwork.Output "windows-appcontainer-network" "--network allow"
        $allowListNetwork = Run-Heel -ArgumentList @("run", "--working-dir", $Sandbox, "--network", "allow-list", "--allow-domain", "example.com", "cmd.exe", "/C", "echo should-not-run") -AllowAnyExit
        if ($allowListNetwork.ExitCode -eq 0) {
            throw "--network allow-list unexpectedly ran on Windows."
        }
        Assert-Contains $allowListNetwork.Output "windows-appcontainer-network" "--network allow-list"
        Add-Result "Non-DenyAll rejected" "PASS" "allow exit $($allowNetwork.ExitCode), allow-list exit $($allowListNetwork.ExitCode), both rejected"

        Write-Step "python smoke"
        if ($SkipPython) {
            Add-Result "Python smoke" "SKIP" "-SkipPython was provided"
        } else {
            $probe = Join-Path $Sandbox "probe.py"
            $outsidePythonBlocked = Join-Path $Outside "python-blocked.txt"
            Set-Content -Encoding UTF8 -Path $probe -Value @(
                "import os",
                "import socket",
                "import sys",
                "from pathlib import Path",
                "root = Path.cwd()",
                'target = root / "python-ok.txt"',
                'target.write_text("python-ok", encoding="utf-8")',
                'print(target.read_text(encoding="utf-8"))',
                'outside_secret = Path(os.environ["HEEL_OUTSIDE_SECRET"])',
                'outside_write = Path(os.environ["HEEL_OUTSIDE_WRITE"])',
                'try:',
                '    print(outside_secret.read_text(encoding="utf-8"))',
                '    print("PY_OUTSIDE_READ_ALLOWED")',
                '    sys.exit(31)',
                'except OSError as exc:',
                '    print("PY_OUTSIDE_READ_DENIED:" + exc.__class__.__name__)',
                'try:',
                '    outside_write.write_text("blocked", encoding="utf-8")',
                '    print("PY_OUTSIDE_WRITE_ALLOWED")',
                '    sys.exit(32)',
                'except OSError as exc:',
                '    print("PY_OUTSIDE_WRITE_DENIED:" + exc.__class__.__name__)',
                'try:',
                '    sock = socket.create_connection(("example.com", 80), timeout=5)',
                '    sock.close()',
                '    print("PY_NETWORK_ALLOWED")',
                '    sys.exit(33)',
                'except OSError as exc:',
                '    print("PY_NETWORK_DENIED:" + exc.__class__.__name__)'
            )
            $pythonSmoke = Run-Heel -ArgumentList @(
                "python",
                "--working-dir", $Sandbox,
                "--python", $script:Python,
                "--env", "HEEL_OUTSIDE_SECRET=$outsideSecret",
                "--env", "HEEL_OUTSIDE_WRITE=$outsidePythonBlocked",
                $probe
            )
            $pythonRealpathWarning = $pythonSmoke.Output.Contains("Failed to find real location of")
            Assert-Contains $pythonSmoke.Output "python-ok" "heel python"
            Assert-Contains $pythonSmoke.Output "PY_OUTSIDE_READ_DENIED" "heel python outside read"
            Assert-Contains $pythonSmoke.Output "PY_OUTSIDE_WRITE_DENIED" "heel python outside write"
            Assert-Contains $pythonSmoke.Output "PY_NETWORK_DENIED" "heel python network"
            Assert-NotContains $pythonSmoke.Output "outside-secret" "heel python outside read"
            Assert-FileContains (Join-Path $Sandbox "python-ok.txt") "python-ok" "heel python"
            Assert-Missing $outsidePythonBlocked "heel python outside write"
            $warningEvidence = if ($pythonRealpathWarning) { "; CPython AppContainer realpath warning observed" } else { "" }
            Add-Result "Python smoke" "PASS" "heel python wrote inside sandbox, denied outside read/write, and denied socket network using $script:Python$warningEvidence"

            Write-Step "python venv smoke"
            $venv = Join-Path $Root "venv"
            $venvCreateProbe = Join-Path $Sandbox "venv-create-probe.py"
            Set-Content -Encoding UTF8 -Path $venvCreateProbe -Value @(
                "import sys",
                'print("VENV_CREATE_OK")',
                'print("VENV_EXE=" + sys.executable)',
                'print("VENV_PREFIX=" + sys.prefix)',
                'print("VENV_BASE_PREFIX=" + sys.base_prefix)'
            )
            $venvCreate = Run-Heel -ArgumentList @(
                "python",
                "--working-dir", $Sandbox,
                "--venv", $venv,
                $venvCreateProbe
            )
            Assert-Contains $venvCreate.Output "VENV_CREATE_OK" "heel python venv creation"
            Assert-Contains $venvCreate.Output $venv "heel python venv prefix"
            Assert-FileContains (Join-Path $venv "pyvenv.cfg") "home" "heel python venv creation"
            if (-not (Test-Path (Join-Path $venv "Scripts\python.exe"))) {
                throw "heel python venv creation did not create Scripts\python.exe"
            }

            $sitePackages = Join-Path $venv "Lib\site-packages"
            $moduleDir = Join-Path $sitePackages "heelprobe"
            New-Item -ItemType Directory -Force $moduleDir | Out-Null
            Set-Content -Encoding UTF8 -Path (Join-Path $moduleDir "__init__.py") -Value 'VALUE = "from-venv-site-packages"'

            $venvIsolationProbe = Join-Path $Sandbox "venv-isolation-probe.py"
            $outsideVenvBlocked = Join-Path $Outside "venv-blocked.txt"
            Set-Content -Encoding UTF8 -Path $venvIsolationProbe -Value @(
                "import os",
                "import socket",
                "import sys",
                "from pathlib import Path",
                "import heelprobe",
                'print("VENV_IMPORT=" + heelprobe.VALUE)',
                'target = Path.cwd() / "venv-ok.txt"',
                'target.write_text("venv-ok", encoding="utf-8")',
                'print(target.read_text(encoding="utf-8"))',
                'try:',
                '    print(Path(os.environ["HEEL_OUTSIDE_SECRET"]).read_text(encoding="utf-8"))',
                '    print("VENV_OUTSIDE_READ_ALLOWED")',
                '    sys.exit(41)',
                'except OSError as exc:',
                '    print("VENV_OUTSIDE_READ_DENIED:" + exc.__class__.__name__)',
                'try:',
                '    Path(os.environ["HEEL_OUTSIDE_WRITE"]).write_text("blocked", encoding="utf-8")',
                '    print("VENV_OUTSIDE_WRITE_ALLOWED")',
                '    sys.exit(42)',
                'except OSError as exc:',
                '    print("VENV_OUTSIDE_WRITE_DENIED:" + exc.__class__.__name__)',
                'try:',
                '    sock = socket.create_connection(("example.com", 80), timeout=5)',
                '    sock.close()',
                '    print("VENV_NETWORK_ALLOWED")',
                '    sys.exit(43)',
                'except OSError as exc:',
                '    print("VENV_NETWORK_DENIED:" + exc.__class__.__name__)'
            )
            $venvSmoke = Run-Heel -ArgumentList @(
                "python",
                "--working-dir", $Sandbox,
                "--venv", $venv,
                "--env", "HEEL_OUTSIDE_SECRET=$outsideSecret",
                "--env", "HEEL_OUTSIDE_WRITE=$outsideVenvBlocked",
                $venvIsolationProbe
            )
            Assert-Contains $venvSmoke.Output "VENV_IMPORT=from-venv-site-packages" "heel python venv import"
            Assert-Contains $venvSmoke.Output "venv-ok" "heel python venv write"
            Assert-Contains $venvSmoke.Output "VENV_OUTSIDE_READ_DENIED" "heel python venv outside read"
            Assert-Contains $venvSmoke.Output "VENV_OUTSIDE_WRITE_DENIED" "heel python venv outside write"
            Assert-Contains $venvSmoke.Output "VENV_NETWORK_DENIED" "heel python venv network"
            Assert-NotContains $venvSmoke.Output "outside-secret" "heel python venv outside read"
            Assert-FileContains (Join-Path $Sandbox "venv-ok.txt") "venv-ok" "heel python venv"
            Assert-Missing $outsideVenvBlocked "heel python venv outside write"
            Add-Result "Python venv smoke" "PASS" "heel python --venv created a Windows venv without --python, imported site-packages, denied outside read/write, and denied socket network"
        }

        Write-Step "environment and current directory"
        $envCwd = Run-Heel -ArgumentList @("run", "--working-dir", $Sandbox, "--env", "HEEL_VALIDATION=ok", "cmd.exe", "/C", "echo %CD% && echo %HEEL_VALIDATION%")
        Assert-Contains $envCwd.Output $Sandbox "env and cwd"
        Assert-Contains $envCwd.Output "ok" "env and cwd"
        Add-Result "Env and cwd" "PASS" "output contained sandbox cwd and HEEL_VALIDATION=ok"

        Write-Step "process tree cleanup"
        $loop = Join-Path $Sandbox "loop.ps1"
        $spawner = Join-Path $Sandbox "spawn-background.ps1"
        $marker = Join-Path $Sandbox "loop-marker.txt"
        Set-Content -Encoding UTF8 -Path $loop -Value @(
            'while ($true) {',
            "    Add-Content -Encoding UTF8 `"$marker`" `"tick`"",
            "    Start-Sleep -Seconds 1",
            "}"
        )
        Set-Content -Encoding UTF8 -Path $spawner -Value @(
            "Start-Process -FilePath powershell.exe -ArgumentList @(`"-NoProfile`", `"-ExecutionPolicy`", `"Bypass`", `"-File`", `"$loop`")",
            "Start-Sleep -Seconds 2"
        )
        Run-Heel -ArgumentList @("run", "--working-dir", $Sandbox, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $spawner)
        $before = Line-Count $marker
        if ($before -lt 1) {
            throw "background process did not write marker before sandbox root exited."
        }
        Start-Sleep -Seconds 4
        $after = Line-Count $marker
        if ($after -gt $before) {
            throw "background child process survived sandbox cleanup: before=$before after=$after marker=$marker"
        }
        Add-Result "Process tree cleanup" "PASS" "marker stopped at $after lines after root process exited"

        Write-Step "unsupported capabilities fail closed"
        $permissive = Run-Heel -ArgumentList @("run", "--working-dir", $Sandbox, "--permissive", "cmd.exe", "/C", "echo should-not-run") -AllowAnyExit
        if ($permissive.ExitCode -eq 0) {
            throw "--permissive unexpectedly ran on Windows."
        }
        Assert-Contains $permissive.Output "windows-appcontainer-filesystem" "--permissive"
        Add-Result "Unsupported permissive rejected" "PASS" "--permissive exited $($permissive.ExitCode) with windows-appcontainer-filesystem"

        Write-Report $gitCommit.Output.Trim() $windowsVersion $rustVersion.Output.Trim() $heelVersion.Output.Trim() $effectiveMode
        Write-Host "PASS"
        Write-Host "report: $Report"
    } finally {
        Pop-Location
    }
} finally {
    Stop-Transcript | Out-Null
    Write-Host "log: $Log"
}
