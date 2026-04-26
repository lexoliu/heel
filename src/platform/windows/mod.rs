mod acl;
#[cfg(target_os = "windows")]
pub(crate) mod job;
mod paths;
mod policy;
mod process;
mod profile;

#[cfg(target_os = "windows")]
pub(crate) use process::AppContainerLaunchState;

use std::future::Future;
use std::path::Path;
use std::process::Output;

use crate::config::SandboxConfigData;
use crate::error::Result;
use crate::platform::{Backend, Child};
use crate::stdio::StdioConfig;

pub struct WindowsBackend;

impl WindowsBackend {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}

const HEEL_APP_ID: &str = "heel";

pub(crate) fn appcontainer_profile_name(
    config: &SandboxConfigData,
) -> Result<profile::ProfileName> {
    profile::profile_name(HEEL_APP_ID, &config.working_dir().to_string_lossy())
}

#[allow(clippy::too_many_arguments)]
fn launch_supported_config(
    config: &SandboxConfigData,
    proxy_port: u16,
    program: &str,
    args: &[String],
    envs: &[(String, String)],
    current_dir: Option<&Path>,
    stdin: StdioConfig,
    stdout: StdioConfig,
    stderr: StdioConfig,
) -> Result<Child> {
    let grants = policy::validate_config_supported(config)?;
    let profile_name = appcontainer_profile_name(config)?;
    let current_dir = current_dir.unwrap_or(config.working_dir());

    #[cfg(target_os = "windows")]
    {
        let base_envs =
            process::allowed_environment_from(std::env::vars(), config.env_passthrough())?;
        let envs = appcontainer_runtime_env(config, envs);
        let profile = profile::AppContainerProfile::create_or_open(profile_name)?;
        let grant_guard = acl::apply_grants_for_appcontainer_sid(&grants, profile.sid())?;
        let launch_state = process::AppContainerLaunchState::new(profile, grant_guard);
        let launch = process::WindowsLaunch {
            program,
            args,
            current_dir,
            base_envs: &base_envs,
            envs: &envs,
            stdin,
            stdout,
            stderr,
        };
        let _ = proxy_port;

        process::launch_appcontainer_process(launch, launch_state)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (
            grants,
            profile_name,
            proxy_port,
            program,
            args,
            envs,
            current_dir,
            stdin,
            stdout,
            stderr,
        );

        Err(crate::error::Error::UnsupportedPlatform)
    }
}

#[cfg(target_os = "windows")]
fn appcontainer_runtime_env(
    config: &SandboxConfigData,
    envs: &[(String, String)],
) -> Vec<(String, String)> {
    let mut effective = envs.to_vec();
    // CreateProcessW needs LOCALAPPDATA when launching with AppContainer
    // security capabilities. Using the sandbox root keeps the redirected
    // Packages\<profile>\AC tree inside Heel's writable boundary.
    effective.push((
        "LOCALAPPDATA".to_string(),
        config.working_dir().to_string_lossy().into_owned(),
    ));
    effective
}

impl Backend for WindowsBackend {
    fn execute(
        &self,
        config: &SandboxConfigData,
        proxy_port: u16,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
        current_dir: Option<&std::path::Path>,
        stdin: StdioConfig,
        stdout: StdioConfig,
        stderr: StdioConfig,
    ) -> impl Future<Output = Result<Output>> + Send {
        async move {
            let child = launch_supported_config(
                config,
                proxy_port,
                program,
                args,
                envs,
                current_dir,
                stdin,
                stdout,
                stderr,
            )?;

            child.wait_with_output().await
        }
    }

    fn spawn(
        &self,
        config: &SandboxConfigData,
        proxy_port: u16,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
        current_dir: Option<&std::path::Path>,
        stdin: StdioConfig,
        stdout: StdioConfig,
        stderr: StdioConfig,
    ) -> impl Future<Output = Result<Child>> + Send {
        async move {
            launch_supported_config(
                config,
                proxy_port,
                program,
                args,
                envs,
                current_dir,
                stdin,
                stdout,
                stderr,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WindowsBackend;
    use crate::config::SandboxConfig;
    use crate::network::AllowAll;
    use crate::platform::Backend;
    use crate::stdio::StdioConfig;
    #[cfg(target_os = "windows")]
    use std::path::{Path, PathBuf};
    #[cfg(target_os = "windows")]
    use std::process::Output;

    #[test]
    fn windows_backend_constructs() {
        let _backend = WindowsBackend::new().expect("backend");
    }

    #[test]
    fn windows_appcontainer_network_deny_all_rejects_allow_all_before_execute_launch() {
        smol::block_on(async {
            let (_, config) = SandboxConfig::builder()
                .network(AllowAll)
                .build()
                .expect("config")
                .into_parts();
            let backend = WindowsBackend::new().expect("backend");

            let err = backend
                .execute(
                    &config,
                    0,
                    "heel-should-not-launch.exe",
                    &[],
                    &[],
                    None,
                    StdioConfig::Null,
                    StdioConfig::Null,
                    StdioConfig::Null,
                )
                .await
                .expect_err("policy validation should reject before process launch");

            assert!(err.to_string().contains("windows-appcontainer-network"));
        });
    }

    #[test]
    fn windows_appcontainer_network_deny_all_rejects_allow_all_before_spawn_launch() {
        smol::block_on(async {
            let (_, config) = SandboxConfig::builder()
                .network(AllowAll)
                .build()
                .expect("config")
                .into_parts();
            let backend = WindowsBackend::new().expect("backend");

            let result = backend
                .spawn(
                    &config,
                    0,
                    "heel-should-not-launch.exe",
                    &[],
                    &[],
                    None,
                    StdioConfig::Null,
                    StdioConfig::Null,
                    StdioConfig::Null,
                )
                .await;

            match result {
                Ok(_) => panic!("policy validation should reject before process launch"),
                Err(err) => assert!(err.to_string().contains("windows-appcontainer-network")),
            }
        });
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_runtime_env_forces_localappdata_into_working_dir() {
        let (_, config) = SandboxConfig::builder()
            .working_dir("C:/Heel/session")
            .build()
            .expect("config")
            .into_parts();
        let envs = super::appcontainer_runtime_env(
            &config,
            &[(
                "LOCALAPPDATA".to_string(),
                "C:/Users/host/AppData/Local".to_string(),
            )],
        );
        let block = super::process::environment_block_from([], &envs).expect("environment block");
        let decoded = String::from_utf16(&block).expect("utf16 env block");

        assert!(decoded.contains("LOCALAPPDATA=C:/Heel/session"));
        assert!(!decoded.contains("C:/Users/host/AppData/Local"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn windows_backend_still_fails_closed_until_process_launch_lands() {
        smol::block_on(async {
            let (_, config) = SandboxConfig::builder()
                .working_dir("C:/Heel/session")
                .build()
                .expect("config")
                .into_parts();
            let backend = WindowsBackend::new().expect("backend");
            let profile_name = super::appcontainer_profile_name(&config).expect("profile name");

            assert_eq!(
                profile_name,
                super::appcontainer_profile_name(&config).unwrap()
            );
            assert!(profile_name.as_str().starts_with("heel.heel."));

            let result = backend
                .spawn(
                    &config,
                    0,
                    "cmd.exe",
                    &["/C".to_string(), "echo ok".to_string()],
                    &[("HEEL_TEST".to_string(), "1".to_string())],
                    None,
                    StdioConfig::Null,
                    StdioConfig::Piped,
                    StdioConfig::Piped,
                )
                .await;

            match result {
                Ok(_) => panic!("process launch is intentionally fail-closed until Task 10"),
                Err(err) => assert!(matches!(err, crate::error::Error::UnsupportedPlatform)),
            }
        });
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires Windows AppContainer process launch"]
    fn windows_backend_executes_cmd_echo_in_appcontainer() {
        smol::block_on(async {
            let (_temp_guard, config) = temp_config("heel-windows-echo");
            let backend = WindowsBackend::new().expect("backend");

            let output = backend
                .execute(
                    &config,
                    0,
                    "cmd.exe",
                    &["/C".to_string(), "echo heel-windows-ok".to_string()],
                    &[],
                    None,
                    StdioConfig::Null,
                    StdioConfig::Piped,
                    StdioConfig::Piped,
                )
                .await
                .expect("cmd echo should launch inside AppContainer");

            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("heel-windows-ok"),
                "stdout should contain marker, got {stdout:?}"
            );
        });
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires Windows AppContainer process launch and host process polling"]
    fn windows_job_kills_process_tree() {
        smol::block_on(async {
            let (_temp_guard, config) = temp_config("heel-windows-job");
            let backend = WindowsBackend::new().expect("backend");
            let marker = unique_marker("heel-job-tree");

            let mut child = backend
                .spawn(
                    &config,
                    0,
                    "cmd.exe",
                    &["/C".to_string(), background_sleep_command(&marker, 120)],
                    &[],
                    None,
                    StdioConfig::Null,
                    StdioConfig::Null,
                    StdioConfig::Null,
                )
                .await
                .expect("cmd should launch sleep descendant in the process tree");

            poll_until("sleep descendant starts", || {
                command_line_process_exists(&marker)
            })
            .expect("sleep child should appear before killing root");

            child.kill().expect("job kill should succeed");
            drop(child);

            poll_until("sleep descendant exits after job cleanup", || {
                !command_line_process_exists(&marker)
            })
            .expect("sleep child should exit when the job is terminated");
        });
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires Windows AppContainer process launch and host process polling"]
    fn windows_wait_closes_job_after_root_exits_with_background_descendant() {
        smol::block_on(async {
            let (_temp_guard, config) = temp_config("heel-windows-wait");
            let backend = WindowsBackend::new().expect("backend");
            let (spawner, marker) =
                write_background_file_probe(config.working_dir(), "heel-wait-tree", 2, None);

            let mut child = backend
                .spawn(
                    &config,
                    0,
                    "powershell.exe",
                    &[
                        "-NoProfile".to_string(),
                        "-ExecutionPolicy".to_string(),
                        "Bypass".to_string(),
                        "-File".to_string(),
                        spawner.to_string_lossy().into_owned(),
                    ],
                    &[],
                    None,
                    StdioConfig::Null,
                    StdioConfig::Null,
                    StdioConfig::Null,
                )
                .await
                .expect("cmd should launch sleep descendant in the process tree");

            poll_until("sleep descendant starts before root exits", || {
                line_count(&marker) > 0
            })
            .expect("sleep child should appear before waiting for root");

            let status = child.wait().await.expect("root wait should succeed");
            assert!(status.success(), "root command should exit successfully");

            let after_wait = line_count(&marker);
            std::thread::sleep(std::time::Duration::from_secs(3));
            let after_sleep = line_count(&marker);
            assert_eq!(
                after_sleep, after_wait,
                "background marker should stop changing after wait closes the job"
            );
        });
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires Windows AppContainer process launch and host process polling"]
    fn windows_output_closes_job_before_joining_piped_background_descendant() {
        smol::block_on(async {
            let (_temp_guard, config) = temp_config("heel-windows-output");
            let backend = WindowsBackend::new().expect("backend");
            let (spawner, marker) = write_background_file_probe(
                config.working_dir(),
                "heel-output-tree",
                0,
                Some("heel-output-root-done"),
            );

            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let output = smol::block_on(async {
                    backend
                        .execute(
                            &config,
                            0,
                            "powershell.exe",
                            &[
                                "-NoProfile".to_string(),
                                "-ExecutionPolicy".to_string(),
                                "Bypass".to_string(),
                                "-File".to_string(),
                                spawner.to_string_lossy().into_owned(),
                            ],
                            &[],
                            None,
                            StdioConfig::Null,
                            StdioConfig::Piped,
                            StdioConfig::Piped,
                        )
                        .await
                });
                sender.send(output).expect("send output result");
            });

            let output = receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("output() should finish after root exits and job closes");
            let output = output.expect("cmd should launch sleep descendant");
            let stdout = String::from_utf8_lossy(&output.stdout);

            assert!(
                stdout.contains("heel-output-root-done"),
                "stdout should contain root marker, got {stdout:?}"
            );
            assert!(
                output.status.success(),
                "root command should exit successfully: stderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
            let after_output = line_count(&marker);
            std::thread::sleep(std::time::Duration::from_secs(3));
            let after_sleep = line_count(&marker);
            assert_eq!(
                after_sleep, after_output,
                "background marker should stop changing after output() closes the job"
            );
        });
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires Windows AppContainer file boundary enforcement"]
    fn windows_appcontainer_file_boundaries() {
        smol::block_on(async {
            let temp_root = std::env::temp_dir().join(format!(
                "heel-windows-file-boundaries-{}",
                std::process::id()
            ));
            if temp_root.exists() {
                std::fs::remove_dir_all(&temp_root).expect("clean stale temp root");
            }
            std::fs::create_dir(&temp_root).expect("temp root");
            let temp_root_guard = TempDirGuard(temp_root.clone());

            let working = temp_root.join("working");
            let read = temp_root.join("read");
            let write = temp_root.join("write");
            let outside = temp_root.join("outside");
            for dir in [&working, &read, &write, &outside] {
                std::fs::create_dir(dir).expect("test directory");
            }

            let read_file = read.join("allowed.txt");
            let write_file = write.join("created.txt");
            let outside_file = outside.join("secret.txt");
            std::fs::write(&read_file, "heel-read-ok").expect("read fixture");
            std::fs::write(&outside_file, "heel-outside-secret").expect("outside fixture");

            let (_, config) = SandboxConfig::builder()
                .working_dir(&working)
                .readable_path(&read)
                .writable_path(&write)
                .build()
                .expect("config")
                .into_parts();
            let backend = WindowsBackend::new().expect("backend");

            let read_output = backend
                .execute(
                    &config,
                    0,
                    "powershell.exe",
                    &[
                        "-NoProfile".to_string(),
                        "-NonInteractive".to_string(),
                        "-Command".to_string(),
                        format!(
                            "$ErrorActionPreference='Stop'; Get-Content -Raw -LiteralPath {}",
                            ps_literal_path(&read_file)
                        ),
                    ],
                    &[],
                    None,
                    StdioConfig::Null,
                    StdioConfig::Piped,
                    StdioConfig::Piped,
                )
                .await
                .expect("allowed read should launch");
            assert!(
                read_output.status.success(),
                "allowed read failed: stderr={}",
                String::from_utf8_lossy(&read_output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&read_output.stdout).contains("heel-read-ok"),
                "allowed read stdout should contain fixture"
            );

            let write_output = backend
                .execute(
                    &config,
                    0,
                    "powershell.exe",
                    &[
                        "-NoProfile".to_string(),
                        "-NonInteractive".to_string(),
                        "-Command".to_string(),
                        format!(
                            "$ErrorActionPreference='Stop'; Set-Content -NoNewline -Encoding ASCII -LiteralPath {} -Value 'heel-write-ok'; Get-Content -Raw -LiteralPath {}",
                            ps_literal_path(&write_file),
                            ps_literal_path(&write_file)
                        ),
                    ],
                    &[],
                    None,
                    StdioConfig::Null,
                    StdioConfig::Piped,
                    StdioConfig::Piped,
                )
                .await
                .expect("allowed write should launch");
            assert!(
                write_output.status.success(),
                "allowed write failed: stderr={}",
                String::from_utf8_lossy(&write_output.stderr)
            );
            assert_eq!(
                std::fs::read_to_string(&write_file)
                    .expect("written file")
                    .trim(),
                "heel-write-ok"
            );

            let outside_output = backend
                .execute(
                    &config,
                    0,
                    "powershell.exe",
                    &[
                        "-NoProfile".to_string(),
                        "-NonInteractive".to_string(),
                        "-Command".to_string(),
                        format!(
                            "$ErrorActionPreference='Stop'; Get-Content -Raw -LiteralPath {}",
                            ps_literal_path(&outside_file)
                        ),
                    ],
                    &[],
                    None,
                    StdioConfig::Null,
                    StdioConfig::Piped,
                    StdioConfig::Piped,
                )
                .await
                .expect("outside read command should launch");
            assert!(
                !outside_output.status.success(),
                "outside read unexpectedly succeeded: stdout={}",
                String::from_utf8_lossy(&outside_output.stdout)
            );

            drop(temp_root_guard);
        });
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires Windows AppContainer network boundary enforcement"]
    fn windows_appcontainer_network_deny_all_blocks_outbound_http() {
        smol::block_on(async {
            let script = format!(
                "{}\n{}",
                powershell_network_probe_prelude(),
                r#"
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
try {
    Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 -Uri 'http://example.com/' -ErrorAction Stop | Out-Null
    Write-Output 'HEEL_PROBE_ALLOWED:http'
    exit 0
} catch {
    $exception = $_.Exception
    if ((Test-ExceptionChain $exception 'System.Net.WebException') -or (Test-ExceptionChain $exception 'System.Net.Sockets.SocketException')) {
        Exit-ProbeDenied 'http' $exception
    }
    Exit-ProbeError 'http' $exception
}
"#
            );
            let host_output = run_host_powershell(&script);
            assert_probe_allowed("host HTTP positive control", &host_output);

            let output = run_default_deny_all_powershell(&script)
                .await
                .expect("HTTP probe should launch inside AppContainer");

            assert_probe_denied("DenyAll AppContainer outbound HTTP", &output);
        });
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires Windows AppContainer network boundary enforcement"]
    fn windows_appcontainer_network_deny_all_blocks_dns_lookup() {
        smol::block_on(async {
            let script = format!(
                "{}\n{}",
                powershell_network_probe_prelude(),
                r#"
$ErrorActionPreference = 'Stop'
try {
    [System.Net.Dns]::GetHostAddresses('example.com') | Out-Null
    Write-Output 'HEEL_PROBE_ALLOWED:dns'
    exit 0
} catch {
    $exception = $_.Exception
    if (Test-ExceptionChain $exception 'System.Net.Sockets.SocketException') {
        Exit-ProbeDenied 'dns' $exception
    }
    Exit-ProbeError 'dns' $exception
}
"#
            );
            let host_output = run_host_powershell(&script);
            assert_probe_allowed("host DNS positive control", &host_output);

            let output = run_default_deny_all_powershell(&script)
                .await
                .expect("DNS probe should launch inside AppContainer");

            assert_probe_denied("DenyAll AppContainer DNS lookup", &output);
        });
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires Windows AppContainer network boundary enforcement"]
    fn windows_appcontainer_network_deny_all_blocks_loopback_connection() {
        smol::block_on(async {
            let listener =
                std::net::TcpListener::bind(("127.0.0.1", 0)).expect("host loopback listener");
            listener
                .set_nonblocking(true)
                .expect("nonblocking loopback listener");
            let port = listener.local_addr().expect("listener address").port();
            let script = format!(
                "{}\n{}",
                powershell_network_probe_prelude(),
                format!(
                    r#"
$ErrorActionPreference = 'Stop'
try {{
    $client = [System.Net.Sockets.TcpClient]::new()
    $pending = $client.BeginConnect('127.0.0.1', {port}, $null, $null)
    if (-not $pending.AsyncWaitHandle.WaitOne(5000)) {{
        $client.Close()
        Write-Output 'HEEL_PROBE_DENIED:loopback:connect-timeout'
        exit 86
    }}
    $client.EndConnect($pending)
    $client.Close()
    Write-Output 'HEEL_PROBE_ALLOWED:loopback'
    exit 0
}} catch {{
    $exception = $_.Exception
    if (Test-ExceptionChain $exception 'System.Net.Sockets.SocketException') {{
        Exit-ProbeDenied 'loopback' $exception
    }}
    Exit-ProbeError 'loopback' $exception
}}
"#
                )
            );
            let host_output = run_host_powershell(&script);
            assert_probe_allowed("host loopback positive control", &host_output);
            accept_loopback_connection(&listener, "host loopback positive control");

            let output = run_default_deny_all_powershell(&script)
                .await
                .expect("loopback probe should launch inside AppContainer");

            assert_probe_denied("DenyAll AppContainer loopback connection", &output);
            match listener.accept() {
                Ok((_, addr)) => {
                    panic!("DenyAll AppContainer unexpectedly reached host listener from {addr}")
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("failed to inspect host listener queue: {error}"),
            }
        });
    }

    #[cfg(target_os = "windows")]
    const POWERSHELL_PROBE_DENIED_EXIT: i32 = 86;

    #[cfg(target_os = "windows")]
    const POWERSHELL_PROBE_ERROR_EXIT: i32 = 87;

    #[cfg(target_os = "windows")]
    fn powershell_network_probe_prelude() -> &'static str {
        r#"
function Test-ExceptionChain {
    param(
        [System.Exception] $Exception,
        [string] $TypeName
    )
    while ($null -ne $Exception) {
        if ($Exception.GetType().FullName -eq $TypeName) {
            return $true
        }
        $Exception = $Exception.InnerException
    }
    return $false
}

function Exit-ProbeDenied {
    param(
        [string] $Name,
        [System.Exception] $Exception
    )
    Write-Output "HEEL_PROBE_DENIED:$($Name):$($Exception.GetType().FullName):$($Exception.Message)"
    exit 86
}

function Exit-ProbeError {
    param(
        [string] $Name,
        [System.Exception] $Exception
    )
    Write-Error "HEEL_PROBE_ERROR:$($Name):$($Exception.GetType().FullName):$($Exception.Message)"
    exit 87
}
"#
    }

    #[cfg(target_os = "windows")]
    fn run_host_powershell(script: &str) -> Output {
        std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .expect("host PowerShell probe should launch")
    }

    #[cfg(target_os = "windows")]
    async fn run_default_deny_all_powershell(script: &str) -> crate::error::Result<Output> {
        let (_temp_guard, config) = temp_config("heel-windows-network");
        let backend = WindowsBackend::new().expect("backend");

        backend
            .execute(
                &config,
                0,
                "powershell.exe",
                &[
                    "-NoProfile".to_string(),
                    "-NonInteractive".to_string(),
                    "-Command".to_string(),
                    script.to_string(),
                ],
                &[],
                None,
                StdioConfig::Null,
                StdioConfig::Piped,
                StdioConfig::Piped,
            )
            .await
    }

    #[cfg(target_os = "windows")]
    fn assert_probe_allowed(context: &str, output: &Output) {
        assert!(
            output.status.success(),
            "{context} failed; host network prerequisite or probe is unavailable: status={:?}, stdout={}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("HEEL_PROBE_ALLOWED"),
            "{context} exited successfully without the allowed token: stdout={}, stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "windows")]
    fn assert_probe_denied(context: &str, output: &Output) {
        match output.status.code() {
            Some(POWERSHELL_PROBE_DENIED_EXIT) => assert!(
                String::from_utf8_lossy(&output.stdout).contains("HEEL_PROBE_DENIED"),
                "{context} used the denial exit code without the denial token: stdout={}, stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Some(0) => panic!(
                "{context} unexpectedly allowed network access: stdout={}, stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Some(POWERSHELL_PROBE_ERROR_EXIT) => panic!(
                "{context} failed because the PowerShell probe errored: stdout={}, stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            other => panic!(
                "{context} failed with an unexpected PowerShell status {other:?}: stdout={}, stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        }
    }

    #[cfg(target_os = "windows")]
    fn accept_loopback_connection(listener: &std::net::TcpListener, context: &str) {
        poll_until(context, || match listener.accept() {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(error) => panic!("{context} failed to inspect host listener queue: {error}"),
        })
        .expect("host loopback listener should receive the positive-control connection");
    }

    #[cfg(target_os = "windows")]
    fn ps_literal_path(path: &std::path::Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "''"))
    }

    #[cfg(target_os = "windows")]
    fn poll_until(label: &str, mut predicate: impl FnMut() -> bool) -> std::io::Result<()> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);

        while std::time::Instant::now() < deadline {
            if predicate() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("timed out waiting for {label}"),
        ))
    }

    #[cfg(target_os = "windows")]
    fn command_line_process_exists(command_marker: &str) -> bool {
        let marker = ps_single_quoted(command_marker);
        let script = format!(
            "$marker = {marker}; $p = Get-CimInstance Win32_Process | Where-Object {{ $_.ProcessId -ne $PID -and $_.CommandLine -like \"*$marker*\" }}; if ($p) {{ exit 0 }} else {{ exit 1 }}"
        );
        let Ok(status) = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status()
        else {
            return false;
        };

        status.success()
    }

    #[cfg(target_os = "windows")]
    fn ps_single_quoted(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    #[cfg(target_os = "windows")]
    fn background_sleep_command(marker: &str, seconds: u32) -> String {
        format!(
            "start \"\" /B powershell.exe -NoProfile -NonInteractive -Command \"$m='{marker}'; Start-Sleep -Seconds {seconds}\""
        )
    }

    #[cfg(target_os = "windows")]
    fn write_background_file_probe(
        root: &Path,
        name: &str,
        parent_seconds: u32,
        root_output: Option<&str>,
    ) -> (PathBuf, PathBuf) {
        let loop_script = root.join(format!("{name}-loop.ps1"));
        let spawner_script = root.join(format!("{name}-spawner.ps1"));
        let marker = root.join(format!("{name}-marker.txt"));

        std::fs::write(
            &loop_script,
            format!(
                "while ($true) {{ Add-Content -Encoding UTF8 {} 'tick'; Start-Sleep -Seconds 1 }}",
                ps_literal_path(&marker)
            ),
        )
        .expect("write background loop script");
        let output_line = root_output
            .map(|output| format!("Write-Output {}\n", ps_single_quoted(output)))
            .unwrap_or_default();
        std::fs::write(
            &spawner_script,
            format!(
                "Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',{})\n{output_line}Start-Sleep -Seconds {parent_seconds}\n",
                ps_literal_path(&loop_script),
            ),
        )
        .expect("write background spawner script");

        (spawner_script, marker)
    }

    #[cfg(target_os = "windows")]
    fn line_count(path: &Path) -> usize {
        match std::fs::read_to_string(path) {
            Ok(content) => content.lines().count(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => panic!("failed to read marker {}: {error}", path.display()),
        }
    }

    #[cfg(target_os = "windows")]
    fn unique_marker(prefix: &str) -> String {
        format!("{prefix}-{}", std::process::id())
    }

    #[cfg(target_os = "windows")]
    fn temp_config(prefix: &str) -> (TempDirGuard, crate::config::SandboxConfigData) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("{prefix}-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&root).expect("temp working root");
        let guard = TempDirGuard(root.clone());
        let (_, config) = SandboxConfig::builder()
            .working_dir(root)
            .build()
            .expect("config")
            .into_parts();
        (guard, config)
    }

    #[cfg(target_os = "windows")]
    struct TempDirGuard(std::path::PathBuf);

    #[cfg(target_os = "windows")]
    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            if let Err(error) = std::fs::remove_dir_all(&self.0) {
                tracing::warn!(
                    path = %self.0.display(),
                    "failed to remove Windows AppContainer file-boundary temp root: {error}"
                );
            }
        }
    }
}
