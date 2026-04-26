use std::collections::{BTreeMap, BTreeSet};

#[cfg(target_os = "windows")]
use std::mem::size_of;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use std::os::windows::io::FromRawHandle;

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{
    BOOL, CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT,
    HANDLE_FLAGS, SetHandleInformation,
};
#[cfg(target_os = "windows")]
use windows::Win32::Security::{SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES};
#[cfg(target_os = "windows")]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Pipes::CreatePipe;
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess,
    UpdateProcThreadAttribute,
};
#[cfg(target_os = "windows")]
use windows::core::{PCWSTR, PWSTR};

#[cfg(target_os = "windows")]
use crate::stdio::{ChildStderr, ChildStdin, ChildStdout, StdioConfig};

const WINDOWS_RUNTIME_ENV_ALLOWLIST: &[&str] =
    &["ComSpec", "PATH", "PATHEXT", "SystemRoot", "WINDIR"];

pub(crate) fn quote_arg(input: &str) -> String {
    if input.is_empty() {
        return "\"\"".to_string();
    }

    let needs_quotes = input
        .chars()
        .any(|ch| matches!(ch, ' ' | '\t' | '\n' | '\r' | '"'));

    if !needs_quotes {
        return input.to_string();
    }

    let mut quoted = String::with_capacity(input.len() + 2);
    quoted.push('"');

    let mut backslashes = 0;
    for ch in input.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.extend(std::iter::repeat_n('\\', backslashes));
                quoted.push(ch);
                backslashes = 0;
            }
        }
    }

    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

pub(crate) fn command_line(program: &str, args: &[String]) -> String {
    std::iter::once(quote_arg(program))
        .chain(args.iter().map(|arg| quote_arg(arg)))
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn allowed_environment_from(
    parent: impl IntoIterator<Item = (String, String)>,
    passthrough: &[String],
) -> crate::error::Result<Vec<(String, String)>> {
    let mut allowed = BTreeSet::new();
    for key in WINDOWS_RUNTIME_ENV_ALLOWLIST {
        allowed.insert(key.to_ascii_uppercase());
    }
    for key in passthrough {
        validate_environment_key(key)?;
        allowed.insert(key.to_ascii_uppercase());
    }

    let mut envs = BTreeMap::new();
    for (key, value) in parent {
        if allowed.contains(&key.to_ascii_uppercase()) {
            insert_environment_entry(&mut envs, key, value)?;
        }
    }

    Ok(envs.into_values().collect())
}

pub(crate) fn environment_block_from(
    base: impl IntoIterator<Item = (String, String)>,
    overlay: &[(String, String)],
) -> crate::error::Result<Vec<u16>> {
    let mut envs = BTreeMap::new();

    for (key, value) in base {
        insert_environment_entry(&mut envs, key, value)?;
    }

    for (key, value) in overlay {
        insert_environment_entry(&mut envs, key.clone(), value.clone())?;
    }

    let mut block = Vec::new();
    for (_, (key, value)) in envs {
        block.extend(format!("{key}={value}").encode_utf16());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);

    Ok(block)
}

fn insert_environment_entry(
    envs: &mut BTreeMap<String, (String, String)>,
    key: String,
    value: String,
) -> crate::error::Result<()> {
    validate_environment_key(&key)?;
    validate_no_interior_nul("environment value", &value)?;
    envs.insert(key.to_ascii_uppercase(), (key, value));
    Ok(())
}

fn validate_environment_key(key: &str) -> crate::error::Result<()> {
    if key.is_empty() || key.contains('=') {
        return Err(crate::error::Error::ConfigError(format!(
            "invalid Windows environment key: {key:?}"
        )));
    }
    validate_no_interior_nul("environment key", key)
}

fn validate_no_interior_nul(label: &str, value: &str) -> crate::error::Result<()> {
    if value.encode_utf16().any(|unit| unit == 0) {
        return Err(crate::error::Error::ConfigError(format!(
            "{label} contains interior NUL"
        )));
    }
    Ok(())
}

fn validate_command_parts(program: &str, args: &[String]) -> crate::error::Result<()> {
    validate_no_interior_nul("program", program)?;
    for arg in args {
        validate_no_interior_nul("argument", arg)?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn environment_block(
    base: &[(String, String)],
    overlay: &[(String, String)],
) -> crate::error::Result<Vec<u16>> {
    environment_block_from(base.iter().cloned(), overlay)
}

#[cfg(target_os = "windows")]
pub(crate) struct WindowsLaunch<'a> {
    pub(crate) program: &'a str,
    pub(crate) args: &'a [String],
    pub(crate) current_dir: &'a std::path::Path,
    pub(crate) base_envs: &'a [(String, String)],
    pub(crate) envs: &'a [(String, String)],
    pub(crate) stdin: StdioConfig,
    pub(crate) stdout: StdioConfig,
    pub(crate) stderr: StdioConfig,
}

#[cfg(target_os = "windows")]
pub(crate) struct AppContainerLaunchState {
    _grant_guard: super::acl::AclGrantGuard,
    profile: super::profile::AppContainerProfile,
}

#[cfg(target_os = "windows")]
impl AppContainerLaunchState {
    pub(crate) fn new(
        profile: super::profile::AppContainerProfile,
        grant_guard: super::acl::AclGrantGuard,
    ) -> Self {
        Self {
            _grant_guard: grant_guard,
            profile,
        }
    }

    pub(crate) fn profile(&self) -> &super::profile::AppContainerProfile {
        &self.profile
    }
}

#[cfg(target_os = "windows")]
// SAFETY: AppContainerLaunchState owns process-lifetime state only: an
// AppContainer SID allocated by Windows and released with FreeSid, plus the ACL
// grant guard. The guard does not retain the SID and is declared before the
// profile so ACL restoration runs before FreeSid. The guard owns any
// thread-affine Windows coordination state through its own owner thread, so
// moving the launch state does not move raw mutex ownership across threads.
// Future state must preserve that invariant before extending this type.
unsafe impl Send for AppContainerLaunchState {}

#[cfg(target_os = "windows")]
pub(crate) fn launch_appcontainer_process(
    launch: WindowsLaunch<'_>,
    state: AppContainerLaunchState,
) -> crate::error::Result<crate::platform::Child> {
    validate_launch(&launch)?;
    let stdio = StdioHandles::new(launch.stdin, launch.stdout, launch.stderr)?;
    let child_handles = stdio.child_handles();
    let attribute_list = ProcThreadAttributeList::new(2)?;
    let mut security_capabilities = appcontainer_security_capabilities(state.profile().sid());

    unsafe {
        UpdateProcThreadAttribute(
            attribute_list.as_raw(),
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            Some((&mut security_capabilities as *mut SECURITY_CAPABILITIES).cast()),
            size_of::<SECURITY_CAPABILITIES>(),
            None,
            None,
        )
        .map_err(|error| {
            crate::error::Error::FfiError(format!(
                "UpdateProcThreadAttribute security capabilities failed: {error}"
            ))
        })?;

        UpdateProcThreadAttribute(
            attribute_list.as_raw(),
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            Some(child_handles.as_ptr().cast()),
            child_handles.len() * size_of::<HANDLE>(),
            None,
            None,
        )
        .map_err(|error| {
            crate::error::Error::FfiError(format!(
                "UpdateProcThreadAttribute handle list failed: {error}"
            ))
        })?;
    }

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdio.child_stdin.raw();
    startup.StartupInfo.hStdOutput = stdio.child_stdout.raw();
    startup.StartupInfo.hStdError = stdio.child_stderr.raw();
    startup.lpAttributeList = attribute_list.as_raw();

    let mut process_information = PROCESS_INFORMATION::default();
    let mut command_line = wide_null(&command_line(launch.program, launch.args));
    let current_dir = wide_path(launch.current_dir)?;
    let environment = environment_block(launch.base_envs, launch.envs)?;
    let job = super::job::JobGuard::new()?;

    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            PWSTR(command_line.as_mut_ptr()),
            None,
            None,
            BOOL(1),
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            Some(environment.as_ptr().cast()),
            PCWSTR(current_dir.as_ptr()),
            (&startup as *const STARTUPINFOEXW).cast::<STARTUPINFOW>(),
            &mut process_information,
        )
        .map_err(|error| {
            crate::error::Error::FfiError(format!(
                "CreateProcessW failed for '{}': {error}",
                launch.program
            ))
        })?;
    }

    let mut created_process = CreatedProcess::new(process_information);
    job.assign_process(created_process.process())?;
    created_process.resume()?;
    let (process, thread, pid) = created_process.into_parts();

    crate::platform::Child::from_windows(
        process,
        thread,
        pid,
        stdio.parent_stdin,
        stdio.parent_stdout,
        stdio.parent_stderr,
        job,
        state,
    )
}

#[cfg(target_os = "windows")]
fn appcontainer_security_capabilities(
    appcontainer_sid: windows::Win32::Security::PSID,
) -> SECURITY_CAPABILITIES {
    SECURITY_CAPABILITIES {
        AppContainerSid: appcontainer_sid,
        Capabilities: std::ptr::null_mut::<SID_AND_ATTRIBUTES>(),
        CapabilityCount: 0,
        Reserved: 0,
    }
}

#[cfg(target_os = "windows")]
fn validate_launch(launch: &WindowsLaunch<'_>) -> crate::error::Result<()> {
    validate_command_parts(launch.program, launch.args)
}

#[cfg(target_os = "windows")]
struct ProcThreadAttributeList {
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
    _storage: Vec<usize>,
}

#[cfg(target_os = "windows")]
impl ProcThreadAttributeList {
    fn new(attribute_count: u32) -> crate::error::Result<Self> {
        let mut byte_len = 0;

        unsafe {
            let _ = InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
                attribute_count,
                0,
                &mut byte_len,
            );
        }

        if byte_len == 0 {
            return Err(crate::error::Error::FfiError(
                "InitializeProcThreadAttributeList did not report a backing size".to_string(),
            ));
        }

        let word_len = byte_len.div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; word_len];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());

        unsafe {
            InitializeProcThreadAttributeList(list, attribute_count, 0, &mut byte_len).map_err(
                |error| {
                    crate::error::Error::FfiError(format!(
                        "InitializeProcThreadAttributeList failed: {error}"
                    ))
                },
            )?;
        }

        Ok(Self {
            list,
            _storage: storage,
        })
    }

    fn as_raw(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.list
    }
}

#[cfg(target_os = "windows")]
impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        if !self.list.is_invalid() {
            unsafe {
                DeleteProcThreadAttributeList(self.list);
            }
        }
    }
}

#[cfg(target_os = "windows")]
struct CreatedProcess {
    process: HANDLE,
    thread: HANDLE,
    pid: u32,
    disarmed: bool,
}

#[cfg(target_os = "windows")]
impl CreatedProcess {
    fn new(process_information: PROCESS_INFORMATION) -> Self {
        Self {
            process: process_information.hProcess,
            thread: process_information.hThread,
            pid: process_information.dwProcessId,
            disarmed: false,
        }
    }

    fn process(&self) -> HANDLE {
        self.process
    }

    fn resume(&mut self) -> crate::error::Result<()> {
        let previous_suspend_count = unsafe { ResumeThread(self.thread) };
        if previous_suspend_count == u32::MAX {
            return Err(crate::error::Error::FfiError(format!(
                "ResumeThread failed: {}",
                windows::core::Error::from_win32()
            )));
        }

        Ok(())
    }

    fn into_parts(mut self) -> (HANDLE, HANDLE, u32) {
        self.disarmed = true;
        (self.process, self.thread, self.pid)
    }
}

#[cfg(target_os = "windows")]
impl Drop for CreatedProcess {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }

        if !self.process.is_invalid()
            && !self.process.0.is_null()
            && let Err(error) = unsafe { TerminateProcess(self.process, 1) }
        {
            tracing::warn!(
                pid = self.pid,
                "failed to terminate Windows process after launch error: {error}"
            );
        }

        if !self.thread.is_invalid()
            && !self.thread.0.is_null()
            && let Err(error) = unsafe { CloseHandle(self.thread) }
        {
            tracing::warn!(
                pid = self.pid,
                "failed to close Windows thread handle after launch error: {error}"
            );
        }

        if !self.process.is_invalid()
            && !self.process.0.is_null()
            && let Err(error) = unsafe { CloseHandle(self.process) }
        {
            tracing::warn!(
                pid = self.pid,
                "failed to close Windows process handle after launch error: {error}"
            );
        }
    }
}

#[cfg(target_os = "windows")]
struct StdioHandles {
    child_stdin: OwnedWindowsHandle,
    child_stdout: OwnedWindowsHandle,
    child_stderr: OwnedWindowsHandle,
    parent_stdin: Option<ChildStdin>,
    parent_stdout: Option<ChildStdout>,
    parent_stderr: Option<ChildStderr>,
}

#[cfg(target_os = "windows")]
impl StdioHandles {
    fn new(
        stdin: StdioConfig,
        stdout: StdioConfig,
        stderr: StdioConfig,
    ) -> crate::error::Result<Self> {
        let (child_stdin, parent_stdin) = stdin_handle(stdin)?;
        let (child_stdout, parent_stdout) = stdout_handle(stdout)?;
        let (child_stderr, parent_stderr) = stderr_handle(stderr)?;

        Ok(Self {
            child_stdin,
            child_stdout,
            child_stderr,
            parent_stdin,
            parent_stdout,
            parent_stderr,
        })
    }

    fn child_handles(&self) -> Vec<HANDLE> {
        vec![
            self.child_stdin.raw(),
            self.child_stdout.raw(),
            self.child_stderr.raw(),
        ]
    }
}

#[cfg(target_os = "windows")]
struct OwnedWindowsHandle {
    handle: HANDLE,
    label: &'static str,
}

#[cfg(target_os = "windows")]
impl OwnedWindowsHandle {
    fn new(handle: HANDLE, label: &'static str) -> crate::error::Result<Self> {
        if handle.is_invalid() || handle.0.is_null() {
            return Err(crate::error::Error::FfiError(format!(
                "Windows {label} handle was invalid"
            )));
        }

        Ok(Self { handle, label })
    }

    fn raw(&self) -> HANDLE {
        self.handle
    }

    fn into_file(mut self) -> std::fs::File {
        let handle = self.handle;
        self.handle = HANDLE::default();
        unsafe { std::fs::File::from_raw_handle(handle.0) }
    }
}

#[cfg(target_os = "windows")]
impl Drop for OwnedWindowsHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid()
            && !self.handle.0.is_null()
            && let Err(error) = unsafe { CloseHandle(self.handle) }
        {
            tracing::warn!(
                handle = self.label,
                "failed to close Windows handle: {error}"
            );
        }
    }
}

#[cfg(target_os = "windows")]
fn stdin_handle(
    config: StdioConfig,
) -> crate::error::Result<(OwnedWindowsHandle, Option<ChildStdin>)> {
    match config {
        StdioConfig::Inherit => {
            duplicate_std_handle(STD_INPUT_HANDLE, "stdin").map(|handle| (handle, None))
        }
        StdioConfig::Null => {
            open_nul(FILE_GENERIC_READ.0, "stdin null").map(|handle| (handle, None))
        }
        StdioConfig::Piped => {
            let (read, write) = create_pipe("stdin pipe read", "stdin pipe write")?;
            make_not_inheritable(write.raw(), "stdin parent pipe")?;
            Ok((read, Some(write.into_file())))
        }
    }
}

#[cfg(target_os = "windows")]
fn stdout_handle(
    config: StdioConfig,
) -> crate::error::Result<(OwnedWindowsHandle, Option<ChildStdout>)> {
    match config {
        StdioConfig::Inherit => {
            duplicate_std_handle(STD_OUTPUT_HANDLE, "stdout").map(|handle| (handle, None))
        }
        StdioConfig::Null => {
            open_nul(FILE_GENERIC_WRITE.0, "stdout null").map(|handle| (handle, None))
        }
        StdioConfig::Piped => {
            let (read, write) = create_pipe("stdout pipe read", "stdout pipe write")?;
            make_not_inheritable(read.raw(), "stdout parent pipe")?;
            Ok((write, Some(read.into_file())))
        }
    }
}

#[cfg(target_os = "windows")]
fn stderr_handle(
    config: StdioConfig,
) -> crate::error::Result<(OwnedWindowsHandle, Option<ChildStderr>)> {
    match config {
        StdioConfig::Inherit => {
            duplicate_std_handle(STD_ERROR_HANDLE, "stderr").map(|handle| (handle, None))
        }
        StdioConfig::Null => {
            open_nul(FILE_GENERIC_WRITE.0, "stderr null").map(|handle| (handle, None))
        }
        StdioConfig::Piped => {
            let (read, write) = create_pipe("stderr pipe read", "stderr pipe write")?;
            make_not_inheritable(read.raw(), "stderr parent pipe")?;
            Ok((write, Some(read.into_file())))
        }
    }
}

#[cfg(target_os = "windows")]
fn create_pipe(
    read_label: &'static str,
    write_label: &'static str,
) -> crate::error::Result<(OwnedWindowsHandle, OwnedWindowsHandle)> {
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    let security_attributes = inheritable_security_attributes();

    unsafe {
        CreatePipe(&mut read, &mut write, Some(&security_attributes), 0).map_err(|error| {
            crate::error::Error::FfiError(format!("CreatePipe failed: {error}"))
        })?;
    }

    Ok((
        OwnedWindowsHandle::new(read, read_label)?,
        OwnedWindowsHandle::new(write, write_label)?,
    ))
}

#[cfg(target_os = "windows")]
fn duplicate_std_handle(
    std_handle: windows::Win32::System::Console::STD_HANDLE,
    label: &'static str,
) -> crate::error::Result<OwnedWindowsHandle> {
    let source = unsafe { GetStdHandle(std_handle) }
        .map_err(|error| crate::error::Error::FfiError(format!("GetStdHandle failed: {error}")))?;
    let current_process = unsafe { GetCurrentProcess() };
    let mut target = HANDLE::default();

    unsafe {
        DuplicateHandle(
            current_process,
            source,
            current_process,
            &mut target,
            0,
            BOOL(1),
            DUPLICATE_SAME_ACCESS,
        )
        .map_err(|error| {
            crate::error::Error::FfiError(format!("DuplicateHandle for {label} failed: {error}"))
        })?;
    }

    OwnedWindowsHandle::new(target, label)
}

#[cfg(target_os = "windows")]
fn open_nul(access: u32, label: &'static str) -> crate::error::Result<OwnedWindowsHandle> {
    let name = wide_null("NUL");
    let security_attributes = inheritable_security_attributes();
    let handle = unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(&security_attributes),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )
        .map_err(|error| {
            crate::error::Error::FfiError(format!("CreateFileW for {label} failed: {error}"))
        })?
    };

    OwnedWindowsHandle::new(handle, label)
}

#[cfg(target_os = "windows")]
fn make_not_inheritable(handle: HANDLE, label: &'static str) -> crate::error::Result<()> {
    unsafe {
        SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)).map_err(|error| {
            crate::error::Error::FfiError(format!(
                "SetHandleInformation for {label} failed: {error}"
            ))
        })
    }
}

#[cfg(target_os = "windows")]
fn inheritable_security_attributes() -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: BOOL(1),
    }
}

#[cfg(target_os = "windows")]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn wide_path(path: &std::path::Path) -> crate::error::Result<Vec<u16>> {
    let encoded = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    if encoded[..encoded.len().saturating_sub(1)]
        .iter()
        .any(|unit| *unit == 0)
    {
        return Err(crate::error::Error::ConfigError(format!(
            "current directory contains interior NUL: {}",
            path.display()
        )));
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::{
        allowed_environment_from, command_line, environment_block_from, quote_arg,
        validate_command_parts,
    };

    #[test]
    fn command_line_quotes_spaces_and_quotes() {
        let args = ["-c".to_string(), "print(\"hi\")".to_string()];

        assert_eq!(
            command_line("C:/Program Files/Python/python.exe", &args),
            "\"C:/Program Files/Python/python.exe\" -c \"print(\\\"hi\\\")\""
        );
    }

    #[test]
    fn quote_arg_quotes_empty_arguments() {
        assert_eq!(quote_arg(""), "\"\"");
    }

    #[test]
    fn quote_arg_preserves_trailing_backslashes_before_closing_quote() {
        assert_eq!(
            quote_arg(r"C:\Program Files\Python\"),
            r#""C:\Program Files\Python\\""#
        );
    }

    #[test]
    fn environment_block_merges_parent_and_overlay_and_double_terminates() {
        let parent = [
            ("PATH".to_string(), "C:\\Windows\\System32".to_string()),
            ("HEEL_KEEP".to_string(), "parent".to_string()),
        ];
        let overlay = [
            ("PATH".to_string(), "C:\\Heel\\bin".to_string()),
            ("HEEL_NEW".to_string(), "overlay".to_string()),
        ];

        let block = environment_block_from(parent, &overlay).expect("environment block");
        let decoded = String::from_utf16(&block).expect("utf16 env block");
        let entries = decoded
            .trim_end_matches('\0')
            .split('\0')
            .collect::<Vec<_>>();

        assert!(entries.contains(&"HEEL_KEEP=parent"));
        assert!(entries.contains(&"HEEL_NEW=overlay"));
        assert!(entries.contains(&"PATH=C:\\Heel\\bin"));
        assert!(!entries.contains(&"PATH=C:\\Windows\\System32"));
        assert!(block.ends_with(&[0, 0]));
    }

    #[test]
    fn environment_block_double_terminates_empty_blocks() {
        let block = environment_block_from([], &[]).expect("environment block");

        assert_eq!(block, vec![0, 0]);
    }

    #[test]
    fn environment_block_rejects_empty_or_assignment_keys() {
        let empty_key = environment_block_from([("".to_string(), "value".to_string())], &[])
            .expect_err("empty key should be rejected");
        assert!(empty_key.to_string().contains("environment key"));

        let assignment_key =
            environment_block_from([("A=B".to_string(), "value".to_string())], &[])
                .expect_err("assignment-like key should be rejected");
        assert!(assignment_key.to_string().contains("environment key"));
    }

    #[test]
    fn environment_block_rejects_interior_nuls() {
        let key_err = environment_block_from([("A\0B".to_string(), "value".to_string())], &[])
            .expect_err("nul in key should be rejected");
        assert!(key_err.to_string().contains("interior NUL"));

        let value_err = environment_block_from([("A".to_string(), "x\0y".to_string())], &[])
            .expect_err("nul in value should be rejected");
        assert!(value_err.to_string().contains("interior NUL"));
    }

    #[test]
    fn command_parts_reject_interior_nuls_before_windows_encoding() {
        let program_err =
            validate_command_parts("cmd\0.exe", &[]).expect_err("program nul should fail");
        assert!(program_err.to_string().contains("interior NUL"));

        let args = ["ok".to_string(), "bad\0arg".to_string()];
        let arg_err = validate_command_parts("cmd.exe", &args).expect_err("arg nul should fail");
        assert!(arg_err.to_string().contains("interior NUL"));
    }

    #[test]
    fn allowed_environment_uses_runtime_allowlist_and_passthrough_only() {
        let parent = [
            ("PATH".to_string(), "C:\\Windows\\System32".to_string()),
            ("SystemRoot".to_string(), "C:\\Windows".to_string()),
            ("HEEL_KEEP".to_string(), "explicit".to_string()),
            ("SECRET_TOKEN".to_string(), "do-not-copy".to_string()),
        ];
        let passthrough = ["HEEL_KEEP".to_string()];

        let allowed = allowed_environment_from(parent, &passthrough).expect("allowed environment");

        assert!(allowed.iter().any(|(key, _)| key == "PATH"));
        assert!(allowed.iter().any(|(key, _)| key == "SystemRoot"));
        assert!(allowed.iter().any(|(key, _)| key == "HEEL_KEEP"));
        assert!(!allowed.iter().any(|(key, _)| key == "SECRET_TOKEN"));
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::{
        AppContainerLaunchState, WindowsLaunch, appcontainer_security_capabilities,
        launch_appcontainer_process,
    };
    use crate::error::Result;
    use crate::platform::Child;
    use windows::Win32::Security::PSID;

    #[test]
    fn appcontainer_launch_process_takes_owned_state() {
        let _launch_fn: for<'a> fn(WindowsLaunch<'a>, AppContainerLaunchState) -> Result<Child> =
            launch_appcontainer_process;
    }

    #[test]
    fn appcontainer_security_capabilities_grant_no_network_capabilities() {
        let capabilities = appcontainer_security_capabilities(PSID::default());

        assert!(capabilities.AppContainerSid.is_invalid());
        assert!(capabilities.Capabilities.is_null());
        assert_eq!(capabilities.CapabilityCount, 0);
    }
}
