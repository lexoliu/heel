//! Process launch into the AppContainer with `STARTUPINFOEX` attributes.
//!
//! `CreateProcessW` cannot be driven through `std::process::Command`: the
//! container assignment, the job the process joins at creation and the exact
//! set of handles it inherits all live in a `PROC_THREAD_ATTRIBUTE_LIST` that
//! `Command` does not expose.
//!
//! Three of those attributes matter to a sandbox. The security capabilities
//! name the package SID — and, when the process may reach the proxy, the
//! `internetClient` capability — and Windows 11 on ARM64 rejects a non-null
//! pointer to an empty capability array, so the struct is built from an
//! `Option` whose `None` writes null by construction. The job list assigns
//! the child to the job at creation, so no child or grandchild ever runs
//! outside the sandbox's limits or at normal priority. And the handle list
//! inherits exactly the std handles the launch asked for — nothing else the
//! parent happens to hold open leaks into the container.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;

use windows::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS,
    SetHandleInformation,
};
use windows::Win32::Security::{SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows::Win32::System::SystemServices::SE_GROUP_ENABLED;
use windows::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
    UpdateProcThreadAttribute,
};
use windows::core::{PCWSTR, PWSTR};

use super::sid::Sid;
use super::{Win32Failure, priority, wide};
use crate::priority::ProcessPriority;

/// A launch-prep result; the failure names the call that produced it.
type Result<T> = std::result::Result<T, Win32Failure>;

/// How the child's three standard streams are wired.
///
/// One mode covers all three: every caller asks for the same thing on all of
/// them, so the launcher takes a single value.
#[derive(Clone, Copy, Debug)]
pub(super) enum Stdio {
    /// The parent's own handles, duplicated inheritable.
    Inherit,
    /// The null device.
    Null,
    /// Anonymous pipes; the parent's ends come back in [`Launched`].
    Pipe,
}

/// Everything one launch needs, assembled before the process starts.
pub(super) struct Launch<'a> {
    /// The container's package SID.
    pub(super) package: &'a Sid,
    /// `internetClient`, when the process may reach the proxy.
    pub(super) capability: Option<&'a Sid>,
    /// Program to run.
    pub(super) exe: PathBuf,
    /// The command line the process sees.
    pub(super) cmdline: String,
    /// The directory the process starts in.
    pub(super) cwd: PathBuf,
    /// The complete environment; a container never inherits the parent's.
    pub(super) env: Vec<(OsString, OsString)>,
    /// How the three standard streams are wired.
    pub(super) stdio: Stdio,
    /// Per-process memory limit for the job, in bytes.
    pub(super) memory_bytes: Option<usize>,
    /// The priority the job runs at.
    pub(super) priority: ProcessPriority,
}

/// A launched process and the handles the parent keeps.
#[derive(Debug)]
pub(crate) struct Launched {
    /// The process identifier.
    pub(crate) pid: u32,
    /// The process itself, for waiting and exit codes.
    pub(crate) process: OwnedHandle,
    /// The job the process was assigned to at creation: kill-on-close, so
    /// dropping this handle ends the whole tree.
    pub(crate) job: OwnedHandle,
    /// The parent's ends of the pipes, when `Stdio::Pipe` was asked for.
    pub(crate) stdin: Option<File>,
    /// Same, for standard output.
    pub(crate) stdout: Option<File>,
    /// Same, for standard error.
    pub(crate) stderr: Option<File>,
}

/// The `SECURITY_CAPABILITIES` value for one launch, and the capability entry
/// it points at.
///
/// The entry lives on the heap so the pointer survives wherever the value
/// goes between `UpdateProcThreadAttribute` and `CreateProcessW`. `None`
/// writes a null `Capabilities` and a zero count by construction — Windows 11
/// ARM64 rejects a non-null pointer to an empty array with
/// `ERROR_INVALID_PARAMETER`.
#[derive(Debug)]
pub(super) struct SecurityCapabilities {
    /// The capability entry the struct points into, when there is one. The
    /// box keeps its address stable through moves; production code only holds
    /// it for ownership, while the tests assert its contents.
    pub(super) _entry: Box<Option<SID_AND_ATTRIBUTES>>,
    /// The struct as the attribute list passes it.
    pub(super) value: SECURITY_CAPABILITIES,
}

impl SecurityCapabilities {
    /// Build the capabilities for `package`, carrying `capability` when given.
    pub(super) fn new(package: &Sid, capability: Option<&Sid>) -> Self {
        let mut entry = Box::new(capability.map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.as_psid(),
            Attributes: SE_GROUP_ENABLED as u32,
        }));
        let (array, count) = match entry.as_mut() {
            Some(entry) => (std::ptr::from_mut(entry), 1),
            None => (std::ptr::null_mut(), 0),
        };
        let value = SECURITY_CAPABILITIES {
            AppContainerSid: package.as_psid(),
            Capabilities: array,
            CapabilityCount: count,
            Reserved: 0,
        };
        Self {
            _entry: entry,
            value,
        }
    }
}

/// An initialized `PROC_THREAD_ATTRIBUTE_LIST`, deleted on drop.
struct AttributeList {
    /// The buffer the list lives in, pointer-aligned as the kernel structure
    /// requires; kept for ownership alone.
    _storage: Vec<usize>,
    /// The list itself.
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl AttributeList {
    /// Allocate a list with room for `count` attributes.
    fn new(count: u32) -> Result<Self> {
        let mut bytes = 0usize;
        // SAFETY: a null list with a valid size out-parameter asks for the
        // required size without writing anything.
        let _ = unsafe { InitializeProcThreadAttributeList(None, count, None, &mut bytes) };
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        let pointer = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        // SAFETY: `storage` is exactly the buffer the sizing call described,
        // and it is not used for anything else.
        unsafe { InitializeProcThreadAttributeList(Some(pointer), count, None, &mut bytes) }
            .map_err(Win32Failure::call("InitializeProcThreadAttributeList"))?;
        Ok(Self {
            _storage: storage,
            pointer,
        })
    }

    /// Add an attribute whose value is the `size` bytes at `pointer`.
    ///
    /// `pointer` must stay valid until `CreateProcessW` has run.
    fn set(
        &mut self,
        attribute: u32,
        pointer: *const core::ffi::c_void,
        size: usize,
    ) -> Result<()> {
        // SAFETY: the list is initialized, and the caller keeps `pointer`'s
        // target alive through `CreateProcessW`.
        unsafe {
            UpdateProcThreadAttribute(
                self.pointer,
                0,
                attribute as usize,
                Some(pointer),
                size,
                None,
                None,
            )
        }
        .map_err(|source| Win32Failure::call("UpdateProcThreadAttribute")(source))
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: the list was initialized in `new` and is deleted exactly once.
        unsafe { DeleteProcThreadAttributeList(self.pointer) };
    }
}

/// The std handles one launch hands to its child, and the parent's ends of
/// any pipes.
struct StdHandles {
    /// The parent's ends of the pipes — `Some` only under `Stdio::Pipe`, in
    /// stdin/stdout/stderr order.
    parent: [Option<File>; 3],
    /// The child's std handles in the same order — `None` where there is
    /// nothing to pass.
    child: [Option<OwnedHandle>; 3],
}

/// Launch the process `launch` describes inside its container.
///
/// The job exists before the process does — carrying the memory limit, the
/// kill-on-close flag and the lowered priority — and the child is assigned to
/// it by `PROC_THREAD_ATTRIBUTE_JOB_LIST` at creation, so there is no window
/// where the child or a grandchild runs outside the job or at normal
/// priority.
pub(super) fn launch(launch: &Launch<'_>) -> Result<Launched> {
    let environment = environment_block(&launch.env)?;

    let job = create_job(launch.memory_bytes)?;
    if !launch.priority.is_normal() {
        priority::apply(HANDLE(job.as_raw_handle()), launch.priority)?;
    }

    let stdio = std_handles(launch.stdio)?;
    let mut child = [HANDLE::default(); 3];
    let mut inherited = Vec::with_capacity(3);
    for (slot, handle) in child.iter_mut().zip(&stdio.child) {
        *slot = handle
            .as_ref()
            .map_or(HANDLE::default(), |h| HANDLE(h.as_raw_handle()));
        if let Some(handle) = handle {
            inherited.push(HANDLE(handle.as_raw_handle()));
        }
    }

    let capabilities = SecurityCapabilities::new(launch.package, launch.capability);
    let job_handle = HANDLE(job.as_raw_handle());

    let mut attributes = AttributeList::new(2 + u32::from(!inherited.is_empty()))?;
    attributes.set(
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        (&raw const capabilities.value).cast(),
        size_of::<SECURITY_CAPABILITIES>(),
    )?;
    attributes.set(
        PROC_THREAD_ATTRIBUTE_JOB_LIST,
        (&raw const job_handle).cast(),
        size_of::<HANDLE>(),
    )?;
    if !inherited.is_empty() {
        attributes.set(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited.as_ptr().cast(),
            std::mem::size_of_val(inherited.as_slice()),
        )?;
    }

    let mut startup = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: size_of::<STARTUPINFOEXW>() as u32,
            ..Default::default()
        },
        lpAttributeList: attributes.pointer,
    };
    startup.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = child[0];
    startup.StartupInfo.hStdOutput = child[1];
    startup.StartupInfo.hStdError = child[2];

    let exe = wide(&launch.exe);
    let mut command = wide(&launch.cmdline);
    let cwd = wide(&launch.cwd);
    let mut information = PROCESS_INFORMATION::default();

    // SAFETY: every buffer the call reads — the strings, the environment
    // block, the attribute list and everything the attributes point at — is
    // alive in this frame until the call returns. The returned handles are
    // adopted exactly once below; the child ends in `stdio.child` are dropped
    // when the function returns, which closes the parent's copies.
    unsafe {
        CreateProcessW(
            PCWSTR(exe.as_ptr()),
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            !inherited.is_empty(),
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            Some(environment.as_ptr().cast()),
            PCWSTR(cwd.as_ptr()),
            (&raw const startup).cast::<STARTUPINFOW>(),
            &mut information,
        )
    }
    .map_err(Win32Failure::call("CreateProcessW"))?;

    // The thread handle is not used; the process handle belongs to the child.
    // SAFETY: both are valid handles the call just returned.
    drop(unsafe { OwnedHandle::from_raw_handle(information.hThread.0) });
    // SAFETY: as above.
    let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess.0) };

    let [stdin, stdout, stderr] = stdio.parent;
    Ok(Launched {
        pid: information.dwProcessId,
        process,
        job,
        stdin,
        stdout,
        stderr,
    })
}

/// Create the job the child joins at creation, carrying the sandbox's limits.
fn create_job(memory_bytes: Option<usize>) -> Result<OwnedHandle> {
    // SAFETY: anonymous job with default security; the returned handle is ours.
    let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
        .map_err(Win32Failure::call("CreateJobObjectW"))?;
    // SAFETY: the call just returned it, and ownership moves to the guard.
    let job = unsafe { OwnedHandle::from_raw_handle(job.0) };

    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    // The sandbox owns the tree: when the job closes, it goes.
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if let Some(bytes) = memory_bytes {
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        info.ProcessMemoryLimit = bytes;
    }

    // SAFETY: `info` is a correctly sized, initialized value of the
    // information class named alongside it.
    unsafe {
        SetInformationJobObject(
            HANDLE(job.as_raw_handle()),
            JobObjectExtendedLimitInformation,
            (&raw const info).cast(),
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).map_err(|source| {
                Win32Failure::Invalid(format!("job limit structure is too large: {source}"))
            })?,
        )
    }
    .map_err(Win32Failure::call("SetInformationJobObject"))?;
    Ok(job)
}

/// Build the std handles `mode` asks for.
fn std_handles(mode: Stdio) -> Result<StdHandles> {
    match mode {
        Stdio::Null => null_handles(),
        Stdio::Inherit => inherited_handles(),
        Stdio::Pipe => piped_handles(),
    }
}

/// Open the null device three times: once to read, twice to write.
fn null_handles() -> Result<StdHandles> {
    let open = |access: u32| -> Result<OwnedHandle> {
        let path = wide("\\\\.\\NUL");
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: true.into(),
        };
        // SAFETY: `path` is NUL-terminated and `attributes` outlives the call.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                Some(&raw const attributes),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map_err(Win32Failure::call("CreateFileW(NUL)"))?;
        // SAFETY: the call just returned the handle, which the guard now owns.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle.0) })
    };

    Ok(StdHandles {
        parent: [None, None, None],
        child: [
            Some(open(FILE_GENERIC_READ.0)?),
            Some(open(FILE_GENERIC_WRITE.0)?),
            Some(open(FILE_GENERIC_WRITE.0)?),
        ],
    })
}

/// Duplicate the parent's own std handles as inheritable copies.
///
/// A parent without a handle — a GUI process has no console — gets `None`,
/// which is passed to the child as a null handle rather than failing.
fn inherited_handles() -> Result<StdHandles> {
    fn duplicate(which: STD_HANDLE) -> Result<Option<OwnedHandle>> {
        // SAFETY: `which` is a valid std-handle selector.
        let source = match unsafe { GetStdHandle(which) } {
            Ok(handle) if !handle.is_invalid() => handle,
            _ => return Ok(None),
        };
        let mut target = HANDLE::default();
        // SAFETY: `source` is the process's own valid std handle, and the
        // copy is inheritable for the child.
        unsafe {
            let current = GetCurrentProcess();
            DuplicateHandle(
                current,
                source,
                current,
                &mut target,
                0,
                true,
                DUPLICATE_SAME_ACCESS,
            )
        }
        .map_err(Win32Failure::call("DuplicateHandle"))?;
        // SAFETY: the call just wrote the handle, which the guard now owns.
        Ok(Some(unsafe { OwnedHandle::from_raw_handle(target.0) }))
    }

    Ok(StdHandles {
        parent: [None, None, None],
        child: [
            duplicate(STD_INPUT_HANDLE)?,
            duplicate(STD_OUTPUT_HANDLE)?,
            duplicate(STD_ERROR_HANDLE)?,
        ],
    })
}

/// Create three anonymous pipes; the child ends are inheritable, the parent's
/// are not.
fn piped_handles() -> Result<StdHandles> {
    fn pipe() -> Result<(OwnedHandle, OwnedHandle)> {
        let (reader, writer) = std::io::pipe().map_err(Win32Failure::io("std::io::pipe"))?;
        Ok((reader.into(), writer.into()))
    }
    fn mark(handle: &OwnedHandle, inheritable: bool) -> Result<()> {
        // SAFETY: the handle is open and only its inherit flag is changed.
        unsafe {
            SetHandleInformation(
                HANDLE(handle.as_raw_handle()),
                HANDLE_FLAG_INHERIT.0,
                if inheritable {
                    HANDLE_FLAG_INHERIT
                } else {
                    HANDLE_FLAGS(0)
                },
            )
        }
        .map_err(Win32Failure::call("SetHandleInformation"))
    }

    let (child_stdin, parent_stdin) = pipe()?;
    let (parent_stdout, child_stdout) = pipe()?;
    let (parent_stderr, child_stderr) = pipe()?;

    mark(&child_stdin, true)?;
    mark(&child_stdout, true)?;
    mark(&child_stderr, true)?;
    mark(&parent_stdin, false)?;
    mark(&parent_stdout, false)?;
    mark(&parent_stderr, false)?;

    Ok(StdHandles {
        parent: [
            Some(File::from(parent_stdin)),
            Some(File::from(parent_stdout)),
            Some(File::from(parent_stderr)),
        ],
        child: [Some(child_stdin), Some(child_stdout), Some(child_stderr)],
    })
}

/// The environment block `CreateProcessW` reads: `NAME=VALUE` strings joined
/// by NULs, terminated by a second one.
fn environment_block(env: &[(OsString, OsString)]) -> Result<Vec<u16>> {
    let mut block = Vec::new();
    for (name, value) in env {
        check_entry(name, value)?;
        block.extend(name.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    // An empty block is still NUL-terminated twice — the format's final
    // terminator follows the last entry's own.
    if env.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

/// Reject what would corrupt the block before `CreateProcessW` sees it.
///
/// `CreateProcessW` reports a malformed block as `ERROR_ENVVAR_NOT_FOUND`,
/// which names no entry, so the entries are checked here instead.
fn check_entry(name: &OsStr, value: &OsStr) -> Result<()> {
    let name_wide: Vec<u16> = name.encode_wide().collect();
    if name_wide.is_empty() {
        return Err(Win32Failure::Invalid(
            "the launch environment has an entry with an empty name".to_string(),
        ));
    }
    // `=` is the name/value separator, so one inside the name would end it
    // early. Windows tolerates a leading `=` — `=C:` names a drive's private
    // variable — so only a `=` past the first character is rejected.
    if name_wide[1..].contains(&u16::from(b'=')) {
        return Err(Win32Failure::Invalid(format!(
            "the launch environment name {} contains `=`",
            name.to_string_lossy()
        )));
    }
    for (what, text) in [("name", name), ("value", value)] {
        if text.encode_wide().any(|unit| unit == 0) {
            return Err(Win32Failure::Invalid(format!(
                "the launch environment {what} for {} contains a NUL",
                name.to_string_lossy()
            )));
        }
    }
    Ok(())
}
