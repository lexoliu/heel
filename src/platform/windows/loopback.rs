//! The loopback exemption a filtering sandbox needs.
//!
//! AppContainers cannot open loopback connections without an exemption, and
//! the proxy is a loopback listener, so every filtering policy depends on
//! this. The exemption is machine-wide and keyed on the container SID: adding
//! it reads the firewall's table, inserts the SID when absent and writes it
//! back. An ephemeral container holds a guard that removes the exemption on
//! drop; a named identity retains it until the identity is removed.
//!
//! The read-modify-write is not atomic — two sandboxes launched at the same
//! moment can lose one another's entries — but it is a line in a shared table
//! that the machine already races on, and a lost entry fails the sandbox it
//! belonged to rather than corrupting the table.

use std::io;

use windows::Win32::NetworkManagement::WindowsFirewall::{
    NetworkIsolationGetAppContainerConfig, NetworkIsolationSetAppContainerConfig,
};
use windows::Win32::Security::{EqualSid, SID_AND_ATTRIBUTES};
use windows::Win32::System::Memory::{GetProcessHeap, HEAP_FLAGS, HeapFree};

use super::sid::Sid;

/// The firewall's loopback exemption table, read into a guard that releases
/// it.
///
/// `NetworkIsolationGetAppContainerConfig` hands out process-heap memory —
/// each entry's `Sid` is a separate allocation and so is the array. The
/// function's documentation says "it is the calling program's responsibility
/// to free the memory associated with the PSID_AND_ATTRIBUTES structure", and
/// the `FreeAppContainerConfig` example it gives releases every `Sid` and
/// then the array with `HeapFree` on the process heap — what `Drop` does
/// below.
struct Config {
    /// The number of entries in `entries`.
    count: u32,
    /// The table, or null when it is empty.
    entries: *mut SID_AND_ATTRIBUTES,
}

impl Config {
    /// Read the current table.
    fn get() -> io::Result<Self> {
        let mut count = 0;
        let mut entries = std::ptr::null_mut();
        // SAFETY: both out-parameters are valid destinations.
        let status = unsafe { NetworkIsolationGetAppContainerConfig(&mut count, &mut entries) };
        if status != 0 {
            return Err(io::Error::other(format!(
                "NetworkIsolationGetAppContainerConfig failed: {}",
                io::Error::from_raw_os_error(status.cast_signed())
            )));
        }
        Ok(Self { count, entries })
    }

    /// The table's rows.
    fn entries(&self) -> &[SID_AND_ATTRIBUTES] {
        if self.entries.is_null() {
            &[]
        } else {
            // SAFETY: `entries` names `count` valid rows until the guard drops.
            unsafe { std::slice::from_raw_parts(self.entries, self.count as usize) }
        }
    }

    /// Write `entries` back as the table.
    fn set(entries: &[SID_AND_ATTRIBUTES]) -> io::Result<()> {
        // SAFETY: `entries` is a valid slice; the call copies it synchronously,
        // so the pointers its rows carry need only outlive this call.
        let status = unsafe { NetworkIsolationSetAppContainerConfig(entries) };
        if status != 0 {
            return Err(io::Error::other(format!(
                "NetworkIsolationSetAppContainerConfig failed: {}",
                io::Error::from_raw_os_error(status.cast_signed())
            )));
        }
        Ok(())
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        if self.entries.is_null() {
            return;
        }
        // SAFETY: `entries` came from `NetworkIsolationGetAppContainerConfig`,
        // and its documented release is `HeapFree` on the process heap for
        // each `Sid` and then the array; each is freed exactly once here.
        unsafe {
            if let Ok(heap) = GetProcessHeap() {
                for entry in self.entries() {
                    let _ = HeapFree(heap, HEAP_FLAGS(0), Some(entry.Sid.0.cast_const()));
                }
                let _ = HeapFree(heap, HEAP_FLAGS(0), Some(self.entries.cast_const().cast()));
            }
        }
    }
}

/// An ephemeral container's loopback exemption, withdrawn on drop.
#[derive(Debug)]
pub(crate) struct LoopbackExemption {
    /// The container's package SID, kept to remove on drop.
    sid: Sid,
}

impl LoopbackExemption {
    /// Add `sid` to the firewall's loopback table, unless it is already there.
    pub(crate) fn add(sid: Sid) -> io::Result<Self> {
        Self::ensure(&sid)?;
        Ok(Self { sid })
    }

    /// Ensure `sid` stays in the firewall's loopback table.
    pub(crate) fn ensure(sid: &Sid) -> io::Result<()> {
        Self::update(sid, true)
    }

    /// Remove `sid` from the firewall's loopback table.
    pub(crate) fn remove_persistent(sid: &Sid) -> io::Result<()> {
        Self::update(sid, false)
    }

    fn update(sid: &Sid, present: bool) -> io::Result<()> {
        let config = Config::get()?;
        let ours = sid.as_psid();
        let mut entries = config.entries().to_vec();
        let had_entry = entries.iter().any(|entry|
            // SAFETY: both arguments are valid SIDs for the call.
            unsafe { EqualSid(entry.Sid, ours) }.is_ok());

        if present && !had_entry {
            entries.push(SID_AND_ATTRIBUTES {
                Sid: ours,
                Attributes: 0,
            });
        } else if !present && had_entry {
            entries.retain(|entry|
                // SAFETY: both arguments are valid SIDs for the call.
                unsafe { EqualSid(entry.Sid, ours) }.is_err());
        } else {
            return Ok(());
        }
        Config::set(&entries)
    }

    /// Take the SID back out of the table.
    fn remove(&self) -> io::Result<()> {
        Self::remove_persistent(&self.sid)
    }
}

impl Drop for LoopbackExemption {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            tracing::warn!(%error, "failed to remove the loopback exemption");
        }
    }
}
