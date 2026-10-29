//! The slice of `/proc` the supervisor reads.

use std::io;

/// One process, as `/proc/<pid>/stat` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) pid: u32,
    pub(crate) ppid: u32,
    /// The kernel's state letter; `Z` is a zombie.
    pub(crate) state: char,
    /// `comm`: the executable name, at most 15 bytes, lossily decoded.
    pub(crate) name: String,
}

impl Entry {
    pub(crate) fn is_zombie(&self) -> bool {
        self.state == 'Z'
    }

    /// Parse the contents of `/proc/<pid>/stat`.
    ///
    /// `comm` is arbitrary bytes between parentheses and may itself contain
    /// spaces and parentheses, so the closing one is the *last* in the line.
    pub(crate) fn parse(stat: &[u8]) -> Option<Self> {
        let open = stat.iter().position(|&byte| byte == b'(')?;
        let close = stat.iter().rposition(|&byte| byte == b')')?;
        let pid = std::str::from_utf8(stat.get(..open)?)
            .ok()?
            .trim()
            .parse()
            .ok()?;
        let name = String::from_utf8_lossy(stat.get(open + 1..close)?).into_owned();
        let rest = std::str::from_utf8(stat.get(close + 1..)?).ok()?;
        let mut fields = rest.split_ascii_whitespace();
        let state = fields.next()?.chars().next()?;
        let ppid = fields.next()?.parse().ok()?;
        Some(Self {
            pid,
            ppid,
            state,
            name,
        })
    }
}

/// Read one process, or `None` when it no longer exists.
pub(crate) fn read(pid: u32) -> io::Result<Option<Entry>> {
    match std::fs::read(format!("/proc/{pid}/stat")) {
        Ok(stat) => Entry::parse(&stat).map(Some).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unreadable /proc/{pid}/stat"),
            )
        }),
        // A process can exit between listing `/proc` and reading it; reading a
        // process that is being torn down fails with ESRCH.
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ESRCH) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Every process the kernel lists right now.
pub(crate) fn snapshot() -> io::Result<Vec<Entry>> {
    let mut table = Vec::new();
    for listed in std::fs::read_dir("/proc")? {
        let name = listed?.file_name();
        let Some(pid) = name.to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };
        if let Some(entry) = read(pid)? {
            table.push(entry);
        }
    }
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_plain_line() {
        let entry = Entry::parse(b"42 (sleep) S 7 42 42 0 -1 4194304 100").unwrap();
        assert_eq!(
            entry,
            Entry {
                pid: 42,
                ppid: 7,
                state: 'S',
                name: "sleep".into()
            }
        );
    }

    #[test]
    fn a_name_with_spaces_and_parentheses_does_not_shift_the_fields() {
        let entry = Entry::parse(b"9 (a) b (c) Z 3 9 9 0").unwrap();
        assert_eq!(entry.name, "a) b (c");
        assert_eq!(entry.state, 'Z');
        assert!(entry.is_zombie());
        assert_eq!(entry.ppid, 3);
    }

    #[test]
    fn a_truncated_line_is_refused() {
        assert!(Entry::parse(b"9 (a) S").is_none());
        assert!(Entry::parse(b"nonsense").is_none());
    }

    #[test]
    fn this_process_is_listed() {
        let me = std::process::id();
        let entry = read(me).unwrap().unwrap();
        assert_eq!(entry.pid, me);
        assert!(snapshot().unwrap().iter().any(|listed| listed.pid == me));
    }
}
