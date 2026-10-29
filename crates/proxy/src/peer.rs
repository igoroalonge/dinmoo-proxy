//! Ownership checks for local SOCKS peers before the voice bridge reveals its certificate.
//! Chromium accepts the pinned voice key for any host, so only the user's own processes may
//! see it. macOS also requires the owner to run from Discord.app; that is only a path check,
//! which a same-user process able to start a bundle binary with an inherited socket gets around.
//! The CLI uses the same lookups, reversed, to confirm that it pins Discord to this user's proxy.
use std::net::SocketAddr;
#[cfg(any(target_os = "macos", test))]
use std::path::{Component, Path};

type Check<T = ()> = std::result::Result<T, String>;

/// `peer` is the connecting app's address and `local` our listener's. Fails closed.
pub async fn verify_voice_peer(peer: SocketAddr, local: SocketAddr) -> bool {
    let reason = match tokio::task::spawn_blocking(move || check(peer, local)).await {
        Ok(Ok(())) => return true,
        Ok(Err(reason)) => reason,
        Err(error) => format!("lookup task failed: {error}"),
    };
    eprintln!("voice bridge refused local peer {peer}: {reason}");
    false
}

fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

fn single<T: Copy>(owners: &[T]) -> Check<T> {
    match owners {
        [owner] => Ok(*owner),
        [] => Err("no local socket matches the connection".into()),
        _ => Err(format!(
            "{} local sockets match the connection",
            owners.len()
        )),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The socket whose local end is `peer` and remote end `local` belongs to this user.
#[cfg(target_os = "linux")]
pub(crate) fn verify_owner(peer: SocketAddr, local: SocketAddr) -> Check {
    let uid = linux::peer_uid(peer, local)?;
    if uid != effective_uid() {
        return Err(format!("socket belongs to uid {uid}"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn verify_owner(peer: SocketAddr, local: SocketAddr) -> Check {
    owner_pid(peer, local).map(drop)
}

#[cfg(windows)]
pub(crate) fn verify_owner(peer: SocketAddr, local: SocketAddr) -> Check {
    let (pid, created) = windows::peer_socket(peer, local)?;
    windows::same_user(pid, created)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) fn verify_owner(_peer: SocketAddr, _local: SocketAddr) -> Check {
    Err("peer ownership checks are unsupported on this OS".into())
}

#[cfg(target_os = "macos")]
fn owner_pid(peer: SocketAddr, local: SocketAddr) -> Check<libc::pid_t> {
    let pid = macos::peer_pid(peer, local)?;
    let uid = macos::process_uid(pid)?;
    if uid != effective_uid() {
        return Err(format!("process {pid} runs as uid {uid}"));
    }
    Ok(pid)
}

#[cfg(not(target_os = "macos"))]
fn check(peer: SocketAddr, local: SocketAddr) -> Check {
    verify_owner(peer, local)
}

#[cfg(target_os = "macos")]
fn check(peer: SocketAddr, local: SocketAddr) -> Check {
    let pid = owner_pid(peer, local)?;
    trusted_discord(&macos::executable(pid)?).map_err(|reason| format!("process {pid}: {reason}"))
}

/// `executable` runs from a Discord.app the voice peer check accepts.
#[cfg(target_os = "macos")]
pub(crate) fn trusted_discord(executable: &Path) -> Check {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    discord_executable(executable, home.as_deref())
}

/// Owner uids of `/proc/net/tcp{,6}` rows whose local end is `peer` and remote end `local`.
#[cfg(any(target_os = "linux", test))]
fn proc_net_owners(table: &str, peer: SocketAddr, local: SocketAddr) -> Check<Vec<u32>> {
    fn address(field: &str) -> Option<SocketAddr> {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let (ip, port) = field.split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        // The kernel prints each raw network-order 32-bit word with %08X.
        let mut words = ip.as_bytes().chunks(8).map(|word| {
            let word = std::str::from_utf8(word).ok()?;
            Some(u32::from_str_radix(word, 16).ok()?.to_ne_bytes())
        });
        let ip = match ip.len() {
            8 => Ipv4Addr::from(words.next()??).into(),
            32 => {
                let mut bytes = [0; 16];
                for chunk in bytes.chunks_exact_mut(4) {
                    chunk.copy_from_slice(&words.next()??);
                }
                Ipv6Addr::from(bytes).into()
            }
            _ => return None,
        };
        Some(canonical(SocketAddr::new(ip, port)))
    }
    let (peer, local) = (canonical(peer), canonical(local));
    let mut owners = Vec::new();
    for row in table.lines().skip(1) {
        let columns: Vec<&str> = row.split_whitespace().collect();
        let (Some(source), Some(destination)) = (
            columns.get(1).and_then(|field| address(field)),
            columns.get(2).and_then(|field| address(field)),
        ) else {
            return Err(format!("unexpected socket table row: {row:?}"));
        };
        if source == peer && destination == local {
            let uid = columns.get(7).and_then(|uid| uid.parse().ok());
            owners.push(uid.ok_or_else(|| format!("unexpected socket table row: {row:?}"))?);
        }
    }
    Ok(owners)
}

/// Byte layout of MIB_TCPTABLE_OWNER_MODULE, asserted against windows-sys on Windows: a u32 row
/// count, then 8-byte aligned rows.
#[cfg(any(windows, test))]
mod owner_module {
    pub(super) const TABLE: usize = 8;
    pub(super) const ROW: usize = 160;
    pub(super) const LOCAL_ADDR: usize = 4;
    pub(super) const LOCAL_PORT: usize = 8;
    pub(super) const REMOTE_ADDR: usize = 12;
    pub(super) const REMOTE_PORT: usize = 16;
    pub(super) const OWNING_PID: usize = 20;
    pub(super) const CREATE_TIMESTAMP: usize = 24;
}

/// (owning pid, socket creation FILETIME) of rows whose local end is `peer` and remote end `local`.
#[cfg(any(windows, test))]
fn owner_module_rows(
    table: &[u8],
    peer: std::net::SocketAddrV4,
    local: std::net::SocketAddrV4,
) -> Check<Vec<(u32, i64)>> {
    use owner_module::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    fn at<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
        let mut value = [0; N];
        value.copy_from_slice(&bytes[offset..offset + N]);
        value
    }
    let count = table.get(..4).ok_or("empty TCP table")?;
    let count = u32::from_ne_bytes(at(count, 0)) as usize;
    let rows = count
        .checked_mul(ROW)
        .and_then(|len| table.get(TABLE..)?.get(..len))
        .ok_or("truncated TCP table")?;
    // Addresses are raw in_addr values; a port's first two bytes hold it in network order.
    let endpoint = |row: &[u8], addr, port| {
        SocketAddrV4::new(
            Ipv4Addr::from(at::<4>(row, addr)),
            u16::from_be_bytes(at(row, port)),
        )
    };
    Ok(rows
        .chunks_exact(ROW)
        .filter(|row| {
            endpoint(row, LOCAL_ADDR, LOCAL_PORT) == peer
                && endpoint(row, REMOTE_ADDR, REMOTE_PORT) == local
        })
        .map(|row| {
            (
                u32::from_ne_bytes(at(row, OWNING_PID)),
                i64::from_ne_bytes(at(row, CREATE_TIMESTAMP)),
            )
        })
        .collect())
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn discord_executable(executable: &Path, home: Option<&Path>) -> Check {
    let canonical = std::fs::canonicalize(executable)
        .map_err(|error| format!("{}: {error}", executable.display()))?;
    let home = home.and_then(|home| std::fs::canonicalize(home).ok());
    if !inside_discord_bundle(&canonical, home.as_deref()) {
        return Err(format!("{} is outside Discord.app", canonical.display()));
    }
    Ok(())
}

/// `executable` and `home` must already be canonical.
#[cfg(any(target_os = "macos", test))]
fn inside_discord_bundle(executable: &Path, home: Option<&Path>) -> bool {
    let inside = |bundle: &Path| {
        bundle.is_absolute()
            && executable.strip_prefix(bundle).is_ok_and(|inner| {
                inner.components().next().is_some()
                    && inner
                        .components()
                        .all(|part| matches!(part, Component::Normal(_)))
            })
    };
    inside(Path::new("/Applications/Discord.app"))
        || home.is_some_and(|home| inside(&home.join("Applications/Discord.app")))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{proc_net_owners, single, Check};
    use std::{io, net::SocketAddr};

    pub(super) fn peer_uid(peer: SocketAddr, local: SocketAddr) -> Check<u32> {
        let mut owners = Vec::new();
        // IPv4-mapped peers of an IPv4 listener appear in tcp6.
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            match std::fs::read_to_string(path) {
                Ok(table) => owners.extend(proc_net_owners(&table, peer, local)?),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("{path}: {error}")),
            }
        }
        single(&owners)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{canonical, single, Check};
    use std::{
        ffi::OsString,
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        os::unix::ffi::OsStringExt,
        path::PathBuf,
    };

    // struct socket_fdinfo from <sys/proc_info.h>, which libc does not bind. Offsets
    // were checked against the macOS SDK on arm64 and x86_64.
    const PROC_PIDFDSOCKETINFO: i32 = 3;
    const SOCKET_FDINFO_SIZE: usize = 792;
    const SOI_TYPE: usize = 176;
    const SOI_KIND: usize = 256;
    const INSI_FPORT: usize = 264;
    const INSI_LPORT: usize = 268;
    const INSI_VFLAG: usize = 288;
    const INSI_FADDR: usize = 296;
    const INSI_LADDR: usize = 312;
    const SOCKINFO_IN: i32 = 1;
    const SOCKINFO_TCP: i32 = 2;
    const INI_IPV4: u8 = 1;
    const INI_IPV6: u8 = 2;

    #[repr(C, align(8))]
    struct SocketFdInfo([u8; SOCKET_FDINFO_SIZE]);

    /// Other users' processes fail PROC_PIDLISTFDS with EPERM and are skipped, so
    /// their sockets are never found.
    pub(super) fn peer_pid(peer: SocketAddr, local: SocketAddr) -> Check<libc::pid_t> {
        let wanted = (canonical(peer), canonical(local));
        let mut info = SocketFdInfo([0; SOCKET_FDINFO_SIZE]);
        let mut owners = Vec::new();
        for pid in all_pids()? {
            for fd in socket_fds(pid) {
                // SAFETY: `info` is writable for SOCKET_FDINFO_SIZE bytes.
                let written = unsafe {
                    libc::proc_pidfdinfo(
                        pid,
                        fd,
                        PROC_PIDFDSOCKETINFO,
                        info.0.as_mut_ptr().cast(),
                        SOCKET_FDINFO_SIZE as i32,
                    )
                };
                if written as usize == SOCKET_FDINFO_SIZE
                    && endpoints(&info) == Some(wanted)
                    && !owners.contains(&pid)
                {
                    owners.push(pid);
                }
            }
        }
        single(&owners)
    }

    pub(super) fn process_uid(pid: libc::pid_t) -> Check<libc::uid_t> {
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdshortinfo>::zeroed();
        let size = size_of::<libc::proc_bsdshortinfo>() as i32;
        // SAFETY: `info` is writable for `size` bytes.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDT_SHORTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if written != size {
            return Err(format!(
                "process {pid} info: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: zero-initialised and then filled by the kernel.
        Ok(unsafe { info.assume_init() }.pbsi_uid)
    }

    pub(super) fn executable(pid: libc::pid_t) -> Check<PathBuf> {
        let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: `path` is writable for its full length.
        let len = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
        if len <= 0 {
            return Err(format!(
                "process {pid} path: {}",
                io::Error::last_os_error()
            ));
        }
        path.truncate(len as usize);
        Ok(OsString::from_vec(path).into())
    }

    fn all_pids() -> Check<Vec<libc::pid_t>> {
        // SAFETY: a null buffer only asks for the current number of processes.
        let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        if count <= 0 {
            return Err(format!("process list: {}", io::Error::last_os_error()));
        }
        let mut pids: Vec<libc::pid_t> = vec![0; count as usize + 64];
        let bytes = size_of_val(pids.as_slice()) as i32;
        // SAFETY: `pids` is writable for `bytes` bytes.
        let count = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        if count <= 0 {
            return Err(format!("process list: {}", io::Error::last_os_error()));
        }
        pids.truncate(count as usize);
        Ok(pids)
    }

    fn socket_fds(pid: libc::pid_t) -> Vec<i32> {
        // SAFETY: a null buffer only asks for the size of the descriptor list.
        let size =
            unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        if size <= 0 {
            return Vec::new();
        }
        let entry = size_of::<libc::proc_fdinfo>();
        let empty = libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        let mut fds = vec![empty; size as usize / entry + 16];
        // SAFETY: `fds` is writable for the byte length passed.
        let size = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr().cast(),
                (fds.len() * entry) as i32,
            )
        };
        fds.truncate(size.max(0) as usize / entry);
        fds.iter()
            .filter(|fd| fd.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
            .map(|fd| fd.proc_fd)
            .collect()
    }

    fn field<const N: usize>(info: &SocketFdInfo, offset: usize) -> [u8; N] {
        let mut bytes = [0; N];
        bytes.copy_from_slice(&info.0[offset..offset + N]);
        bytes
    }

    /// (local, foreign) endpoints of a TCP socket.
    fn endpoints(info: &SocketFdInfo) -> Option<(SocketAddr, SocketAddr)> {
        let int = |offset| i32::from_ne_bytes(field(info, offset));
        if int(SOI_TYPE) != libc::SOCK_STREAM
            || !matches!(int(SOI_KIND), SOCKINFO_IN | SOCKINFO_TCP)
        {
            return None;
        }
        let vflag = info.0[INSI_VFLAG];
        let address = |offset| -> Option<IpAddr> {
            let raw: [u8; 16] = field(info, offset);
            if vflag & INI_IPV4 != 0 {
                Some(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]).into())
            } else if vflag & INI_IPV6 != 0 {
                Some(Ipv6Addr::from(raw).to_canonical())
            } else {
                None
            }
        };
        // Ports are network-order u16 values widened to int.
        let port = |offset| u16::from_be(int(offset) as u16);
        Some((
            SocketAddr::new(address(INSI_LADDR)?, port(INSI_LPORT)),
            SocketAddr::new(address(INSI_FADDR)?, port(INSI_FPORT)),
        ))
    }
}

#[cfg(windows)]
mod windows {
    use super::{canonical, owner_module, owner_module_rows, single, Check};
    use std::{io, mem::offset_of, net::SocketAddr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE, NO_ERROR},
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCPROW_OWNER_MODULE, MIB_TCPTABLE_OWNER_MODULE,
            TCP_TABLE_OWNER_MODULE_ALL,
        },
        Networking::WinSock::AF_INET,
        Security::{EqualSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER},
        System::Threading::{
            GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    };

    type Row = MIB_TCPROW_OWNER_MODULE;
    const _: () = assert!(
        offset_of!(MIB_TCPTABLE_OWNER_MODULE, table) == owner_module::TABLE
            && size_of::<Row>() == owner_module::ROW
            && offset_of!(Row, dwLocalAddr) == owner_module::LOCAL_ADDR
            && offset_of!(Row, dwLocalPort) == owner_module::LOCAL_PORT
            && offset_of!(Row, dwRemoteAddr) == owner_module::REMOTE_ADDR
            && offset_of!(Row, dwRemotePort) == owner_module::REMOTE_PORT
            && offset_of!(Row, dwOwningPid) == owner_module::OWNING_PID
            && offset_of!(Row, liCreateTimestamp) == owner_module::CREATE_TIMESTAMP
    );

    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle was opened by this module and is closed exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// Pid of the process that created the peer's socket, and the socket's creation FILETIME.
    pub(super) fn peer_socket(peer: SocketAddr, local: SocketAddr) -> Check<(u32, i64)> {
        let (SocketAddr::V4(peer), SocketAddr::V4(local)) = (canonical(peer), canonical(local))
        else {
            return Err("IPv6 peers are not checked".into());
        };
        single(&owner_module_rows(&tcp_table()?, peer, local)?)
    }

    fn tcp_table() -> Check<Vec<u8>> {
        // u64 words keep the rows' 64-bit fields aligned.
        let mut table: Vec<u64> = Vec::new();
        let mut size = 0u32;
        for _ in 0..4 {
            let buffer = if table.is_empty() {
                std::ptr::null_mut()
            } else {
                table.as_mut_ptr().cast()
            };
            // SAFETY: `buffer` is null with `size` 0, or writable for `size` bytes.
            let status = unsafe {
                GetExtendedTcpTable(
                    buffer,
                    &mut size,
                    0,
                    AF_INET as u32,
                    TCP_TABLE_OWNER_MODULE_ALL,
                    0,
                )
            };
            match status {
                NO_ERROR if !table.is_empty() => {
                    return Ok(table.iter().flat_map(|word| word.to_ne_bytes()).collect())
                }
                NO_ERROR | ERROR_INSUFFICIENT_BUFFER => {
                    table = vec![0; (size as usize + 16 * owner_module::ROW).div_ceil(8)];
                    size = (table.len() * 8) as u32;
                }
                status => return Err(format!("GetExtendedTcpTable failed with {status}")),
            }
        }
        Err("TCP table kept growing".into())
    }

    /// SID storage for a TOKEN_USER; u64 keeps the embedded pointer aligned.
    fn token_user(process: HANDLE) -> Check<Vec<u64>> {
        let mut token = std::ptr::null_mut();
        // SAFETY: `token` is a valid out pointer.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(format!("process token: {}", io::Error::last_os_error()));
        }
        let token = Handle(token);
        let mut len = 0u32;
        // SAFETY: a null buffer of length 0 only reports the required length.
        unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut len) };
        let mut user = vec![0u64; (len as usize).div_ceil(8)];
        if user.is_empty() {
            return Err(format!("token user: {}", io::Error::last_os_error()));
        }
        let capacity = (user.len() * 8) as u32;
        // SAFETY: `user` is writable for `capacity` bytes.
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                user.as_mut_ptr().cast(),
                capacity,
                &mut len,
            )
        };
        if ok == 0 {
            return Err(format!("token user: {}", io::Error::last_os_error()));
        }
        Ok(user)
    }

    fn creation_time(process: HANDLE) -> Check<i64> {
        let mut times = [FILETIME::default(); 4];
        let [created, exited, kernel, user] = &mut times;
        // SAFETY: all four out pointers are valid FILETIMEs.
        if unsafe { GetProcessTimes(process, created, exited, kernel, user) } == 0 {
            return Err(format!("process times: {}", io::Error::last_os_error()));
        }
        Ok((i64::from(created.dwHighDateTime) << 32) | i64::from(created.dwLowDateTime))
    }

    /// The table's pid is the socket's creator, which may have exited while a process it handed
    /// the socket to stays connected; a process started after the socket only reuses that pid.
    pub(super) fn same_user(pid: u32, socket_created: i64) -> Check {
        // SAFETY: returns a pseudo-handle that needs no closing.
        let ours = token_user(unsafe { GetCurrentProcess() })?;
        // SAFETY: plain call; failure returns null.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return Err(format!("process {pid}: {}", io::Error::last_os_error()));
        }
        let process = Handle(process);
        // The open handle keeps the pid from being reused until the checks are done.
        let started = creation_time(process.0)?;
        if socket_created <= 0 || started > socket_created {
            return Err(format!(
                "process {pid} started after the socket was created"
            ));
        }
        let theirs = token_user(process.0)?;
        // SAFETY: both buffers start with a TOKEN_USER written by GetTokenInformation whose
        // SID points into the same buffer, and both buffers outlive the comparison.
        let equal = unsafe {
            let ours = ours.as_ptr().cast::<TOKEN_USER>().read();
            let theirs = theirs.as_ptr().cast::<TOKEN_USER>().read();
            EqualSid(ours.User.Sid, theirs.User.Sid)
        };
        if equal == 0 {
            return Err(format!("process {pid} belongs to another user"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0438 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 4101 1 0000000000000000 100 0 0 10 0
   1: 0100007F:D2A2 0100007F:0438 01 00000000:00000000 00:00000000 00000000  1002        0 4102 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:0438 0100007F:D2A2 01 00000000:00000000 00:00000000 00000000  1001        0 4103 1 0000000000000000 20 4 30 10 -1
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000100007F:D2A4 0000000000000000FFFF00000100007F:0438 01 00000000:00000000 00:00000000 00000000  1003        0 4104 1 0000000000000000 20 4 30 10 -1
   1: 00000000000000000000000001000000:D2A5 00000000000000000000000001000000:0438 01 00000000:00000000 00:00000000 00000000  1004        0 4105 1 0000000000000000 20 4 30 10 -1
";

    fn addr(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    #[test]
    fn proc_net_rows_match_only_the_peer_end_of_the_connection() {
        let listener = addr("127.0.0.1:1080");
        assert_eq!(
            proc_net_owners(TCP, addr("127.0.0.1:53922"), listener),
            Ok(vec![1002])
        );
        assert_eq!(
            proc_net_owners(TCP, listener, addr("127.0.0.1:53922")),
            Ok(vec![1001])
        );
        assert_eq!(
            proc_net_owners(TCP, addr("127.0.0.1:53923"), listener),
            Ok(vec![])
        );
        assert_eq!(
            proc_net_owners(TCP6, addr("127.0.0.1:53924"), listener),
            Ok(vec![1003])
        );
        assert_eq!(
            proc_net_owners(TCP6, addr("[::1]:53925"), addr("[::1]:1080")),
            Ok(vec![1004])
        );
        let duplicated = format!("{TCP}{}", TCP.lines().nth(2).unwrap());
        assert_eq!(
            proc_net_owners(&duplicated, addr("127.0.0.1:53922"), listener),
            Ok(vec![1002, 1002])
        );
        for broken in [
            "header\n   0: 0100007F:D2A2 0100007F:0438 01\n",
            "header\n   0: 0100007F:ZZZZ 0100007F:0438 01 0:0 0:0 0 1002 0 1\n",
            "header\n   0: 0100007F:D2A2 0100007F:0438 01 0:0 0:0 0 uid 0 1\n",
        ] {
            assert!(
                proc_net_owners(broken, addr("127.0.0.1:53922"), listener).is_err(),
                "{broken}"
            );
        }
    }

    /// A MIB_TCPTABLE_OWNER_MODULE laid out by hand, independently of `owner_module`.
    fn owner_module_table(count: u32, rows: &[(&str, &str, u32, i64)]) -> Vec<u8> {
        let mut table = vec![0; 8 + rows.len() * 160];
        table[..4].copy_from_slice(&count.to_ne_bytes());
        for (row, (source, destination, pid, created)) in table[8..].chunks_mut(160).zip(rows) {
            row[..4].copy_from_slice(&5u32.to_ne_bytes());
            for (at, end) in [(4, source), (12, destination)] {
                let end: std::net::SocketAddrV4 = end.parse().unwrap();
                row[at..at + 4].copy_from_slice(&end.ip().octets());
                let [high, low] = end.port().to_be_bytes();
                row[at + 4..at + 8].copy_from_slice(&[high, low, 0xAB, 0xCD]);
            }
            row[20..24].copy_from_slice(&pid.to_ne_bytes());
            row[24..32].copy_from_slice(&created.to_ne_bytes());
            row[32..].fill(0xEE);
        }
        table
    }

    #[test]
    fn owner_module_rows_match_only_the_peer_end_with_its_creation_time() {
        let v4 = |value: &str| value.parse::<std::net::SocketAddrV4>().unwrap();
        let (peer, listener) = (v4("127.0.0.1:53922"), v4("127.0.0.1:1080"));
        let rows = [
            ("127.0.0.1:1080", "127.0.0.1:53922", 4, 100),
            ("127.0.0.1:53922", "127.0.0.1:1080", 7, 200),
            ("127.0.0.1:53923", "127.0.0.1:1080", 8, 300),
        ];
        let mut table = owner_module_table(3, &rows);
        table.extend([0; 40]);
        assert_eq!(
            owner_module_rows(&table, peer, listener),
            Ok(vec![(7, 200)])
        );
        assert_eq!(
            owner_module_rows(&table, listener, peer),
            Ok(vec![(4, 100)])
        );
        assert_eq!(
            owner_module_rows(&table, v4("127.0.0.1:53924"), listener),
            Ok(vec![])
        );
        assert!(owner_module_rows(&owner_module_table(4, &rows), peer, listener).is_err());
        assert!(owner_module_rows(&[1, 0], peer, listener).is_err());
    }

    #[test]
    fn discord_bundle_policy_accepts_only_the_installed_app() {
        let home = Path::new("/Users/x");
        for accepted in [
            "/Applications/Discord.app/Contents/MacOS/Discord",
            "/Applications/Discord.app/Contents/Frameworks/Discord Helper.app/Contents/MacOS/Discord Helper",
            "/Users/x/Applications/Discord.app/Contents/MacOS/Discord",
        ] {
            assert!(
                inside_discord_bundle(Path::new(accepted), Some(home)),
                "{accepted}"
            );
        }
        for rejected in [
            "/Users/x/Library/Containers/evil/Data/Applications/Discord.app/Contents/MacOS/Discord",
            "/Applications/Discord.app.evil/Contents/MacOS/Discord",
            "/Applications/Evil.app/Contents/Resources/Applications/Discord.app/Contents/MacOS/Discord",
            "/Applications/Discord.app/../Evil.app/Contents/MacOS/Evil",
            "/Applications/Discord.app",
            "Applications/Discord.app/Contents/MacOS/Discord",
            "/usr/local/bin/dinmoo-proxy",
        ] {
            assert!(
                !inside_discord_bundle(Path::new(rejected), Some(home)),
                "{rejected}"
            );
        }
        assert!(!inside_discord_bundle(
            Path::new("/Users/x/Applications/Discord.app/Contents/MacOS/Discord"),
            None
        ));
    }

    #[cfg(unix)]
    #[test]
    fn discord_executable_is_judged_by_canonical_paths() {
        let root = std::env::temp_dir().join(format!("dinmoo-peer-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let bundle = root.join("real/Applications/Discord.app/Contents/MacOS");
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::write(bundle.join("Discord"), b"").unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("home")).unwrap();
        let home = root.join("home");
        let installed = home.join("Applications/Discord.app/Contents/MacOS/Discord");
        let results = [
            discord_executable(&installed, Some(&home)),
            discord_executable(&bundle.join("Discord"), Some(&home)),
            discord_executable(&installed, None),
            discord_executable(&home.join("missing"), Some(&home)),
        ];
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(results[0], Ok(()));
        assert_eq!(results[1], Ok(()));
        assert!(results[2]
            .as_ref()
            .unwrap_err()
            .contains("outside Discord.app"));
        assert!(results[3].is_err());
    }

    fn loopback_connection() -> (TcpListener, TcpStream, TcpStream, SocketAddr, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, peer) = listener.accept().unwrap();
        let local = server.local_addr().unwrap();
        (listener, client, server, peer, local)
    }

    fn unused_port() -> SocketAddr {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_lookup_finds_this_user_for_an_accepted_loopback_connection() {
        let (_listener, _client, _server, peer, local) = loopback_connection();
        assert_eq!(linux::peer_uid(peer, local), Ok(effective_uid()));
        assert!(linux::peer_uid(unused_port(), local).is_err());
        assert!(linux::peer_uid(local, unused_port()).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_lookup_finds_this_process_for_an_accepted_loopback_connection() {
        let (_listener, _client, _server, peer, local) = loopback_connection();
        let pid = macos::peer_pid(peer, local).unwrap();
        assert_eq!(pid, std::process::id() as libc::pid_t);
        assert_eq!(macos::process_uid(pid), Ok(effective_uid()));
        assert_eq!(
            std::fs::canonicalize(macos::executable(pid).unwrap()).unwrap(),
            std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
        );
        assert!(check(peer, local)
            .unwrap_err()
            .contains("outside Discord.app"));
        assert!(macos::peer_pid(unused_port(), local).is_err());
        assert!(macos::peer_pid(local, unused_port()).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_lookup_finds_this_process_for_an_accepted_loopback_connection() {
        let (_listener, _client, _server, peer, local) = loopback_connection();
        let (pid, created) = windows::peer_socket(peer, local).unwrap();
        assert_eq!(pid, std::process::id());
        assert_eq!(windows::same_user(pid, created), Ok(()));
        assert!(windows::same_user(pid, 0).is_err());
        assert!(windows::same_user(pid, 1).is_err());
        assert!(windows::peer_socket(unused_port(), local).is_err());
        assert!(windows::peer_socket(local, unused_port()).is_err());
    }

    #[test]
    fn listener_end_of_a_connection_to_this_process_belongs_to_this_user() {
        let (_listener, _client, _server, peer, local) = loopback_connection();
        assert_eq!(verify_owner(local, peer), Ok(()));
        assert!(verify_owner(unused_port(), peer).is_err());
    }

    #[tokio::test]
    async fn voice_peer_must_be_this_user_and_on_macos_discord() {
        let (_listener, _client, _server, peer, local) = loopback_connection();
        assert_eq!(
            verify_voice_peer(peer, local).await,
            cfg!(any(target_os = "linux", windows))
        );
        assert!(!verify_voice_peer(unused_port(), local).await);
    }
}
