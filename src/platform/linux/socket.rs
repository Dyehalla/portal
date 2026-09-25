use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const TUN_PATH: &str = "/dev/net/tun";

/// One nonblocking TUN queue. The dispatcher owns the device queue.
pub struct TunSocket {
    fd: OwnedFd,
}

impl TunSocket {
    /// Opens and attaches one TUN queue with no packet-info prefix.
    pub fn new(name: &str) -> io::Result<Self> {
        let path = CString::new(TUN_PATH).expect("TUN path has no NUL bytes");
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in ifreq.ifr_name.iter_mut().zip(name.as_bytes()) {
            *dst = *src as libc::c_char;
        }
        unsafe {
            ifreq.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
            if libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &ifreq) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Self::from_owned_fd(fd)
    }

    /// Takes ownership of an already-configured TUN descriptor.
    pub(crate) fn from_owned_fd(fd: OwnedFd) -> io::Result<Self> {
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    /// Returns the descriptor registered by the dispatcher poller.
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Reads one IP packet, retrying only if interrupted.
    pub fn read(&self, buffer: &mut [u8]) -> Result<usize, io::Error> {
        loop {
            let read = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if read >= 0 {
                return Ok(read as usize);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error);
            }
        }
    }

    /// Writes one complete IP packet to the TUN queue.
    pub fn write(&self, packet: &[u8]) -> Result<usize, io::Error> {
        loop {
            let written =
                unsafe { libc::write(self.fd.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
            if written >= 0 {
                return Ok(written as usize);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error);
            }
        }
    }
}
