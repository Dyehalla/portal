use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;
use crate::Error::{self, OS};

const TUN_PATH: &str = "/dev/net/tun";

pub trait PacketSource {
    fn fd(&self) -> RawFd;

    fn read(&self, buf: &mut [u8]) -> Result<usize, Error>;
}

pub struct TunSocket {
    name: String,
    fd: RawFd,
}

impl Drop for TunSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl TunSocket {
    pub fn new(name: &str) -> Result<Self, Error> {
        let path = CString::new(TUN_PATH)
            .expect("TUN device path must not contain a NUL byte");
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(OS(io::Error::last_os_error()));
        }

        let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };

        for (dst, src) in ifreq.ifr_name.iter_mut().zip(name.as_bytes()) {
            *dst = *src as libc::c_char;
        }

        unsafe {
            ifreq.ifr_ifru.ifru_flags =
                (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE) as libc::c_short;

            if libc::ioctl(fd, libc::TUNSETIFF, &ifreq) < 0 {
                let error = io::Error::last_os_error();
                libc::close(fd);
                return Err(OS(error));
            }
        }

        Ok(Self { name: name.to_owned(), fd })
    }
}

impl PacketSource for TunSocket {
    fn fd(&self) -> RawFd {
        self.fd
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        Ok(0)
    }
}
