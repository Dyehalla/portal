use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;

const TUN_PATH: &str = "/dev/net/tun";

pub struct TunSocket {
    _name: String,
    fd: RawFd,
}

impl Drop for TunSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl TunSocket {
    pub fn new(name: &str) -> io::Result<Self> {
        let path = CString::new(TUN_PATH)
            .expect("TUN device path must not contain a NUL byte");
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
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
                return Err(error);
            }
        }

        // Один worker должен владеть одним независимым queue fd.
        Ok(Self { _name: name.to_owned(), fd })
    }
}
