use std::{ffi::CString, net::UdpSocket};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use crate::Error::{self, OS};

const TUN_PATH: &str = "/dev/net/tun";

pub enum SocketType {
    TUN(TunSocket),
    //UDP(UdpSocket)
}

impl SocketType {
    fn fd(&self) -> RawFd {
        match self {
            SocketType::TUN(s) => s.fd(),
            //SocketType::UDP(s) => s.as_raw_fd(),
        }
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        match self {
            SocketType::TUN(s) => s.read(buf),
        }
    }
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

    fn fd(&self) -> RawFd {
        self.fd
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        loop {
            let bytes_read = unsafe {libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len())};
            if bytes_read >= 0 {
                return Ok(bytes_read as usize);
            }
            
            let err = io::Error::last_os_error();                                   
            match err.raw_os_error() {                                                         
                Some(libc::EINTR) => continue,                                      

                Some(libc::EAGAIN) => {
                    return Err(Error::WouldBlock);
                }
                _ => return Err(OS(err)),                                               
            }   
        }
    }
}


    

