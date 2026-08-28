type EventToken = u64;
use libc::epoll_create1;
use crate::Error::{self, OS};

struct Poller {

}

impl Poller {
    fn new() -> Result<Poller, Error> {
        let epoll_fd = unsafe {epoll_create1(0)};
        if epoll_fd < 0 {
            return Err(OS(std::io::Error::last_os_error()))
        }

        

        return Ok(Poller {});

    }
}