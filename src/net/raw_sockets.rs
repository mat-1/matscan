//! borrowed from smoltcp

use std::os::unix::io::{AsRawFd, RawFd};
use std::{io, mem};

#[repr(C)]
#[derive(Debug, Clone)]
struct ifreq {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_data: libc::c_int, /* ifr_ifindex or ifr_mtu */
}

fn ifreq_for(name: &str) -> ifreq {
    let mut ifreq = ifreq {
        ifr_name: [0; libc::IF_NAMESIZE],
        ifr_data: 0,
    };
    for (i, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[i] = *byte as libc::c_char
    }
    ifreq
}

fn ifreq_ioctl(
    lower: libc::c_int,
    ifreq: &mut ifreq,
    cmd: libc::c_ulong,
) -> io::Result<libc::c_int> {
    unsafe {
        let res = libc::ioctl(lower, cmd as _, ifreq as *mut ifreq);
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(ifreq.ifr_data)
}

pub const SIOCGIFMTU: libc::c_ulong = 0x8921;
pub const SIOCGIFINDEX: libc::c_ulong = 0x8933;
pub const ETH_P_ALL: libc::c_short = 0x0003;
pub const ETH_P_IEEE802154: libc::c_short = 0x00F6;

#[derive(Debug)]
pub struct RawSocket {
    protocol: libc::c_short,
    lower: libc::c_int,
    ifreq: ifreq,
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
    }
}

impl RawSocket {
    pub fn new(name: &str) -> io::Result<RawSocket> {
        let protocol = ETH_P_ALL;

        let lower = unsafe {
            let lower = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                protocol.to_be() as i32,
            );
            if lower == -1 {
                return Err(io::Error::last_os_error());
            }
            lower
        };

        let mut socket = RawSocket {
            protocol,
            lower,
            ifreq: ifreq_for(name),
        };
        socket.bind_interface()?;

        Ok(socket)
    }

    pub fn interface_mtu(&mut self) -> io::Result<usize> {
        ifreq_ioctl(self.lower, &mut self.ifreq, SIOCGIFMTU).map(|mtu| mtu as usize)
    }

    pub fn bind_interface(&mut self) -> io::Result<()> {
        let sockaddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: self.protocol.to_be() as u16,
            sll_ifindex: ifreq_ioctl(self.lower, &mut self.ifreq, SIOCGIFINDEX)?,
            sll_hatype: 1,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [0; 8],
        };

        unsafe {
            let res = libc::bind(
                self.lower,
                &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            );
            if res == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::recv(
                self.lower,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            );
            if len == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(len as usize)
        }
    }

    pub fn send(&mut self, buffer: &[u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::send(
                self.lower,
                buffer.as_ptr() as *const libc::c_void,
                buffer.len(),
                0,
            );
            if len == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(len as usize)
        }
    }

    pub fn send_blocking(&mut self, buffer: &[u8]) {
        loop {
            match self.send(buffer) {
                Ok(_) => break,
                Err(err) => match err.kind() {
                    std::io::ErrorKind::WouldBlock => {}
                    e => panic!("error sending packet: {:?}", e),
                },
            }
        }
    }
}

impl Clone for RawSocket {
    /// this can panic so hopefully it doesn't lol
    fn clone(&self) -> Self {
        let protocol = ETH_P_ALL;

        let lower = unsafe {
            let lower = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                protocol.to_be() as i32,
            );
            if lower == -1 {
                panic!("{}", io::Error::last_os_error());
            }
            lower
        };

        let mut socket = RawSocket {
            protocol,
            lower,
            ifreq: self.ifreq.clone(),
        };
        socket.bind_interface().unwrap();

        socket
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.lower);
        }
    }
}
