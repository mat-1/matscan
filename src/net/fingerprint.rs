use pnet::packet::tcp::TcpOption;

#[derive(Debug, Clone)]
pub struct TcpFingerprint {
    pub mss: u16,
    
    pub ittl: u8,
    pub window: u16,
    /// TCP Options for SYN
    pub options: Vec<TcpOption>,
}

// Fingerprint signatures from p0f
// https://github.com/p0f/p0f/blob/master/p0f.fp
impl TcpFingerprint {
    // -------- SILLY --------
    
    pub fn nintendo_3ds() -> Self {
        // p0f fingerprint: *:64:0:1360:32768,0:mss,nop,nop,sok:df,id+:0
        Self {
            mss: 1360,
            ittl: 64,
            window: 32768,
            options: vec![
                TcpOption::mss(1360),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::sack_perm(),
            ],
        }
    }
    
    // -------- WINDOWS --------
    
    pub fn windows_xp() -> Self {
        // p0f fingerprint: *:128:0:*:16384,0:mss,nop,nop,sok:df,id+:0
        Self {
            mss: 1337,
            ittl: 128,
            window: 16384,
            options: vec![
                TcpOption::mss(1337),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::sack_perm(),
            ]
        }
    }

    pub fn windows_7_or_8() -> Self {
        // p0f fingerprint: *:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0
        Self {
            mss: 1337,
            ittl: 128,
            window: 8192,
            options: vec![
                TcpOption::mss(1337),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::sack_perm(),
            ]
        }
    }
    
    // -------- LINUX/UNIX --------
    
    pub fn linux_3_11_and_newer() -> Self {
        // p0f fingerprint: *:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0
        Self {
            mss: 128,
            ittl: 64,
            window: 128*20,
            options: vec![
                TcpOption::mss(128),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(10),
            ]
        }
    }

    pub fn solaris_8() -> Self {
        // p0f fingerprint: *:64:0:*:32850,1:nop,ws,nop,nop,ts,nop,nop,sok,mss:df,id+:0
        Self {
            mss: 1337,
            ittl: 64,
            window: 32850,
            options: vec![
                TcpOption::nop(),
                TcpOption::wscale(1),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::sack_perm(),
                TcpOption::mss(1337),
            ],
        }
    }

    // p0f fingerprint: *:64:0:*:mss*44,1:mss,sok,ts,nop,ws:df,id+:0
    pub fn android() -> Self {
        Self {
            mss: 1000,
            ittl: 64,
            window: 1000*44,
            options: vec![
                TcpOption::mss(1000),
                TcpOption::sack_perm(),
                TcpOption::timestamp(1, 0),
                TcpOption::nop(),
                TcpOption::wscale(1)
            ]
        }
    }
}