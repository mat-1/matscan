use pnet::packet::tcp::TcpOption;

#[derive(Debug, Clone)]
pub struct TcpFingerprint {
    pub ittl: u8,
    pub window: u16,
    /// TCP Options for SYN
    pub options: Vec<TcpOption>,
}

// Fingerprint signatures from p0f
// https://github.com/p0f/p0f/blob/master/p0f.fp
impl TcpFingerprint {
    // Nintendo please don't sue :pleading_face:
    // p0f fingerprint: *:64:0:1360:32768,0:mss,nop,nop,sok:df,id+:0
    fn nintendo_3ds() -> Self {
        Self {
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

    // the fingerprint is as weird as the OS itself
    // p0f fingerprint: *:64:0:*:32850,1:nop,ws,nop,nop,ts,nop,nop,sok,mss:df,id+:0
    fn solaris_8() -> Self {
        Self {
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

    // <3
    // p0f fingerprint: *:128:0:*:16384,0:mss,nop,nop,sok:df,id+:0
    fn windows_xp() -> Self {
        Self {
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

    // p0f fingerprint: *:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0
    fn windows_7_or_8() -> Self {
        Self {
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
}

impl Default for TcpFingerprint {
    fn default() -> Self {
        Self::nintendo_3ds()
    }
}