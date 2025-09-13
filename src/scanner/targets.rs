use std::{
    mem,
    net::{Ipv4Addr, SocketAddrV4},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScanRange {
    pub ip_start: Ipv4Addr,
    pub ip_end: Ipv4Addr,
    pub port_start: u16,
    pub port_end: u16,
}

impl ScanRange {
    pub fn count_addresses(&self) -> usize {
        (u32::from(self.ip_end) as u64 - u32::from(self.ip_start) as u64 + 1) as usize
    }

    pub fn count_ports(&self) -> usize {
        ((self.port_end - self.port_start) + 1) as usize
    }

    /// Count the number of combinations of addresses and ports in this range.
    pub fn count(&self) -> usize {
        self.count_addresses() * self.count_ports()
    }

    /// Get the address and port at the given index.
    pub fn index(&self, index: usize) -> SocketAddrV4 {
        let port_count = self.count_ports();
        let addr_index = index / port_count;
        let port_index = index % port_count;
        let addr = u32::from(self.ip_start) + addr_index as u32;
        let port = self.port_start + port_index as u16;
        SocketAddrV4::new(Ipv4Addr::from(addr), port)
    }

    pub fn single(ip: Ipv4Addr, port: u16) -> Self {
        Self {
            ip_start: ip,
            ip_end: ip,
            port_start: port,
            port_end: port,
        }
    }
    pub fn single_port(addr_start: Ipv4Addr, addr_end: Ipv4Addr, port: u16) -> Self {
        Self {
            ip_start: addr_start,
            ip_end: addr_end,
            port_start: port,
            port_end: port,
        }
    }
    pub fn single_address(addr: Ipv4Addr, port_start: u16, port_end: u16) -> Self {
        Self {
            ip_start: addr,
            ip_end: addr,
            port_start,
            port_end,
        }
    }
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct ScanRanges {
    /// The ranges in order of `addr_start`.
    ranges: Vec<ScanRange>,
}

impl ScanRanges {
    pub fn new(ranges: Vec<ScanRange>) -> Self {
        let mut s = Self::default();
        s.extend(ranges);
        s
    }

    /// Add to the set of ranges. There is no push function because it'd be too
    /// inefficient, you can call this with a single-item vec if you really need
    /// to.
    pub fn extend(&mut self, r: Vec<ScanRange>) {
        self.ranges.extend(r);
        self.ranges.sort_by_key(|r| r.ip_start);
    }

    /// Remove the given ranges from this set of ranges. Returns the ranges that
    /// were renoved.
    pub fn apply_exclude(&mut self, exclude_ranges: &Ipv4Ranges) -> Vec<Ipv4Range> {
        let mut ranges: Vec<ScanRange> = Vec::new();
        let mut removed_ranges: Vec<Ipv4Range> = Vec::new();

        let mut scan_ranges = mem::take(&mut self.ranges).into_iter();
        let mut exclude_ranges = exclude_ranges.ranges.iter();

        let Some(mut exclude_range) = exclude_ranges.next() else {
            ranges.extend(scan_ranges);
            self.ranges = ranges;
            return vec![];
        };
        let Some(mut scan_range) = scan_ranges.next() else {
            return vec![];
        };

        loop {
            if scan_range.ip_end < exclude_range.start {
                // scan_range is before exclude_range
                ranges.push(scan_range);
                scan_range = match scan_ranges.next() {
                    Some(scan_range) => scan_range,
                    None => break,
                };
            } else if scan_range.ip_start > exclude_range.end {
                // scan_range is after exclude_range
                exclude_range = match exclude_ranges.next() {
                    Some(exclude_range) => exclude_range,
                    None => {
                        ranges.push(scan_range);
                        break;
                    }
                };
            } else if scan_range.ip_start < exclude_range.start
                && scan_range.ip_end > exclude_range.end
            {
                // scan_range contains exclude_range
                ranges.push(ScanRange {
                    ip_start: scan_range.ip_start,
                    ip_end: Ipv4Addr::from(u32::from(exclude_range.start) - 1),
                    port_start: scan_range.port_start,
                    port_end: scan_range.port_end,
                });
                removed_ranges.push(*exclude_range);
                scan_range.ip_start = Ipv4Addr::from(u32::from(exclude_range.end) + 1);
            } else if scan_range.ip_start < exclude_range.start {
                // cut off the right side
                ranges.push(ScanRange {
                    ip_start: scan_range.ip_start,
                    ip_end: Ipv4Addr::from(u32::from(exclude_range.start) - 1),
                    port_start: scan_range.port_start,
                    port_end: scan_range.port_end,
                });
                removed_ranges.push(Ipv4Range {
                    start: exclude_range.start,
                    end: scan_range.ip_end,
                });
                scan_range = match scan_ranges.next() {
                    Some(scan_range) => scan_range,
                    None => break,
                };
            } else if scan_range.ip_end > exclude_range.end {
                // cut off the left side
                removed_ranges.push(Ipv4Range {
                    start: scan_range.ip_start,
                    end: exclude_range.end,
                });
                scan_range.ip_start = Ipv4Addr::from(u32::from(exclude_range.end) + 1);
            } else {
                // scan_range is contained within exclude_range
                removed_ranges.push(Ipv4Range {
                    start: scan_range.ip_start,
                    end: scan_range.ip_end,
                });
                scan_range = match scan_ranges.next() {
                    Some(scan_range) => scan_range,
                    None => break,
                };
            }
        }

        ranges.extend(scan_ranges);
        self.ranges = ranges;
        removed_ranges
    }

    /// Get the address and port at the given index.
    ///
    /// You should use [`Self::to_static`] and then call index on that.
    pub fn slow_index(&self, index: usize) -> SocketAddrV4 {
        let mut i = 0;
        let mut index = index;
        while i < self.ranges.len() {
            let range = &self.ranges[i];
            let count = range.count();
            if index < count {
                return range.index(index);
            }
            index -= count;
            i += 1;
        }
        panic!("index out of bounds");
    }

    /// Count the total number of targets that are going to be scanned.
    pub fn count(&self) -> usize {
        let mut total = 0;
        for range in &self.ranges {
            total += range.count();
        }
        total
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn ranges(&self) -> &Vec<ScanRange> {
        &self.ranges
    }

    pub fn to_static(self) -> StaticScanRanges {
        let mut ranges = Vec::with_capacity(self.ranges.len());
        let mut index = 0;
        for range in self.ranges {
            let count = range.count();
            ranges.push(StaticScanRange {
                count,
                range,
                index,
            });
            index += count;
        }
        StaticScanRanges {
            ranges,
            count: index,
        }
    }
}
impl From<Vec<ScanRange>> for ScanRanges {
    fn from(ranges: Vec<ScanRange>) -> Self {
        Self::new(ranges)
    }
}

pub struct StaticScanRanges {
    pub ranges: Vec<StaticScanRange>,
    pub count: usize,
}
pub struct StaticScanRange {
    pub range: ScanRange,
    count: usize,
    index: usize,
}

impl StaticScanRanges {
    pub fn index(&self, index: usize) -> SocketAddrV4 {
        // binary search to find the range that contains the index
        let mut start = 0;
        let mut end = self.ranges.len();
        while start < end {
            let mid = (start + end) / 2;
            let range = &self.ranges[mid];
            if range.index + range.count <= index {
                start = mid + 1;
            } else if range.index > index {
                end = mid;
            } else {
                return range.range.index(index - range.index);
            }
        }
        panic!("index out of bounds");
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Ipv4Range {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
}

impl Ipv4Range {
    pub fn single(addr: Ipv4Addr) -> Self {
        Self {
            start: addr,
            end: addr,
        }
    }
}

#[derive(Default, Debug)]
pub struct Ipv4Ranges {
    ranges: Vec<Ipv4Range>,
}

impl Ipv4Ranges {
    pub fn new(mut ranges: Vec<Ipv4Range>) -> Self {
        ranges.sort_by_key(|r| r.start);
        Self { ranges }
    }

    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let mut start = 0;
        let mut end = self.ranges.len();
        while start < end {
            let mid = (start + end) / 2;
            let range = &self.ranges[mid];
            if range.end < addr {
                start = mid + 1;
            } else if range.start > addr {
                end = mid;
            } else {
                return true;
            }
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn ranges(&self) -> &Vec<Ipv4Range> {
        &self.ranges
    }

    pub fn count(&self) -> usize {
        let mut total: u64 = 0;
        for range in &self.ranges {
            total += (u32::from(range.end) as u64) - (u32::from(range.start) as u64) + 1;
        }
        total as usize
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_count_addresses_slash0() {
        let ranges = ScanRanges::new(vec![ScanRange::single_port(
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            0,
        )]);
        assert_eq!(ranges.count(), 2usize.pow(32));
    }

    #[test]
    fn test_subtract_center() {
        let mut ranges = ScanRanges::new(vec![ScanRange::single_port(
            Ipv4Addr::new(1, 32, 32, 32),
            Ipv4Addr::new(1, 128, 128, 128),
            0,
        )]);

        let excluded_ranges = ranges.apply_exclude(&Ipv4Ranges::new(vec![Ipv4Range {
            start: Ipv4Addr::new(1, 64, 64, 64),
            end: Ipv4Addr::new(1, 96, 96, 96),
        }]));

        assert_eq!(
            ranges,
            ScanRanges {
                ranges: vec![
                    ScanRange::single_port(
                        Ipv4Addr::new(1, 32, 32, 32),
                        Ipv4Addr::new(1, 64, 64, 63),
                        0,
                    ),
                    ScanRange::single_port(
                        Ipv4Addr::new(1, 96, 96, 97),
                        Ipv4Addr::new(1, 128, 128, 128),
                        0,
                    )
                ]
            }
        );
        assert_eq!(
            excluded_ranges,
            vec![Ipv4Range {
                start: Ipv4Addr::new(1, 64, 64, 64),
                end: Ipv4Addr::new(1, 96, 96, 96),
            }]
        );
    }

    #[test]
    fn test_subtract_center_from_slash_0() {
        let mut ranges = ScanRanges::new(vec![ScanRange::single_port(
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            0,
        )]);

        let ranges_to_exclude = Ipv4Ranges::new(vec![
            Ipv4Range::single(Ipv4Addr::new(1, 1, 1, 1)),
            Ipv4Range::single(Ipv4Addr::new(1, 1, 1, 2)),
        ]);
        let excluded_ranges = ranges.apply_exclude(&ranges_to_exclude);

        assert_eq!(
            ranges,
            ScanRanges {
                ranges: vec![
                    ScanRange::single_port(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(1, 1, 1, 0), 0,),
                    ScanRange::single_port(
                        Ipv4Addr::new(1, 1, 1, 3),
                        Ipv4Addr::new(255, 255, 255, 255),
                        0,
                    )
                ]
            }
        );
        assert_eq!(
            excluded_ranges,
            vec![
                Ipv4Range::single(Ipv4Addr::new(1, 1, 1, 1)),
                Ipv4Range::single(Ipv4Addr::new(1, 1, 1, 2))
            ]
        );
    }

    #[test]
    fn test_subtract_left() {
        let mut ranges = ScanRanges::new(vec![ScanRange::single_port(
            Ipv4Addr::new(1, 32, 32, 32),
            Ipv4Addr::new(1, 128, 128, 128),
            0,
        )]);

        let excluded_ranges = ranges.apply_exclude(&Ipv4Ranges::new(vec![Ipv4Range {
            start: Ipv4Addr::new(1, 32, 32, 32),
            end: Ipv4Addr::new(1, 96, 96, 96),
        }]));

        assert_eq!(
            ranges,
            ScanRanges {
                ranges: vec![ScanRange::single_port(
                    Ipv4Addr::new(1, 96, 96, 97),
                    Ipv4Addr::new(1, 128, 128, 128),
                    0,
                )]
            }
        );
        assert_eq!(
            excluded_ranges,
            vec![Ipv4Range {
                start: Ipv4Addr::new(1, 32, 32, 32),
                end: Ipv4Addr::new(1, 96, 96, 96),
            }]
        );
    }

    #[test]
    fn test_subtract_right() {
        let mut ranges = ScanRanges::new(vec![ScanRange::single_port(
            Ipv4Addr::new(1, 32, 32, 32),
            Ipv4Addr::new(1, 128, 128, 128),
            0,
        )]);

        let excluded_ranges = ranges.apply_exclude(&Ipv4Ranges::new(vec![Ipv4Range {
            start: Ipv4Addr::new(1, 96, 96, 96),
            end: Ipv4Addr::new(1, 128, 128, 128),
        }]));

        assert_eq!(
            ranges,
            ScanRanges {
                ranges: vec![ScanRange::single_port(
                    Ipv4Addr::new(1, 32, 32, 32),
                    Ipv4Addr::new(1, 96, 96, 95),
                    0,
                )]
            }
        );
        assert_eq!(
            excluded_ranges,
            vec![Ipv4Range {
                start: Ipv4Addr::new(1, 96, 96, 96),
                end: Ipv4Addr::new(1, 128, 128, 128),
            }]
        );
    }

    #[test]
    fn test_count_slash0() {
        let range = ScanRange::single_port(
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            25565,
        );
        assert_eq!(range.count(), 4294967296);
    }

    #[test]
    fn contains_but_is_empty() {
        let ranges = Ipv4Ranges::new(vec![]);
        assert!(!ranges.contains(Ipv4Addr::new(1, 2, 3, 4)));
    }
}
