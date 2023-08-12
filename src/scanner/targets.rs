use std::net::{Ipv4Addr, SocketAddrV4};

#[derive(Debug, PartialEq, Eq)]
pub struct ScanRange {
    pub addr_start: Ipv4Addr,
    pub addr_end: Ipv4Addr,
    pub port_start: u16,
    pub port_end: u16,
}

impl ScanRange {
    pub fn count_addresses(&self) -> usize {
        (u32::from(self.addr_end) - u32::from(self.addr_start) + 1) as usize
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
        let addr = u32::from(self.addr_start) + addr_index as u32;
        let port = self.port_start + port_index as u16;
        SocketAddrV4::new(
            Ipv4Addr::new(
                (addr >> 24) as u8,
                (addr >> 16) as u8,
                (addr >> 8) as u8,
                addr as u8,
            ),
            port,
        )
    }

    pub fn single(addr: Ipv4Addr, port: u16) -> Self {
        Self {
            addr_start: addr,
            addr_end: addr,
            port_start: port,
            port_end: port,
        }
    }
    pub fn single_port(addr_start: Ipv4Addr, addr_end: Ipv4Addr, port: u16) -> Self {
        Self {
            addr_start,
            addr_end,
            port_start: port,
            port_end: port,
        }
    }
    pub fn single_address(addr: Ipv4Addr, port_start: u16, port_end: u16) -> Self {
        Self {
            addr_start: addr,
            addr_end: addr,
            port_start,
            port_end,
        }
    }
}

#[derive(Default, Debug, PartialEq)]
pub struct ScanRanges {
    /// The ranges in order of `addr_start`.
    ranges: Vec<ScanRange>,
}

impl ScanRanges {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add to the set of ranges. There is no push function because it'd be too
    /// inefficient, you can call this with a single-item vec if you really need to.
    pub fn extend(&mut self, ranges: Vec<ScanRange>) {
        self.ranges.extend(ranges);
        self.ranges.sort_by_key(|r| r.addr_start);
    }

    /// Remove the given range from this set of ranges. Inclusive.
    ///
    /// Returns true if at least one address was removed, false otherwise.
    pub fn exclude(&mut self, exclude_range: &Ipv4Range) -> bool {
        let mut i = 0;
        while i < self.ranges.len() && self.ranges[i].addr_end < exclude_range.start {
            i += 1;
        }

        let mut queued_push = vec![];

        let mut removed_any = false;

        while i < self.ranges.len() && self.ranges[i].addr_start <= exclude_range.end {
            let range = &mut self.ranges[i];
            if range.addr_start >= exclude_range.start && range.addr_end <= exclude_range.end {
                // Range is fully contained in exclude.
                self.ranges.remove(i);
                removed_any = true;
            } else if range.addr_start < exclude_range.start && range.addr_end > exclude_range.end {
                // Range fully contains the exclude, so split.
                let other_range = ScanRange {
                    addr_start: Ipv4Addr::from(u32::from(exclude_range.end) + 1),
                    addr_end: range.addr_end,
                    port_start: range.port_start,
                    port_end: range.port_end,
                };
                range.addr_end = Ipv4Addr::from(u32::from(exclude_range.start) - 1);
                queued_push.push(other_range);
                i += 1;
                removed_any = true;
            } else if range.addr_start < exclude_range.start && range.addr_end <= exclude_range.end
            {
                // Cut off end.
                range.addr_end = Ipv4Addr::from(u32::from(exclude_range.start) - 1);
                i += 1;
                removed_any = true;
            } else if range.addr_start >= exclude_range.start && range.addr_end > exclude_range.end
            {
                // Cut off start.

                // changing addr_start would change the position, so it's easier to just delete it and add it later
                let range = self.ranges.remove(i);
                queued_push.push(ScanRange {
                    addr_start: Ipv4Addr::from(u32::from(exclude_range.end) + 1),
                    addr_end: range.addr_end,
                    port_start: range.port_start,
                    port_end: range.port_end,
                });
                removed_any = true;
            } else {
                unreachable!();
            }
        }

        self.extend(queued_push);
        if self.count() == 0 {
            println!("uh oh count is 0 after {:?}", exclude_range);
            // *usually* this means there's a problem but sometimes it does legitimately happen with the rescanner
            // panic!();
        }

        removed_any
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_subtract_center() {
        let mut ranges = ScanRanges::new();

        ranges.extend(vec![ScanRange::single_port(
            Ipv4Addr::new(1, 32, 32, 32),
            Ipv4Addr::new(1, 128, 128, 128),
            0,
        )]);

        ranges.exclude(&Ipv4Range {
            start: Ipv4Addr::new(1, 64, 64, 64),
            end: Ipv4Addr::new(1, 96, 96, 96),
        });

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
    }

    #[test]
    fn test_subtract_left() {
        let mut ranges = ScanRanges::new();

        ranges.extend(vec![ScanRange::single_port(
            Ipv4Addr::new(1, 32, 32, 32),
            Ipv4Addr::new(1, 128, 128, 128),
            0,
        )]);

        ranges.exclude(&Ipv4Range {
            start: Ipv4Addr::new(1, 32, 32, 32),
            end: Ipv4Addr::new(1, 96, 96, 96),
        });

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
    }

    #[test]
    fn test_subtract_right() {
        let mut ranges = ScanRanges::new();

        ranges.extend(vec![ScanRange::single_port(
            Ipv4Addr::new(1, 32, 32, 32),
            Ipv4Addr::new(1, 128, 128, 128),
            0,
        )]);

        ranges.exclude(&Ipv4Range {
            start: Ipv4Addr::new(1, 96, 96, 96),
            end: Ipv4Addr::new(1, 128, 128, 128),
        });

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
    }
}
