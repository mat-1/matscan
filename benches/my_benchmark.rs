use std::net::{Ipv4Addr, SocketAddrV4};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use matscan::scanner::targets::{Ipv4Range, ScanRange, ScanRanges, StaticScanRanges};
use rand::Rng;

fn scan_ranges_index(scan_ranges: &StaticScanRanges, n: usize) -> SocketAddrV4 {
    scan_ranges.index(n)
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut ranges = ScanRanges::new();
    for i in 0..100_000 {
        ranges.extend(vec![ScanRange {
            addr_start: Ipv4Addr::from(i),
            addr_end: Ipv4Addr::from(i),
            port_start: 1024,
            port_end: 65535,
        }])
    }

    c.bench_function("exclude", |b| {
        b.iter(|| {
            ranges.exclude(&Ipv4Range {
                start: Ipv4Addr::new(1, 64, 64, 64),
                end: Ipv4Addr::new(1, 96, 96, 96),
            })
        })
    });

    let ranges = ranges.to_static();

    let mut rng = rand::thread_rng();
    c.bench_function("scan_ranges_index", |b| {
        b.iter(|| scan_ranges_index(&ranges, black_box(rng.gen_range(0..ranges.count))))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
