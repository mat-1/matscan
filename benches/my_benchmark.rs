use std::{
    hint::black_box,
    net::{Ipv4Addr, SocketAddrV4},
};

use criterion::{Criterion, criterion_group, criterion_main};
use matscan::scanner::targets::{Ipv4Range, Ipv4Ranges, ScanRange, ScanRanges, StaticScanRanges};
use rand::Rng;

fn scan_ranges_index(scan_ranges: &StaticScanRanges, n: usize) -> SocketAddrV4 {
    scan_ranges.index(n)
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut ranges = ScanRanges::default();
    for i in 0..100_000 {
        ranges.extend(vec![ScanRange {
            ip_start: Ipv4Addr::from(i),
            ip_end: Ipv4Addr::from(i),
            port_start: 1024,
            port_end: 65535,
        }])
    }

    let mut excluded = Vec::new();
    for i in 0..100_000 {
        excluded.push(Ipv4Range {
            start: Ipv4Addr::from(i),
            end: Ipv4Addr::from(i),
        })
    }
    let excluded = Ipv4Ranges::new(excluded);

    c.bench_function("exclude", |b| {
        b.iter(|| {
            ranges.clone().apply_exclude(&excluded);
        })
    });

    let ranges = ranges.to_static();

    let mut rng = rand::rng();
    c.bench_function("scan_ranges_index", |b| {
        b.iter(|| scan_ranges_index(&ranges, black_box(rng.random_range(0..ranges.count))))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
