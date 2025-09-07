// download https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz and cache it

use std::{io::BufRead, net::Ipv4Addr, sync::OnceLock, time::Duration};

use crate::scanner::targets::Ipv4Range;

/// A vec of (range, asn) pairs
#[derive(Debug)]
pub struct AsnRanges(pub Vec<(Ipv4Range, u32)>);

pub async fn download() -> eyre::Result<AsnRanges> {
    let client = reqwest::Client::new();

    println!("Downloading ASN data...");
    let resp = client
        .get("https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz")
        .send()
        .await?;
    println!("Downloaded ASN data");

    let resp = resp.bytes().await?;
    let resp = std::io::Cursor::new(resp);
    let resp = flate2::read::GzDecoder::new(resp);

    let mut ranges = Vec::new();
    for line in std::io::BufReader::new(resp).lines() {
        let line = line?;
        let mut parts = line.split('\t');

        let start = parts.next().unwrap();
        let end = parts.next().unwrap();
        let asn = parts.next().unwrap();

        let start = Ipv4Addr::from(start.parse::<u32>()?);
        let end = Ipv4Addr::from(end.parse::<u32>()?);
        let asn = asn.parse::<u32>()?;

        ranges.push((Ipv4Range { start, end }, asn));
    }

    Ok(AsnRanges(ranges))
}

pub async fn get() -> eyre::Result<&'static AsnRanges> {
    static ASN_RANGES: OnceLock<AsnRanges> = OnceLock::new();

    if let Some(ranges) = ASN_RANGES.get() {
        return Ok(ranges);
    }

    let ranges = loop {
        match download().await {
            Ok(r) => break r,
            Err(e) => {
                println!("Failed downloading ASNs: {e:?}");
                println!("Waiting 10 seconds and retrying...");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    };
    ASN_RANGES.set(ranges).unwrap();

    Ok(ASN_RANGES.get().unwrap())
}

impl AsnRanges {
    pub fn get_asn(&self, ip: Ipv4Addr) -> Option<u32> {
        // do a binary search

        let mut start = 0;
        let mut end = self.0.len();

        while start < end {
            let mid = (start + end) / 2;

            let (range, asn) = &self.0[mid];

            if range.start <= ip && ip <= range.end {
                return Some(*asn);
            }

            if range.start > ip {
                end = mid;
            } else {
                start = mid + 1;
            }
        }

        None
    }

    pub fn get_ranges_for_asn(&self, asn: u32) -> Vec<Ipv4Range> {
        self.0
            .iter()
            .filter(|(_, a)| *a == asn)
            .map(|(r, _)| *r)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_asns() {
        let asns = AsnRanges(vec![(
            Ipv4Range {
                start: Ipv4Addr::new(0, 0, 0, 0),
                end: Ipv4Addr::new(0, 0, 0, 255),
            },
            1,
        )]);
        assert_eq!(asns.get_asn(Ipv4Addr::new(0, 0, 0, 128)), Some(1));
        assert_eq!(
            asns.get_ranges_for_asn(1),
            vec![Ipv4Range {
                start: Ipv4Addr::new(0, 0, 0, 0),
                end: Ipv4Addr::new(0, 0, 0, 255),
            }]
        );
    }
}
