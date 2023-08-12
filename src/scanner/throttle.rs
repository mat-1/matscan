//! Makes sure we sent packets at the correct rate.

use std::{
    collections::VecDeque,
    thread,
    time::{Duration, Instant},
};

pub struct Throttler {
    max_rate: u64,

    batch_buffer: VecDeque<Batch>,

    /// This is a float so it can be changed more gradually.
    batch_size: f64,

    total_packets_sent: u64,
}

pub struct Batch {
    pub time: Instant,
    pub total_packets_sent_before: u64,
    pub batch_size: u64,
}

impl Throttler {
    pub fn new(max_packets_per_second: u64) -> Self {
        Self {
            max_rate: max_packets_per_second,
            batch_buffer: VecDeque::new(),
            batch_size: 1.,
            total_packets_sent: 0,
        }
    }

    /// Returns the number of packets that should be sent in the next batch.
    ///
    /// Based on masscan's throttler https://github.com/robertdavidgraham/masscan/blob/master/src/main-throttle.c#L59
    pub fn next_batch(&mut self) -> u64 {
        // if let Some(last_batch) = self.batch_buffer.back() {
        //     // if last batch was over a second ago then reset
        //     if last_batch.time.elapsed() > Duration::from_secs(1) {
        //         self.batch_size = 1.;
        //         // self.batch_buffer.clear();
        //         println!("\nover a second ago\n");
        //         return self.next_batch();
        //     }
        // }

        let current_rate = self.estimated_packets_per_second();

        self.batch_buffer.push_back(Batch {
            time: Instant::now(),
            total_packets_sent_before: self.total_packets_sent,
            batch_size: self.batch_size as u64,
        });
        if self.batch_buffer.len() > 256 {
            self.batch_buffer.pop_front();
        }

        if current_rate > self.max_rate {
            // if we're scanning above the limit, then wait a bit, lower our batch size, and
            // continue
            let mut sleep_time = Duration::from_secs_f64(
                ((current_rate - self.max_rate) as f64 / self.max_rate as f64) / 10.,
            );

            // if it's longer than 100ms then clamp (usually happens at the beginning of
            // scans when the rate is overestimated)
            if sleep_time > Duration::from_millis(100) {
                sleep_time = Duration::from_millis(100);
            }

            self.batch_size *= 0.999;

            // println!("sleeping for {sleep_time:?}");
            thread::sleep(sleep_time);

            // println!("over max rate");
            return self.next_batch();
        }

        self.batch_size *= 1.005;
        if self.batch_size > 10000. {
            self.batch_size = 10000.;
        }

        let batch_size = self.batch_size as u64;
        self.total_packets_sent += batch_size;

        batch_size
    }

    pub fn estimated_packets_per_second(&self) -> u64 {
        // compare the total_packets_sent_before of the oldest and newest batch

        if self.batch_buffer.len() < 2 {
            return 0;
        }

        let oldest_batch = self.batch_buffer.front().unwrap();
        let newest_batch = self.batch_buffer.back().unwrap();

        ((newest_batch.total_packets_sent_before - oldest_batch.total_packets_sent_before) as f64
            / (newest_batch.time - oldest_batch.time).as_secs_f64()) as u64
    }
}
