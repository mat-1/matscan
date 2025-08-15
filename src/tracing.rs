use tracing::level_filters::LevelFilter;
use tracing_subscriber::{prelude::*, EnvFilter};

use crate::config::Config;

pub fn init_tracing(config: &Config) {
    let mut layers = Vec::new();

    layers.push(EnvFilter::from_default_env().boxed());

    if let Some(logging_dir) = &config.logging_dir {
        let file_appender = tracing_appender::rolling::daily(logging_dir, "matscan.log");

        layers.push(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(file_appender)
                .with_filter(LevelFilter::DEBUG)
                .boxed(),
        );
    }

    tracing_subscriber::registry().with(layers).init();
}
