use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::Local;
use colored::*;
use log::{Level, LevelFilter, Log, Metadata, Record};

static LOG_LEVEL: AtomicUsize = AtomicUsize::new(1); // 1 = INFO

pub struct NatterLogger;

impl NatterLogger {
    pub fn init() {
        log::set_logger(&NatterLogger).unwrap();
        log::set_max_level(LevelFilter::Trace);
    }

    pub fn set_verbose(verbose: bool) {
        if verbose {
            LOG_LEVEL.store(0, Ordering::Relaxed); // DEBUG
        } else {
            LOG_LEVEL.store(1, Ordering::Relaxed); // INFO
        }
    }
}

fn level_to_num(level: Level) -> usize {
    match level {
        Level::Trace | Level::Debug => 0,
        Level::Info => 1,
        Level::Warn => 2,
        Level::Error => 3,
    }
}

fn level_letter(level: Level) -> &'static str {
    match level {
        Level::Trace | Level::Debug => "D",
        Level::Info => "I",
        Level::Warn => "W",
        Level::Error => "E",
    }
}

impl Log for NatterLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        level_to_num(metadata.level()) >= LOG_LEVEL.load(Ordering::Relaxed)
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let now = Local::now().format("%Y-%m-%d %H:%M:%S");
        let letter = level_letter(record.level());
        let msg = format!("{} [{}] {}", now, letter, record.args());
        let msg = match record.level() {
            Level::Trace | Level::Debug => msg.bright_black().to_string(),
            Level::Info => msg,
            Level::Warn => msg.yellow().bold().to_string(),
            Level::Error => msg.red().bold().to_string(),
        };
        let _ = writeln!(std::io::stderr(), "{}", msg);
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}
