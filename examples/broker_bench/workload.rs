//! The calls the broker serves, in a loop, timed from the inside.
//!
//! Usage: `workload <create|read> <directory> <count>`; prints microseconds per
//! operation.

use std::io::Write;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (mode, directory, count) = (
        args[1].as_str(),
        args[2].as_str(),
        args[3].parse::<u64>().expect("a count"),
    );
    let path = format!("{directory}/bench-file");
    let started = Instant::now();
    match mode {
        "create" => {
            for _ in 0..count {
                let mut file = std::fs::File::create(&path).expect("create");
                file.write_all(b"x").expect("write");
                drop(file);
                std::fs::remove_file(&path).expect("unlink");
            }
        }
        "read" => {
            std::fs::write(&path, b"x").expect("fixture");
            for _ in 0..count {
                drop(std::fs::File::open(&path).expect("open"));
            }
            std::fs::remove_file(&path).expect("cleanup");
        }
        other => panic!("unknown mode {other}"),
    }
    let elapsed = started.elapsed();
    println!("{:.2}", elapsed.as_secs_f64() * 1e6 / count as f64);
}
