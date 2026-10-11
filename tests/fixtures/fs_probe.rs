//! Probe a directory from inside the sandbox, one filesystem operation at a
//! time, reporting each raw OS error so a denial names the operation that met
//! it.

use std::io;
use std::path::{Path, PathBuf};

fn report(name: &str, result: io::Result<()>) {
    match result {
        Ok(()) => println!("{name}=ok"),
        Err(error) => println!(
            "{name}=err({}) {}",
            error.raw_os_error().unwrap_or(-1),
            error
        ),
    }
}

fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).expect("a directory argument"));
    println!("cwd={:?}", std::env::current_dir());
    println!("TEMP={:?}", std::env::var("TEMP"));
    println!("canonicalized={:?}", std::fs::canonicalize(&dir));

    let sub = dir.join("sub");
    let staged = sub.join("staged.txt");
    let moved = dir.join("moved.txt");
    let direct = dir.join("direct.txt");

    report("write_direct", std::fs::write(&direct, b"x"));
    report("mkdir_sub", std::fs::create_dir(&sub));
    report("write_staged", std::fs::write(&staged, b"x"));
    report(
        "rename_child_to_root",
        std::fs::rename(&staged, &moved),
    );
    report("remove_file", std::fs::remove_file(&direct));
    report("remove_dir_all", std::fs::remove_dir_all(&sub));

    // What the directory actually holds afterwards, and whether a second view
    // of it agrees — a redirected write shows up under a different listing.
    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            let names: Vec<_> = entries
                .filter_map(|entry| entry.ok().map(|e| e.file_name()))
                .collect();
            println!("listing={names:?}");
        }
        Err(error) => println!("listing=err({:?})", error.raw_os_error()),
    }
    println!("exists_direct={}", Path::new(&direct).exists());
    println!("exists_moved={}", moved.exists());
}
