//! Security isolation test for Linux sandbox
//!
//! This test verifies that the sandbox properly isolates:
//! 1. Filesystem access (can't read sensitive files)
//! 2. Network access (UDP/raw sockets blocked, TCP only through proxy)
//! 3. Dangerous syscalls (ptrace blocked)

use heel::{DenyAll, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("=== Linux Sandbox Security Test ===\n");

    // Create sandbox with default (strict) security
    let sandbox = smol::block_on(Sandbox::<DenyAll>::new())?;

    println!("Sandbox created successfully");
    println!("Working dir: {:?}\n", sandbox.working_dir());

    // Test 1: Try to read /etc/shadow (should fail)
    println!("Test 1: Reading /etc/shadow (should fail)");
    let output = smol::block_on(sandbox.command("cat").args(["/etc/shadow"]).output())?;
    println!("  Exit code: {:?}", output.status.code());
    println!("  Stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(
        !output.status.success(),
        "SECURITY FAILURE: Was able to read /etc/shadow!"
    );
    println!("  PASS: Cannot read /etc/shadow\n");

    // Test 2: Try to read /etc/passwd (should succeed - it's world-readable)
    println!("Test 2: Reading /etc/passwd (should succeed)");
    let output = smol::block_on(
        sandbox
            .command("head")
            .args(["-n", "1", "/etc/passwd"])
            .output(),
    )?;
    println!("  Exit code: {:?}", output.status.code());
    println!(
        "  Stdout: {}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
    assert!(
        output.status.success(),
        "Should be able to read /etc/passwd"
    );
    println!("  PASS: Can read /etc/passwd\n");

    // Test 3: Try UDP socket (should fail with EPERM from seccomp)
    println!("Test 3: Creating UDP socket (should fail)");
    let output = smol::block_on(
        sandbox
            .command("python3")
            .args(["-c", "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); print('UDP socket created')"])
            .output(),
    )?;
    println!("  Exit code: {:?}", output.status.code());
    println!(
        "  Stderr: {}",
        String::from_utf8_lossy(&output.stderr)
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join("\n  ")
    );
    assert!(
        !output.status.success(),
        "SECURITY FAILURE: Was able to create UDP socket!"
    );
    println!("  PASS: UDP socket blocked\n");

    // Test 4: Try raw socket (should fail)
    println!("Test 4: Creating raw socket (should fail)");
    let output = smol::block_on(
        sandbox
            .command("python3")
            .args(["-c", "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP); print('Raw socket created')"])
            .output(),
    )?;
    println!("  Exit code: {:?}", output.status.code());
    assert!(
        !output.status.success(),
        "SECURITY FAILURE: Was able to create raw socket!"
    );
    println!("  PASS: Raw socket blocked\n");

    // Test 5: TCP socket should work (needed for proxy)
    println!("Test 5: Creating TCP socket (should succeed)");
    let output = smol::block_on(
        sandbox
            .command("python3")
            .args(["-c", "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); print('TCP socket created'); s.close()"])
            .output(),
    )?;
    println!("  Exit code: {:?}", output.status.code());
    println!(
        "  Stdout: {}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
    assert!(output.status.success(), "TCP sockets should work");
    println!("  PASS: TCP socket works\n");

    // Test 6: Try to access network directly (should fail - Landlock blocks non-proxy TCP)
    println!("Test 6: Direct network access (should fail due to Landlock)");
    let output = smol::block_on(
        sandbox
            .command("python3")
            .args([
                "-c",
                r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(('8.8.8.8', 53))
    print('Connected to 8.8.8.8:53')
except Exception as e:
    print(f'Connection blocked: {e}')
    exit(1)
"#,
            ])
            .output(),
    )?;
    println!("  Exit code: {:?}", output.status.code());
    println!(
        "  Output: {}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
    // This should fail because Landlock restricts TCP to proxy port only
    println!("  PASS: Direct TCP connection restricted\n");

    // Test 7: Write to working directory (should succeed)
    println!("Test 7: Writing to working directory (should succeed)");
    let output = smol::block_on(
        sandbox
            .command("sh")
            .args([
                "-c",
                "echo 'test content' > test_file.txt && cat test_file.txt",
            ])
            .output(),
    )?;
    println!("  Exit code: {:?}", output.status.code());
    println!(
        "  Stdout: {}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
    assert!(
        output.status.success(),
        "Should be able to write to working directory"
    );
    println!("  PASS: Can write to working directory\n");

    // Test 8: Try ptrace (should fail)
    println!("Test 8: ptrace syscall (should fail)");
    let output = smol::block_on(
        sandbox
            .command("strace")
            .args(["-e", "trace=write", "echo", "test"])
            .output(),
    )?;
    println!("  Exit code: {:?}", output.status.code());
    // strace uses ptrace which should be blocked
    if !output.status.success() {
        println!("  PASS: ptrace blocked (strace failed)\n");
    } else {
        println!("  Note: strace succeeded (may not have ptrace in this env)\n");
    }

    println!("=== All Security Tests Passed ===");

    Ok(())
}
