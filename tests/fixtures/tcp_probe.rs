use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

fn main() {
    let address: SocketAddr = std::env::args().nth(1).expect("TCP peer address").parse().expect("socket address");
    let code = match TcpStream::connect_timeout(&address, Duration::from_secs(1)) {
        Ok(_) => 0,
        Err(error) if matches!(error.kind(), std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::TimedOut) => 2,
        Err(_) => 3,
    };
    std::process::exit(code);
}
