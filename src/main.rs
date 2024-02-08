use secp256k1::SecretKey;
use tokio::net::TcpStream;

mod ecies;
mod errors;
mod handshake;
mod messages;
mod utils;

use crate::handshake::Handshake;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // TODO: Fix all unwraps
    // TODO: Add test or tests
    // TODO: refactor main handshake code
    // TODO: Read all again and check again

    let mut args = std::env::args();
    let _inner = args.next();
    let enode = args.next().unwrap_or_default();
    let split = &enode.as_str()[8..].split("@").collect::<Vec<&str>>();
    let node_public_key_input = split[0];
    let ip = split[1];

    if let Ok(mut stream) = TcpStream::connect(ip).await {
        println!("Connected to target adress: {:?}", ip);

        let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let mut handshake = Handshake::new(private_key, node_public_key_input.to_string());

        if let Err(e) = handshake.version_5(&mut stream).await {
            println!("{e}");
        }
    } else {
        println!("Failed to connect to the given Ethereum node.");
    }
}
