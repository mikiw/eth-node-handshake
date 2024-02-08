
use secp256k1::{PublicKey, SecretKey};
use tokio::net::TcpStream;

mod errors;
mod handshake;
mod ecies;
mod utils;
mod messages;

use crate::{errors::{Error, Result}, handshake::Handshake};

// TODO: move to Ecies
fn id2pk(data: &[u8]) -> Result<PublicKey> {
    let mut s = [4_u8; 65];
    s[1..].copy_from_slice(data);
    let public_key =
        PublicKey::from_slice(&s).map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

    Ok(public_key)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // TODO: Apply linter and formats
    // TODO: Fix all unwraps
    // TODO: Add Errors
    // TODO: use enode format, clippy etc
    // TODO: add tests
    // TODO: implement enode
    // TODO: add tests
    // TODO: refactor main handshake code
    // TODO: Read all again and check again

    let ip = "44.210.78.226:30303";
    let node_public_key_input = "442f5a25a0c1955e1afa921d13e95a8a4cd928ae50c36d5d7ee16a148f986fb119e126fd9a0a149271ce42ead08c1dff3ba03947faee80face06ea8aef259923";
    let node_public_key_decoded = hex::decode(node_public_key_input).unwrap();
    let node_public_key = id2pk(&node_public_key_decoded).unwrap(); // remove unwraps later

    if let Ok(mut stream) = TcpStream::connect(ip).await {
        println!("Connected to target adress: {:?}", ip);

        let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let mut handshake = Handshake::new(private_key, node_public_key);

        if let Err(e) = handshake.v5(&mut stream).await {
            println!("{e}");
        }
    } else {
        println!("Failed to connect to the given Ethereum node.");
    }
}
