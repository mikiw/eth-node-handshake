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
    let mut args = std::env::args();
    let _inner = args.next();
    let enode = args.next().unwrap_or_default();
    let split = &enode.as_str()[8..].split('@').collect::<Vec<&str>>();
    let node_public_key_input = split[0];
    let ip = split[1];

    if let Ok(mut stream) = TcpStream::connect(ip).await {
        println!("Connected to target adress: {:?}", ip);

        let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let mut handshake = match Handshake::new(private_key, node_public_key_input.to_string()) {
            Ok(handshake) => handshake,
            Err(error) => panic!("Wrong node public key: {:?}", error),
        };

        if let Err(e) = handshake.version_5(&mut stream).await {
            println!("{e}");
        }
    } else {
        println!("Failed to connect to the given Ethereum node.");
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::{PublicKey, SecretKey};

    use crate::{ecies::Ecies, handshake::Handshake};

    const NODE_ID: &str = "c9d9a8656916a6303e401be2e127ef6054fc3a1f74408593d9cbdb319370c5b13ee98b0d9ef6b7f22a45bec50598a696aa4770cbb9f1109e6ef82ed4d4bea26c";

    #[test]
    fn handshake_init() {
        let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

        assert!(Handshake::new(private_key, NODE_ID.to_string()).is_ok());
    }

    #[test]
    fn ecies_init() {
        let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

        let node_public_key_decoded = hex::decode(NODE_ID).unwrap();
        let mut s = [4_u8; 65];
        s[1..].copy_from_slice(&node_public_key_decoded);
        let public_key =
            PublicKey::from_slice(&s).unwrap();

        let ecies = Ecies::new(private_key, public_key);

        assert_eq!(ecies.private_key, private_key);
        assert_eq!(ecies.ephemeral_private_key.display_secret().to_string().len(), 64);
        assert!(ecies.shared_key.to_string().starts_with("0x"));
        assert!(ecies.nonce.to_string().starts_with("0x"));
    }
}