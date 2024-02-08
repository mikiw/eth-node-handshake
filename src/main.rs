
use secp256k1::{PublicKey, SecretKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

mod errors;
mod handshake;
mod ecies;
mod utils;
mod messages;

use crate::{
    errors::{Error, Result},
    handshake::Handshake, messages::{Disconnect, Hello},
};

// TODO: move to Ecies
// Map node id to public key
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

    let ip = "44.210.78.226:30303";
    let node_public_key_input = "442f5a25a0c1955e1afa921d13e95a8a4cd928ae50c36d5d7ee16a148f986fb119e126fd9a0a149271ce42ead08c1dff3ba03947faee80face06ea8aef259923";
    let node_public_key_decoded = hex::decode(node_public_key_input).unwrap();
    let node_public_key = id2pk(&node_public_key_decoded).unwrap(); // remove unwraps later

    if let Ok(mut stream) = TcpStream::connect(ip).await {
        println!("Connected to target adress:");
        if let Err(e) = handshake(&mut stream, node_public_key).await {
            println!("{e}");
        }
    } else {
        println!("Failed to connect to the given Ethereum node.");
    }
}

// TODO: move to handshake later and refactor add errors etc
async fn handshake(stream: &mut TcpStream, node_public_key: PublicKey) -> Result<()> {
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

    let mut handshake = Handshake::new(private_key, node_public_key);

    let auth_encrypted = handshake.write_auth();

    if stream.write(&auth_encrypted).await? == 0 {
        println!("return Err(Error::TcpConnectionClosed);");
    }

    println!("Auth message send to target node");

    let mut buf = [0_u8; 1024];
    let resp = stream.read(&mut buf).await?;

    if resp == 0 {
        return Err(Error::InvalidResponse(
            "Recipient's response does not contain the auth response".to_string(),
        ));
    }

    let mut bytes_used = 0u16;

    let decrypted = handshake.decrypt_message(&mut buf, &mut bytes_used)?;

    if bytes_used == resp as u16 {
        return Err(Error::InvalidResponse(
            "Recipient's response does not contain the Hello message".to_string(),
        ));
    }

    handshake.derive_secrets(decrypted)?;

    let hello_frame = handshake.write_ack();
    if stream.write(&hello_frame).await? == 0 {
        return Err(Error::TcpConnectionClosed);
    }

    let frame = handshake.read_ack_frame(&mut buf[bytes_used as usize..resp])?;
    handle_incoming_frame(frame)?;

    Ok(())
}

fn handle_incoming_frame(frame: Vec<u8>) -> Result<()> {
    let message_id: u8 = rlp::decode(&[frame[0]])?;

    if message_id == 0 {
        let hello: Hello = rlp::decode(&frame[1..])?;
        println!("Hello message from target node:\n{:?}", hello);
    }

    if message_id == 1 {
        let disc: Disconnect = rlp::decode(&frame[1..])?;
        println!("Disconnect message from target node: \n{:?}", disc);
    }

    Ok(())
}