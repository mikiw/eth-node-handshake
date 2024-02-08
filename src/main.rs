
// use secp256k1::{
//     recovery::{RecoverableSignature, RecoveryId},
//     PublicKey, SecretKey, SECP256K1,
// };
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use bytes::{Bytes, BytesMut};

// Seems that his ecies is missing signing
// use ecies::{decrypt, encrypt, utils::generate_keypair, PublicKey};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use sha2::{Digest as sha2_digest, Sha256};


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
    // TODO: Fix all unwraps
    // TODO: Add Errors
    // TODO: use enode format, clippy etc
    // TODO: add tests

    // Connect to a peer

    // AWS ethereum node
    // let enode = "enode://c9d9a8656916a6303e401be2e127ef6054fc3a1f74408593d9cbdb319370c5b13ee98b0d9ef6b7f22a45bec50598a696aa4770cbb9f1109e6ef82ed4d4bea26c@13.115.79.190:30303";
    let ip = "81.83.6.224:30303";
    let node_public_key_input = "547b7b8d897c12f68c9d1eb176954da285d7d608caccb6121738bf4af243b8c8c90f2476a3403bc06777f68c4ad3b493d19510de586f5ea3281955f60f7deb4a";
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

async fn handshake(stream: &mut TcpStream, node_public_key: PublicKey) -> Result<()> {
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

    println!("new handshake before");
    let mut handshake = Handshake::new(private_key, node_public_key);
    println!("new handshake afters");

    let auth_encrypted = handshake.auth();

    if stream.write(&auth_encrypted).await? == 0 {
        println!("return Err(Error::TcpConnectionClosed);");
    }

    println!("Auth message send to target node");

    let mut buf = [0_u8; 1024];
    let resp = stream.read(&mut buf).await?;

    if resp == 0 {
        println!("return Err(Error::AuthResponse());");
    }

    let mut bytes_used = 0u16;

    let decrypted = handshake.decrypt(&mut buf, &mut bytes_used)?;
    println!("decrypted {:?}", decrypted);
    println!("decrypted.len() {:?}", decrypted.len());

    // TODO: fix this
    // if bytes_used == resp as u16 {
    //     return Err(Error::InvalidResponse(
    //         "Recipient's response does not contain the Hello message".to_string(),
    //     ));
    // }

    handshake.derive_secrets(decrypted)?;

    let hello_frame = handshake.hello_msg();
    if stream.write(&hello_frame).await? == 0 {
        return Err(Error::TcpConnectionClosed);
    }

    let frame = handshake.read_frame(&mut buf[bytes_used as usize..resp])?;
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