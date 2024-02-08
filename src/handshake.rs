use byteorder::{BigEndian, ByteOrder};
// use secp256k1::{
//     recovery::{RecoverableSignature, RecoveryId},
//     PublicKey, SecretKey, SECP256K1,
// };
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use bytes::{Bytes, BytesMut};
// use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};


// Seems that his ecies is missing signing
// use ecies::{decrypt, encrypt, utils::generate_keypair, PublicKey};

use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{tcp, TcpStream}};
// use tokio::io::AsyncWriteExt;
// use std::error::Error;
use rlp::{Rlp, RlpStream};
// use ethereum_types::{H128, H256};
use std::num::TryFromIntError;
// use sha3::{Digest, Keccak256};
use rlp::DecoderError;
use thiserror::Error;
// use sha2::{Digest as sha2_digest, Sha256};

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use ethereum_types::{H128, H256};
use sha3::{Digest, Keccak256};



// use sha3::{Digest, Keccak256};

// use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac as h_mac};

// Note: 5 version is backward compatible with 4
const VERSION: usize = 5;
const ZERO_HEADER: &[u8; 3] = &[194, 128, 128]; // Hex{0xC2, 0x80, 0x80} -> u8 &[194, 128, 128]

use crate::{
    errors::{Error, Result}, messages::Hello, utils::Aes256Ctr
    
};


pub struct HashMac {
    secret: H256,
    hasher: Keccak256,
}

impl HashMac {
    pub fn new(secret: H256) -> Self {
        Self {
            secret,
            hasher: Keccak256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data)
    }

    pub fn digest(&self) -> H128 {
        H128::from_slice(&self.hasher.clone().finalize()[..16])
    }

    pub fn compute_header(&mut self, header_cipher_text: &[u8]) {
        let mut header_mac_seed = self.digest().to_fixed_bytes();

        self.compute(&mut header_mac_seed, header_cipher_text);
    }

    pub fn compute_frame(&mut self, body_ciphertext: &[u8]) {
        self.hasher.update(body_ciphertext);

        let seed = self.digest();
        self.compute(&mut seed.to_fixed_bytes(), seed.as_ref());
    }

    fn compute(&mut self, seed: &mut [u8], cipher_text: &[u8]) {
        self.encrypt(seed);

        for i in 0..cipher_text.len() {
            seed[i] ^= cipher_text[i];
        }

        self.hasher.update(seed);
    }

    fn encrypt(&self, data: &mut [u8]) {
        let cipher = aes::Aes256::new(self.secret.as_ref().into());
        cipher.encrypt_block(GenericArray::from_mut_slice(data));
    }
}


use crate::{
    ecies::Ecies,
    messages,
    // errors::{Error, Result},
};

pub struct Secrets {
    pub aes_secret: H256,
    pub mac_secret: H256,
    pub shared_secret: H256,
    pub ingress_mac: HashMac,
    pub egress_mac: HashMac,
    pub ingress_aes: Aes256Ctr,
    pub egress_aes: Aes256Ctr,
}

pub struct Handshake {
    pub ecies: Ecies,
    pub secrets: Option<Secrets>,
}

impl Handshake {
    pub fn new(private_key: SecretKey, remote_public_key: PublicKey) -> Self {
        Handshake {
            ecies: Ecies::new(private_key, remote_public_key),
            secrets: None,
        }
    }

    pub fn auth(&mut self) -> BytesMut {
        let signature = self.signature();

        let full_pub_key = self.ecies.ephemeral_public_key.serialize_uncompressed();
        let public_key = &full_pub_key[1..];

        let mut stream = RlpStream::new_list(4);
        stream.append(&&signature[..]);
        stream.append(&public_key);
        stream.append(&self.ecies.nonce.as_bytes());
        stream.append(&VERSION);

        let auth_body = stream.out();

        let mut buf = BytesMut::default();
        let _encrypted_len = self.encrypt(auth_body, &mut buf);

        self.ecies.auth = Some(Bytes::copy_from_slice(&buf[..]));

        buf
    }

    pub fn encrypt(&self, data_in: BytesMut, data_out: &mut BytesMut) -> Result<usize> {
        self.ecies.encrypt(data_in, data_out)
    }

    pub fn decrypt<'a>(
        &mut self,
        data_in: &'a mut [u8],
        read_bytes: &mut u16,
    ) -> Result<&'a mut [u8]> {
        self.ecies.decrypt(data_in, read_bytes)
    }

    fn signature(&self) -> [u8; 65] {
        let msg = self.ecies.shared_key ^ self.ecies.nonce;

        let (rec_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_digest_slice(msg.as_bytes()).unwrap(),
                &self.ecies.ephemeral_secret_key,
            )
            .serialize_compact();

        let mut signature: [u8; 65] = [0; 65];
        signature[..64].copy_from_slice(&sig);
        signature[64] = rec_id.to_i32() as u8;

        signature
    }

    fn create_hash(&self, inputs: &[&[u8]]) -> H256 {
        let mut hasher = Keccak256::new();

        for input in inputs {
            hasher.update(input)
        }

        H256::from(hasher.finalize().as_ref())
    }

    pub fn derive_secrets(&mut self, ack_body: &[u8]) -> Result<()> {
        let rlp = Rlp::new(ack_body);

        let recipient_ephemeral_pubk_raw: Vec<_> = rlp.val_at(0)?;

        let mut buf = [4_u8; 65];
        buf[1..].copy_from_slice(&recipient_ephemeral_pubk_raw);
        let recipient_ephemeral_pubk =
            PublicKey::from_slice(&buf).map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

        // recipient nonce
        let recipient_nonce_raw: Vec<_> = rlp.val_at(1)?;
        let recipient_nonce = H256::from_slice(&recipient_nonce_raw);

        // ack-vsn
        let ack_vsn: usize = rlp.val_at(2)?;
        if ack_vsn != VERSION {
            // Ignoring any mismatches in auth-vsn and ack-vsn
        }

        // ephemeral-key
        let ephemeral_key = H256::from_slice(
            &secp256k1::ecdh::shared_secret_point(
                &recipient_ephemeral_pubk,
                &self.ecies.ephemeral_secret_key,
            )[..32],
        );

        let keccak_nonce = self.create_hash(&[recipient_nonce.as_ref(), self.ecies.nonce.as_ref()]);
        let shared_secret = self.create_hash(&[ephemeral_key.as_ref(), keccak_nonce.as_ref()]);
        let aes_secret = self.create_hash(&[ephemeral_key.as_ref(), shared_secret.as_ref()]);
        let mac_secret = self.create_hash(&[ephemeral_key.as_ref(), aes_secret.as_ref()]);

        // egress-mac
        let mut egress_mac = HashMac::new(mac_secret);
        egress_mac.update((mac_secret ^ recipient_nonce).as_bytes());
        egress_mac.update(self.ecies.auth.as_ref().unwrap());

        // ingress-mac
        let mut ingress_mac = HashMac::new(mac_secret);
        ingress_mac.update((mac_secret ^ self.ecies.nonce).as_bytes());
        ingress_mac.update(self.ecies.auth_response.as_ref().unwrap());

        let iv = H128::default(); // TODO: fix this later, or check at least

        self.secrets = Some(Secrets {
            aes_secret,
            mac_secret,
            shared_secret,
            egress_mac,
            ingress_mac,
            ingress_aes: Aes256Ctr::new(aes_secret.as_ref().into(), iv.as_ref().into()),
            egress_aes: Aes256Ctr::new(aes_secret.as_ref().into(), iv.as_ref().into()),
        });

        println!("aes_secret: {:?}", aes_secret);
        println!("mac_secret: {:?}", mac_secret);
        println!("shared_secret: {:?}", shared_secret);

        Ok(())
    }   

    pub fn hello_msg(&mut self) -> BytesMut {
        let msg = Hello {
            protocol_version: VERSION,
            client_version: "hello".to_string(),
            capabilities: vec![],
            port: 0,
            id: self.ecies.ephemeral_public_key,
        };

        let mut encoded_hello = BytesMut::default();
        encoded_hello.extend_from_slice(&rlp::encode(&0_u8));
        encoded_hello.extend_from_slice(&rlp::encode(&msg));

        self.write_frame(&encoded_hello)
    }

    fn write_frame(&mut self, data: &[u8]) -> BytesMut {
        let mut buf = [0; 8];
        let n_bytes = 3; // 3 * 8 = 24;
        BigEndian::write_uint(&mut buf, data.len() as u64, n_bytes);

        let mut header_buf = [0_u8; 16];
        header_buf[..3].copy_from_slice(&buf[..3]);
        header_buf[3..6].copy_from_slice(ZERO_HEADER);

        let secrets = self.secrets.as_mut().unwrap();
        secrets.egress_aes.apply_keystream(&mut header_buf);
        secrets.egress_mac.compute_header(&header_buf);

        let mac = secrets.egress_mac.digest();

        let mut out = BytesMut::default();
        out.reserve(32);
        out.extend_from_slice(&header_buf);
        out.extend_from_slice(mac.as_bytes());

        let mut len = data.len();
        if len % 16 > 0 {
            len = (len / 16 + 1) * 16;
        }

        let old_len = out.len();
        out.resize(old_len + len, 0);

        let encrypted = &mut out[old_len..old_len + len];
        encrypted[..data.len()].copy_from_slice(data);

        secrets.egress_aes.apply_keystream(encrypted);
        secrets.egress_mac.compute_frame(encrypted);
        let mac = secrets.egress_mac.digest();

        out.extend_from_slice(mac.as_bytes());

        out
    }

    pub fn read_frame(&mut self, buf: &mut [u8]) -> Result<Vec<u8>> {
        let (header_bytes, frame) = buf.split_at_mut(32);
        let (header, mac) = header_bytes.split_at_mut(16);
        let mac = H128::from_slice(mac);

        let secrets = self.secrets.as_mut().unwrap();

        secrets.ingress_mac.compute_header(header);
        if mac != secrets.ingress_mac.digest() {
            return Err(Error::InvalidMac(mac));
        }

        secrets.ingress_aes.apply_keystream(header);

        let mut frame_size = BigEndian::read_uint(header, 3) + 16;
        let padding = frame_size % 16;
        if padding > 0 {
            frame_size += 16 - padding;
        }

        let (frame, _) = frame.split_at_mut(frame_size as usize);
        let (frame_data, frame_mac) = frame.split_at_mut(frame.len() - 16);
        let frame_mac = H128::from_slice(frame_mac);

        secrets.ingress_mac.compute_frame(frame_data);

        if frame_mac == secrets.ingress_mac.digest() {
            println!("\nHanshake completed succesfully\n Received MAC is valid!!!\n");
        } else {
            return Err(Error::InvalidMac(frame_mac));
        }

        secrets.ingress_aes.apply_keystream(frame_data);

        Ok(frame_data.to_owned())
    }
}