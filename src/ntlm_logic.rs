use md5;
#[allow(deprecated)]
use rand::thread_rng;
use rand::RngCore;
use chrono::Utc;
use hex;
use md4::{Md4, Digest as Md4Digest};
use thiserror::Error;

const RESPONDER_VERSION: u8 = 1;
const HI_RESPONDER_VERSION: u8 = 1;
const RESERVED_1_PADDING: [u8; 6] = [0u8; 6];
const RESERVED_2_PADDING: [u8; 4] = [0u8; 4];
const RESERVED_3_PADDING: [u8; 4] = [0u8; 4];
const DEFAULT_SERVER_NAME: &str = "WORKGROUP";

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;
const MD5_BLOCK_SIZE: usize = 64;

#[derive(Error, Debug)]
pub enum NtlmError {
    #[error("Hex decoding failed: {0}")]
    HexDecoding(#[from] hex::FromHexError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

fn hmac_md5(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut key_bytes = if key.len() > MD5_BLOCK_SIZE {
        let mut context = md5::Context::new();
        context.consume(key);
        context.compute().to_vec()
    } else {
        key.to_vec()
    };

    if key_bytes.len() < MD5_BLOCK_SIZE {
        key_bytes.resize(MD5_BLOCK_SIZE, 0);
    }

    let mut ikey = vec![0; MD5_BLOCK_SIZE];
    let mut okey = vec![0; MD5_BLOCK_SIZE];

    for i in 0..MD5_BLOCK_SIZE {
        ikey[i] = key_bytes[i] ^ IPAD;
        okey[i] = key_bytes[i] ^ OPAD;
    }

    let mut inner_context = md5::Context::new();
    inner_context.consume(&ikey);
    inner_context.consume(message);
    let inner_hash = inner_context.compute();

    let mut outer_context = md5::Context::new();
    outer_context.consume(&okey);
    outer_context.consume(inner_hash.as_ref());
    outer_context.compute().to_vec()
}

pub fn ntlm(password: &str) -> String {
    let password_utf16: Vec<u16> = password.encode_utf16().collect();
    let mut password_bytes = Vec::with_capacity(password_utf16.len() * 2);
    for char_code in password_utf16 {
        password_bytes.extend_from_slice(&char_code.to_le_bytes());
    }

    let mut hasher = Md4::new();
    hasher.update(&password_bytes);
    let result = hasher.finalize();

    hex::encode(result)
}

pub fn net_ntlm_v2(user: &str, domain: &str, password: &str) -> Result<String, NtlmError> {
    let now_utc = Utc::now();
    let timestamp_secs = now_utc.timestamp();
    let timestamp_bytes: [u8; 8] = timestamp_secs.to_le_bytes();

    #[allow(deprecated)]
    let mut rng = thread_rng();
    let mut client_challenge = [0u8; 8];
    let mut server_challenge = [0u8; 8];
    rng.fill_bytes(&mut client_challenge);
    rng.fill_bytes(&mut server_challenge);

    let server_name_utf16: Vec<u16> = DEFAULT_SERVER_NAME.encode_utf16().collect();
    let mut server_name_bytes = Vec::with_capacity(server_name_utf16.len() * 2);
    for char_code in server_name_utf16 {
        server_name_bytes.extend_from_slice(&char_code.to_le_bytes());
    }

    let blob_len = 1 + 1
                 + RESERVED_1_PADDING.len()
                 + timestamp_bytes.len()
                 + client_challenge.len()
                 + RESERVED_2_PADDING.len()
                 + server_name_bytes.len()
                 + RESERVED_3_PADDING.len();
    let mut blob = Vec::with_capacity(blob_len);

    blob.push(RESPONDER_VERSION);
    blob.push(HI_RESPONDER_VERSION);
    blob.extend_from_slice(&RESERVED_1_PADDING);
    blob.extend_from_slice(&timestamp_bytes);
    blob.extend_from_slice(&client_challenge);
    blob.extend_from_slice(&RESERVED_2_PADDING);
    blob.extend_from_slice(&server_name_bytes);
    blob.extend_from_slice(&RESERVED_3_PADDING);

    let ntlm_hash_hex = ntlm(password);
    let ntlm_hash = hex::decode(ntlm_hash_hex)?;

    let user_upper = user.to_uppercase();
    let hmac1_msg_str = format!("{}{}", user_upper, domain);
    let hmac1_msg_utf16: Vec<u16> = hmac1_msg_str.encode_utf16().collect();
    let mut hmac1_msg_bytes = Vec::with_capacity(hmac1_msg_utf16.len() * 2);
    for char_code in hmac1_msg_utf16 {
        hmac1_msg_bytes.extend_from_slice(&char_code.to_le_bytes());
    }

    let response_key_nt = hmac_md5(&ntlm_hash, &hmac1_msg_bytes);

    let mut server_challenge_with_blob = Vec::with_capacity(server_challenge.len() + blob.len());
    server_challenge_with_blob.extend_from_slice(&server_challenge);
    server_challenge_with_blob.extend_from_slice(&blob);

    let nt_proof_bytes = hmac_md5(&response_key_nt, &server_challenge_with_blob);

    let server_challenge_hex = hex::encode(server_challenge);
    let nt_proof_string_hex = hex::encode(&nt_proof_bytes);
    let blob_hex = hex::encode(&blob);

    Ok(format!(
        "{}::{}:{}:{}:{}",
        user,
        domain,
        server_challenge_hex,
        nt_proof_string_hex,
        blob_hex
    ))
}