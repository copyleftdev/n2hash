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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use hex_literal::hex;

    const KNOWN_PASSWORD_1: &str = "password";
    const KNOWN_NTLM_1: &str = "8846f7eaee8fb117ad06bdd830b7586c";

    const KNOWN_PASSWORD_2: &str = "Password123!";
    const KNOWN_NTLM_2: &str = "2b576acbe6bcfda7294d6bd18041b8fe";

    #[test]
    fn test_ntlm_known_vectors() {
        assert_eq!(ntlm(KNOWN_PASSWORD_1), KNOWN_NTLM_1);
        assert_eq!(ntlm(KNOWN_PASSWORD_2), KNOWN_NTLM_2);
    }

    #[test]
    fn test_hmac_md5() {
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex!("9294727a3638bb1c13f48ef8158bfc9d");
        
        let result = hmac_md5(&key, data);
        assert_eq!(result, expected);
    }
    
    proptest! {
        #[test]
        fn ntlm_hash_always_valid_length(password in ".*") {
            let hash = ntlm(&password);
            prop_assert_eq!(hash.len(), 32);
            prop_assert!(hex::decode(&hash).is_ok());
        }
    }

    proptest! {
        #[test]
        fn net_ntlm_v2_always_valid_format(
            user in "[a-zA-Z0-9]{1,10}",
            domain in "[a-zA-Z0-9]{1,10}",
            password in "[a-zA-Z0-9]{1,10}"
        ) {
            let result = net_ntlm_v2(&user, &domain, &password);
            prop_assert!(result.is_ok());
            
            let hash_string = result.unwrap();
            
            let user_rest: Vec<&str> = hash_string.splitn(2, "::").collect();
            prop_assert_eq!(user_rest.len(), 2);
            prop_assert_eq!(user_rest[0], user);
            
            let rest_parts: Vec<&str> = user_rest[1].split(':').collect();
            prop_assert_eq!(rest_parts.len(), 4);
            prop_assert_eq!(rest_parts[0], domain);
            
            prop_assert_eq!(rest_parts[1].len(), 16);
            prop_assert!(hex::decode(rest_parts[1]).is_ok());
            
            prop_assert_eq!(rest_parts[2].len(), 32);
            prop_assert!(hex::decode(rest_parts[2]).is_ok());
            
            prop_assert!(hex::decode(rest_parts[3]).is_ok());
        }
    }

    #[test]
    fn test_net_ntlm_v2_deterministic() {
        let user = "testuser";
        let domain = "testdomain";
        let password = "testpassword";
        
        let hash1 = net_ntlm_v2(user, domain, password).unwrap();
        let hash2 = net_ntlm_v2(user, domain, password).unwrap();
        
        let parts1: Vec<&str> = hash1.split(':').collect();
        let parts2: Vec<&str> = hash2.split(':').collect();
        
        assert_eq!(parts1[0], parts2[0]);
    }
    
    proptest! {
        #[test]
        fn ntlm_hash_deterministic(password in ".*") {
            let hash1 = ntlm(&password);
            let hash2 = ntlm(&password);
            prop_assert_eq!(hash1, hash2);
        }
    }
    
    proptest! {
        #[test]
        fn different_passwords_different_hashes(
            password1 in "[a-zA-Z0-9]{1,10}",
            password2 in "[a-zA-Z0-9]{1,10}"
        ) {
            prop_assume!(password1 != password2);
            
            let hash1 = ntlm(&password1);
            let hash2 = ntlm(&password2);
            prop_assert_ne!(hash1, hash2);
        }
    }
}