//! Core logic for generating NTLM and NetNTLMv2 hashes.
//!
//! This module implements the cryptographic operations required for NTLMv2 authentication,
//! specifically focusing on generating the necessary hash components based on user credentials.
//! It follows the specifications outlined in [MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol.
//!
//! Assumes compatible crate versions in Cargo.toml, e.g.:
//! md5 = "0.7.0"
//! md4 = "0.10"

// Required Crates
use md5;
#[allow(deprecated)] // Suppress potentially spurious warning for thread_rng
use rand::thread_rng;
use rand::RngCore;    // Trait providing `fill_bytes`
use chrono::Utc;
use hex;
use md4::{Md4, Digest as Md4Digest}; // Alias Digest from md4 to avoid conflict
use thiserror::Error;

// --- Constants ---
const RESPONDER_VERSION: u8 = 1;
const HI_RESPONDER_VERSION: u8 = 1;
const RESERVED_1_PADDING: [u8; 6] = [0u8; 6];
const RESERVED_2_PADDING: [u8; 4] = [0u8; 4];
const RESERVED_3_PADDING: [u8; 4] = [0u8; 4]; // Marks end of ServerName/TargetInfo in blob
const DEFAULT_SERVER_NAME: &str = "WORKGROUP"; // Often used default, per original code. Real server name might be needed.

// HMAC Constants
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;
const MD5_BLOCK_SIZE: usize = 64;

// --- Custom Error Type ---

/// Represents errors that can occur during NTLM/NetNTLMv2 hash generation.
#[derive(Error, Debug)]
pub enum NtlmError {
    /// Error during hexadecimal decoding (e.g., NTLM hash from hex string).
    #[error("Hex decoding failed: {0}")]
    HexDecoding(#[from] hex::FromHexError),

    /// Represents an underlying I/O error, potentially from password reading if integrated here.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// --- Helper Functions ---

/// Custom implementation of HMAC-MD5 for md5 0.7.0
/// See RFC 2104 for the HMAC algorithm specification
fn hmac_md5(key: &[u8], message: &[u8]) -> Vec<u8> {
    // The key needs to be exactly MD5_BLOCK_SIZE bytes
    let mut key_bytes = if key.len() > MD5_BLOCK_SIZE {
        // If key is longer than block size, hash it first
        let mut context = md5::Context::new();
        context.consume(key);
        context.compute().to_vec()
    } else {
        key.to_vec()
    };

    // Pad the key to exactly MD5_BLOCK_SIZE bytes
    if key_bytes.len() < MD5_BLOCK_SIZE {
        key_bytes.resize(MD5_BLOCK_SIZE, 0);
    }

    // Create the inner and outer padded keys
    let mut ikey = vec![0; MD5_BLOCK_SIZE];
    let mut okey = vec![0; MD5_BLOCK_SIZE];

    for i in 0..MD5_BLOCK_SIZE {
        ikey[i] = key_bytes[i] ^ IPAD;
        okey[i] = key_bytes[i] ^ OPAD;
    }

    // Inner hash: H(K_ipad || message)
    let mut inner_context = md5::Context::new();
    inner_context.consume(&ikey);
    inner_context.consume(message);
    let inner_hash = inner_context.compute();

    // Outer hash: H(K_opad || inner_hash)
    let mut outer_context = md5::Context::new();
    outer_context.consume(&okey);
    outer_context.consume(inner_hash.as_ref());
    outer_context.compute().to_vec()
}

// --- Core Functions ---

/// Calculates the NTLM hash (MD4) of a password.
///
/// The NTLM hash is defined as the MD4 hash of the password encoded in UTF-16 Little Endian.
/// See [MS-NLMP] Section 3.3.1 for context on NTLM hash usage.
///
/// # Arguments
/// * `password` - The user's password.
///
/// # Returns
/// A `String` containing the lowercase hexadecimal representation of the NTLM hash.
pub fn ntlm(password: &str) -> String {
    // Encode password to UTF-16 Little Endian bytes
    let password_utf16: Vec<u16> = password.encode_utf16().collect();
    let mut password_bytes = Vec::with_capacity(password_utf16.len() * 2);
    for char_code in password_utf16 {
        password_bytes.extend_from_slice(&char_code.to_le_bytes());
    }

    // Calculate MD4 hash
    let mut hasher = Md4::new();
    // update/finalize methods come from the Md4Digest trait (aliased from digest::Digest)
    hasher.update(&password_bytes);
    let result = hasher.finalize();

    hex::encode(result)
}

/// Generates the NetNTLMv2 hash string based on user credentials and challenges.
///
/// This function implements the core steps of NTLMv2 authentication challenge-response
/// generation as described in [MS-NLMP] Section 3.3.2. It constructs the NTLMv2 Response,
/// which includes the NTProofStr (HMAC-MD5) and the Blob structure.
///
/// # Arguments
/// * `user` - The username.
/// * `domain` - The target domain or workstation name.
/// * `password` - The user's password.
///
/// # Returns
/// A `Result` containing:
/// * `Ok(String)`: The successfully generated NetNTLMv2 hash string in the format:
///   `user::domain:server_challenge_hex:nt_proof_string_hex:blob_hex`
/// * `Err(NtlmError)`: An error indicating failure during the process (e.g., hex decoding, HMAC issues).
///
/// # Security Note
/// This function generates cryptographic material based on provided secrets. Ensure the
/// `password` argument is handled securely by the calling code.
///
/// # Timestamp Note
/// The Blob timestamp generated follows the practice of the original Python code, using
/// Unix epoch seconds (`Utc::now().timestamp()`) converted to 8 bytes LE. The strict
/// [MS-NLMP] specification requires a Windows FILETIME (64-bit LE unsigned integer
/// representing 100ns intervals since 1601-01-01 UTC). Use this function with awareness
/// of this potential discrepancy if strict protocol adherence is required.
pub fn net_ntlm_v2(user: &str, domain: &str, password: &str) -> Result<String, NtlmError> {
    // --- Timestamp ---
    let now_utc = Utc::now();
    let timestamp_secs = now_utc.timestamp();
    let timestamp_bytes: [u8; 8] = timestamp_secs.to_le_bytes();

    // --- Challenges ---
    #[allow(deprecated)] // Suppress potentially spurious warning for thread_rng call
    let mut rng = thread_rng();
    let mut client_challenge = [0u8; 8];
    let mut server_challenge = [0u8; 8];
    // Use fill_bytes from the RngCore trait
    rng.fill_bytes(&mut client_challenge);
    rng.fill_bytes(&mut server_challenge);

    // --- Blob Construction ([MS-NLMP] Section 2.2.1.2 TARGET_INFO) ---
    let server_name_utf16: Vec<u16> = DEFAULT_SERVER_NAME.encode_utf16().collect();
    let mut server_name_bytes = Vec::with_capacity(server_name_utf16.len() * 2);
    for char_code in server_name_utf16 {
        server_name_bytes.extend_from_slice(&char_code.to_le_bytes());
    }

    let blob_len = 1 + 1 // RespVer + HiRespVer
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

    // --- NTLM Hash ---
    let ntlm_hash_hex = ntlm(password);
    let ntlm_hash = hex::decode(ntlm_hash_hex)?;

    // --- Response Keys Calculation ([MS-NLMP] Section 3.3.2) ---

    // 1. Calculate `ResponseKeyNT`
    //    `ResponseKeyNT = HMAC-MD5(NTLMHash, UPPERCASE(Username) + Domain)` (message encoded UTF-16LE)
    let user_upper = user.to_uppercase();
    let hmac1_msg_str = format!("{}{}", user_upper, domain);
    let hmac1_msg_utf16: Vec<u16> = hmac1_msg_str.encode_utf16().collect();
    let mut hmac1_msg_bytes = Vec::with_capacity(hmac1_msg_utf16.len() * 2);
    for char_code in hmac1_msg_utf16 {
        hmac1_msg_bytes.extend_from_slice(&char_code.to_le_bytes());
    }

    // Calculate HMAC-MD5 for ResponseKeyNT
    let response_key_nt = hmac_md5(&ntlm_hash, &hmac1_msg_bytes);

    // 2. Calculate `NTProofStr`
    //    `NTProofStr = HMAC-MD5(ResponseKeyNT, ServerChallenge + Blob)`
    let mut server_challenge_with_blob = Vec::with_capacity(server_challenge.len() + blob.len());
    server_challenge_with_blob.extend_from_slice(&server_challenge);
    server_challenge_with_blob.extend_from_slice(&blob);

    let nt_proof_bytes = hmac_md5(&response_key_nt, &server_challenge_with_blob);

    // --- Formatting Output ---
    let server_challenge_hex = hex::encode(server_challenge);
    let nt_proof_string_hex = hex::encode(&nt_proof_bytes);
    let blob_hex = hex::encode(&blob);

    // Construct the final output string in the standard NetNTLMv2 format.
    Ok(format!(
        "{}::{}:{}:{}:{}",
        user,
        domain,
        server_challenge_hex,
        nt_proof_string_hex,
        blob_hex
    ))
}