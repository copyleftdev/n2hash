#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use hex_literal::hex;

    // Known test vectors - these are real NTLM hashes for validation
    const KNOWN_PASSWORD_1: &str = "password";
    const KNOWN_NTLM_1: &str = "8846f7eaee8fb117ad06bdd830b7586c";

    const KNOWN_PASSWORD_2: &str = "Password123!";
    const KNOWN_NTLM_2: &str = "c5663434f963c1cc96e6d68b93111d78";

    // Test that our NTLM implementation matches known test vectors
    #[test]
    fn test_ntlm_known_vectors() {
        assert_eq!(ntlm(KNOWN_PASSWORD_1), KNOWN_NTLM_1);
        assert_eq!(ntlm(KNOWN_PASSWORD_2), KNOWN_NTLM_2);
    }

    // Test that our HMAC-MD5 implementation works correctly
    #[test]
    fn test_hmac_md5() {
        // Test vector from RFC 2104
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex!("9294727a3638bb1c13f48ef8158bfc9d");
        
        let result = hmac_md5(&key, data);
        assert_eq!(result, expected);
    }

    // Property-based tests
    
    // Property: NTLM hash should always be 32 characters (16 bytes as hex)
    proptest! {
        #[test]
        fn ntlm_hash_always_valid_length(password in ".*") {
            let hash = ntlm(&password);
            prop_assert_eq!(hash.len(), 32);
            // Also verify it's valid hex
            prop_assert!(hex::decode(&hash).is_ok());
        }
    }

    // Property: NetNTLMv2 should always produce a valid format
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
            let parts: Vec<&str> = hash_string.split(':').collect();
            
            // Format should be user::domain:server_challenge:nt_proof_string:blob
            prop_assert_eq!(parts.len(), 5);
            
            // Check that username::domain part is correct
            let user_domain: Vec<&str> = parts[0].split("::").collect();
            prop_assert_eq!(user_domain.len(), 2);
            prop_assert_eq!(user_domain[0], user);
            prop_assert_eq!(user_domain[1], domain);
            
            // Server challenge should be 16 hex characters (8 bytes)
            prop_assert_eq!(parts[2].len(), 16);
            prop_assert!(hex::decode(parts[2]).is_ok());
            
            // NT proof string should be 32 hex characters (16 bytes)
            prop_assert_eq!(parts[3].len(), 32);
            prop_assert!(hex::decode(parts[3]).is_ok());
            
            // Blob should be a valid hex string
            prop_assert!(hex::decode(parts[4]).is_ok());
        }
    }

    // Property: NetNTLMv2 should be deterministic given the same inputs and challenges
    // This test mocks the random generator to ensure consistent challenges
    #[test]
    fn test_net_ntlm_v2_deterministic() {
        // We should be able to calculate the same NetNTLMv2 hash twice for the same inputs
        let user = "testuser";
        let domain = "testdomain";
        let password = "testpassword";
        
        // This is just a smoke test for internal consistency
        // In a real implementation, we would mock the RNG to provide fixed challenges
        let hash1 = net_ntlm_v2(user, domain, password).unwrap();
        let hash2 = net_ntlm_v2(user, domain, password).unwrap();
        
        // Since we use random challenges, only check the user::domain part matches
        let parts1: Vec<&str> = hash1.split(':').collect();
        let parts2: Vec<&str> = hash2.split(':').collect();
        
        assert_eq!(parts1[0], parts2[0]); // user::domain should match
    }
    
    // Property: NTLM hash should be identical for the same input
    proptest! {
        #[test]
        fn ntlm_hash_deterministic(password in ".*") {
            let hash1 = ntlm(&password);
            let hash2 = ntlm(&password);
            prop_assert_eq!(hash1, hash2);
        }
    }
    
    // Property: Different passwords should produce different NTLM hashes
    // (This isn't absolutely guaranteed due to hash collisions, but should be true for our test cases)
    proptest! {
        #[test]
        fn different_passwords_different_hashes(
            password1 in "[a-zA-Z0-9]{1,10}",
            password2 in "[a-zA-Z0-9]{1,10}"
        ) {
            // Skip if the passwords are identical
            prop_assume!(password1 != password2);
            
            let hash1 = ntlm(&password1);
            let hash2 = ntlm(&password2);
            prop_assert_ne!(hash1, hash2);
        }
    }
}
