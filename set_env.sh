export N2HASH_USERNAME="TestUser"
export N2HASH_DOMAIN="Workstation"
export N2HASH_PASSWORD="SecretPassword123"
./target/release/n2hash
# Output will be colorized
unset N2HASH_USERNAME N2HASH_DOMAIN N2HASH_PASSWORD # Clean up