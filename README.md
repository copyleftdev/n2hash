# n2hash

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

A Rust implementation of NTLM and NetNTLMv2 hashing for password security analysis and authentication testing.

## Overview

n2hash provides efficient and secure implementations of NTLM and NetNTLMv2 hashing algorithms used in Windows authentication systems. This library allows security researchers, penetration testers, and system administrators to work with these authentication protocols for legitimate security testing and analysis.

## Features

- **NTLM Hash Generation**: Fast computation of NTLM hashes (MD4 of UTF-16LE encoded passwords)
- **NetNTLMv2 Hash Generation**: Complete implementation of the NTLMv2 challenge-response protocol
- **Pure Rust Implementation**: Fully implemented in Rust with minimal dependencies
- **RFC Compliant**: Follows MS-NLMP protocol specifications
- **Custom HMAC-MD5**: Includes an efficient custom implementation of HMAC-MD5 based on RFC 2104

## Installation

### Using Makefile

The project includes a Makefile that simplifies installation:

```bash
# Build the project
make build

# Install to user's local bin (~/.local/bin)
make install

# Install system-wide (requires sudo)
make install-system

# Uninstall from local bin
make uninstall

# Uninstall from system-wide location
make uninstall-system
```

### Manual Installation

```bash
# Build the project
cargo build --release

# The binary will be available at
# target/release/n2hash
```

## Usage

The tool provides two main functions:

- **NTLM Hash**: Generate an NTLM hash from a password
- **NetNTLMv2 Hash**: Generate a NetNTLMv2 hash with username, domain, and password

Basic command syntax:

```
n2hash ntlm <password>
n2hash netntlmv2 <username> <domain> <password>
```

## Cryptographic Details

### NTLM Hash

The NTLM hash is calculated as the MD4 hash of the UTF-16LE encoded password.

### NetNTLMv2 Hash

NetNTLMv2 involves:
1. NTLM hash of password
2. NTLMv2 key generation using HMAC-MD5
3. Blob structure with version, timestamp, and challenge data
4. NTProofStr calculation using HMAC-MD5

The output format is: `username::domain:server_challenge:nt_proof_string:blob`

## Security Considerations

This tool is intended for legitimate security testing, password migration, and educational purposes only. Always ensure you have proper authorization before using in any environment.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Copyright 2025 [copyleftdev](https://github.com/copyleftdev)
