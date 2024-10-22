# PGP Key Type Detector

## Overview
PGP Key Type Detector is a Go-based tool designed to detect the type of PGP keys. The program can identify whether the provided key is:

- **ECC Public Key**
- **ECC Private Key**
- **RSA Public Key** (PKIX or PKCS1 format)
- **RSA Private Key** (PKCS1 or PKCS8 format)

The tool parses keys encoded in PEM format and detects whether the key is a public or private key and whether it's based on **ECC** or **RSA** algorithms.

## Features
- Detects **ECC** (Elliptic Curve Cryptography) keys:
  - ECC Public Key
  - ECC Private Key
- Detects **RSA** (Rivest–Shamir–Adleman) keys:
  - RSA Public Key (both PKIX and PKCS1 formats)
  - RSA Private Key (both PKCS1 and PKCS8 formats)

## Usage
### Input
The tool takes PEM-encoded keys, with headers such as:
- `-----BEGIN PUBLIC KEY-----` (for public keys)
- `-----BEGIN PRIVATE KEY-----` (for private keys)

### Output
The tool returns one of the following:
- **ECC Public Key**
- **ECC Private Key**
- **RSA Public Key** (PKIX format or PKCS1 format)
- **RSA Private Key** (PKCS1 format or PKCS8 format)

## Example

```go
myKeys := KeysData{
    EcPub:  `-----BEGIN PUBLIC KEY-----
            (Your ECC public key here)
            -----END PUBLIC KEY-----`,
    EcPriv: `-----BEGIN PRIVATE KEY-----
            (Your ECC private key here)
            -----END PRIVATE KEY-----`,
    RsaPub: `-----BEGIN PUBLIC KEY-----
            (Your RSA public key here)
            -----END PUBLIC KEY-----`,
    RsaPriv: `-----BEGIN PRIVATE KEY-----
            (Your RSA private key here)
            -----END PRIVATE KEY-----`,
}

keyType, err := kd.DetectKeyType(myKeys.EcPub)
fmt.Println("Detected Key Type:", keyType)
