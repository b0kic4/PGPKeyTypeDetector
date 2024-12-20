package helpers

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

func RemovePEMBlocks(pemKey string) (string, error) {
	cleanedKey := strings.ReplaceAll(pemKey, "-----BEGIN PGP PRIVATE KEY-----", "")
	cleanedKey = strings.ReplaceAll(cleanedKey, "-----END PGP PRIVATE KEY-----", "")
	cleanedKey = strings.ReplaceAll(cleanedKey, "-----BEGIN PGP PUBLIC KEY-----", "")
	cleanedKey = strings.ReplaceAll(cleanedKey, "-----END PGP PUBLIC KEY-----", "")

	// Remove all unnecessary spaces, newlines, and carriage returns
	cleanedKey = strings.ReplaceAll(cleanedKey, "\n", "")
	cleanedKey = strings.ReplaceAll(cleanedKey, "\r", "")
	cleanedKey = strings.TrimSpace(cleanedKey)

	// Remove all spaces within the base64 string
	cleanedKey = strings.ReplaceAll(cleanedKey, " ", "")

	// Check if the cleaned key is valid base64
	_, err := base64.StdEncoding.DecodeString(cleanedKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode cleaned key: %v", err)
	}

	return cleanedKey, nil
}

func ParseECCPublicKey(pubKey string) (*ecdsa.PublicKey, error) {
	cleanedKey, err := RemovePEMBlocks(pubKey)
	if err != nil {
		return nil, fmt.Errorf("error when removing pem blocks: %w", err)
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(cleanedKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding public key: %v", err)
	}
	publicKeyInterface, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}
	ecdsaPubKey, ok := publicKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}
	return ecdsaPubKey, nil
}

func ParseECCPrivateKey(privKey string) (*ecdsa.PrivateKey, error) {
	cleanedKey, err := RemovePEMBlocks(privKey)
	if err != nil {
		return nil, fmt.Errorf("error when removing pem blocks: %w", err)
	}

	privKeyBytes, err := base64.StdEncoding.DecodeString(cleanedKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding private key: %v", err)
	}
	ecdsaPrivKey, err := x509.ParseECPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %v", err)
	}
	return ecdsaPrivKey, nil
}

// RSA
func ParseRSAPublicKey(pubKey string) (*rsa.PublicKey, error) {
	cleanedKey, err := RemovePEMBlocks(pubKey)
	if err != nil {
		return nil, fmt.Errorf("error when removing pem blocks: %w", err)
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(cleanedKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding public key: %v", err)
	}
	rsaPubKey, err := x509.ParsePKCS1PublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing rsa public key: %v", err)
	}

	return rsaPubKey, nil
}

func ParseRSAPrivateKey(privKey string) (*rsa.PrivateKey, error) {
	cleanedKey, err := RemovePEMBlocks(privKey)
	if err != nil {
		return nil, fmt.Errorf("error when removing pem blocks: %w", err)
	}

	privKeyBytes, err := base64.StdEncoding.DecodeString(cleanedKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding private key: %v", err)
	}
	rsaPrivKey, err := x509.ParsePKCS1PrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %v", err)
	}
	return rsaPrivKey, nil
}
