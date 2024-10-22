package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

type KeysData struct {
	EcPub   string
	EcPriv  string
	RsaPub  string
	RsaPriv string
}

type KeyTypeDetection struct{}

func (kd *KeyTypeDetection) DetectKeyType(keyData string) (string, error) {
	keyData = cleanKeyData(keyData)

	block, _ := pem.Decode([]byte(keyData))
	if block == nil {
		return "", errors.New("failed to decode PEM block")
	}

	switch block.Type {
	case "PGP PUBLIC KEY", "PUBLIC KEY":
		if pubKey, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			switch pubKey.(type) {
			case *rsa.PublicKey:
				return "RSA Public Key (PKIX Format)", nil
			case *ecdsa.PublicKey:
				return "ECC Public Key", nil
			default:
				return "Unknown Public Key Type", nil
			}
		}

		if _, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
			return "RSA Public Key (PKCS1 Format)", nil
		}

		return "", errors.New("failed to parse public key (use ParsePKCS1PublicKey instead for this key format)")

	case "PGP PRIVATE KEY", "PRIVATE KEY", "RSA PRIVATE KEY":
		if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return "ECC Private Key", nil
		}

		if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return "RSA Private Key (PKCS1 Format)", nil
		}

		if privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			switch privKey.(type) {
			case *rsa.PrivateKey:
				return "RSA Private Key (PKCS8 Format)", nil
			case *ecdsa.PrivateKey:
				return "ECC Private Key", nil
			}
		}

		return "", errors.New("failed to parse private key")

	default:
		return "", errors.New("unknown key format")
	}
}

func cleanKeyData(keyData string) string {
	return strings.TrimSpace(keyData)
}

func main() {
	myKeys := KeysData{
		EcPub: `-----BEGIN PGP PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2X6UZ3awWndzx8C97fPnaNpIx6ZQ
K7GcNvbYYL7OlS4z5/LsAx5ZEludUNBWA4OezA6gD4ZXvk5FSA3l3fDr6w==
-----END PGP PUBLIC KEY-----
`,
		EcPriv: `-----BEGIN PGP PRIVATE KEY-----
MHcCAQEEIGmLCsYUep3n7ylm9NM2mPsnigKzU/yz5weLzUVtRONGoAoGCCqGSM49
AwEHoUQDQgAE2X6UZ3awWndzx8C97fPnaNpIx6ZQK7GcNvbYYL7OlS4z5/LsAx5Z
EludUNBWA4OezA6gD4ZXvk5FSA3l3fDr6w==
-----END PGP PRIVATE KEY-----
`,
		RsaPub: `-----BEGIN PGP PUBLIC KEY-----
MIICCgKCAgEA0LtzEp05MEX54aM07hUjZizwEf2WugXPB7W2lxc8eHijmQ6qktxK
tX9sDKeUj9EqQUY2BqVvnIYUbWGJla7iyUktJs4h2lnZny7rcAQOawyYYZo2w8sQ
FmV9wM4Jw8M41JoWUHc/tC5M4FT46WStC+W34F1glCR6cRoLY0zY/d407sY4pcAU
A2u98OaBvDfjueK4bnvj+2F1Qp5Zmcmw+jBjf0/YDp1Jd5P24aTD9PrPgDPUQFvu
0FvUXzpclg43VPnciRYvZz8gQFPj5gFf0YUinMtENWmqhHoFcA42ZKniGFzRyoSI
JRAsLAfPohfx3TGoqntSprFdCjxb7WkO9hgJHTh+21aINselMnSWS3VpprRGZ0I+
1wIP+nmjCSjRy7PQjaiFEXbrBSpXHPg8U1UvVhC/yLFIJDHufJMheaK1ljHp6nkI
4TJgWnUrQDlCKBFMRgiLZ+rokVrjwoRAqwBhXwRUNA9HhuT/96NJTZtSI3/CUajn
+SPdN/3o044om6JM6nOWcCYSPt37bEU/EVYfEQ9CzT2j6QOp9O+migt+7s1lCadJ
6kk6lnclCvC6kcnQ/at7qxZjhW8v7gh0igDsRHG/EyXgiuoJnduK8CTLJRnAaqte
LkJ9h+XA5ix8SZhw3yTNlqCgQRrIFta2+hN0KLumQfHl5Cqco0oXefUCAwEAAQ==
-----END PGP PUBLIC KEY-----
`,
		RsaPriv: `-----BEGIN PGP PRIVATE KEY-----
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
-----END PGP PRIVATE KEY-----
`,
	}

	fmt.Println(myKeys)

	kd := KeyTypeDetection{}
	if keyType, err := kd.DetectKeyType(myKeys.EcPub); err == nil {
		fmt.Println("ECC Public Key Type:", keyType)
	} else {
		fmt.Println("Error detecting ECC public key type:", err)
	}

	if keyType, err := kd.DetectKeyType(myKeys.EcPriv); err == nil {
		fmt.Println("ECC Private Key Type:", keyType)
	} else {
		fmt.Println("Error detecting ECC private key type:", err)
	}

	if keyType, err := kd.DetectKeyType(myKeys.RsaPub); err == nil {
		fmt.Println("RSA Public Key Type:", keyType)
	} else {
		fmt.Println("Error detecting RSA public key type:", err)
	}

	if keyType, err := kd.DetectKeyType(myKeys.RsaPriv); err == nil {
		fmt.Println("RSA Private Key Type:", keyType)
	} else {
		fmt.Println("Error detecting RSA private key type:", err)
	}
}
