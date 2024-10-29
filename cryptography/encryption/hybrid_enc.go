package encryption

import (
	"DetectAlg/filesystem/keys"
	"DetectAlg/helpers"
	keydet "DetectAlg/key_det"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
)

type HybridEncryption struct{}

type HybReqData struct {
	Data          string `json:"data"`
	Passphrase    string `json:"passphrase"`
	Algorithm     string `json:"algorithm,omitempty"`
	AlgorithmType string `json:"algorithmType,omitempty"`
	FolderName    string `json:"folderName"`
	PubKey        string `json:"pubKey"`
	PrivKey       string `json:"privKey"`
}

type HybResData struct {
	SymmetricData       string
	EncryptedPassphrase string
	Signature           string
}

type SaveAsymmetricDataRequest struct {
	SymmetricData       string
	AlgSymEnc           string
	EncryptedPassphrase string
	Signature           string
	FolderName          string
}

func (he *HybridEncryption) EncryptSharedData(req HybReqData) (HybResData, error) {
	var pubKey interface{}
	var privKey interface{}

	kd := keydet.KeyTypeDetection{}

	pubKeyType, err := kd.DetectKeyType(req.PubKey)
	if err != nil {
		return HybResData{}, fmt.Errorf("Error ocurred while detecting pub key type: %v ", err)
	}

	privKeyType, err := kd.DetectKeyType(req.PrivKey)
	if err != nil {
		return HybResData{}, fmt.Errorf("Error ocurred while detecting priv key type: %v", err)
	}

	if pubKeyType != privKeyType {
		return HybResData{}, fmt.Errorf("Key type mismatch: Both the public and private keys must be of the same type (either ECC or RSA), but got pub key type: %s and priv key type: %s", pubKeyType, privKeyType)
	}

	switch pubKeyType {
	case "ECC":
		pubKey, err = helpers.ParseECCPublicKey(req.PubKey)
		if err != nil {
			return HybResData{}, fmt.Errorf("failed to parse ECC public key: %v", err)
		}
		privKey, err = helpers.ParseECCPrivateKey(req.PrivKey)
		if err != nil {
			return HybResData{}, fmt.Errorf("failed to parse ECC private key: %v", err)
		}

	case "RSA":
		pubKey, err = helpers.ParseRSAPublicKey(req.PubKey)
		if err != nil {
			return HybResData{}, fmt.Errorf("failed to parse RSA public key: %v", err)
		}
		privKey, err = helpers.ParseRSAPrivateKey(req.PrivKey)
		if err != nil {
			return HybResData{}, fmt.Errorf("failed to parse RSA private key: %v", err)
		}

	default:
		return HybResData{}, fmt.Errorf("unsupported key type")
	}

	aes := Cryptography{}
	aesEncryptData := RequestData{
		Passphrase:    req.Passphrase,
		Data:          req.Data,
		Algorithm:     req.Algorithm,
		AlgorithmType: req.AlgorithmType,
	}
	aesRes, err := aes.EncryptAES(aesEncryptData)
	if err != nil {
		return HybResData{}, fmt.Errorf("AES encryption failed: %v", err)
	}

	var encPassphrase []byte
	switch pubKeyType {
	case "ECC":
		encPassphrase, err = encryptWithECC([]byte(req.Passphrase), pubKey.(*ecdsa.PublicKey))
	case "RSA":
		encPassphrase, err = encryptWithRSA([]byte(req.Passphrase), pubKey.(*rsa.PublicKey))
	}
	if err != nil {
		return HybResData{}, fmt.Errorf("failed to encrypt passphrase: %v", err)
	}
	encPassphraseB64 := base64.StdEncoding.EncodeToString(encPassphrase)

	var signature []byte
	switch pubKeyType {
	case "ECC":
		signature, err = signWithECC([]byte(aesRes), privKey.(*ecdsa.PrivateKey))
	case "RSA":
		signature, err = signWithRSA([]byte(aesRes), privKey.(*rsa.PrivateKey))
	}
	if err != nil {
		return HybResData{}, fmt.Errorf("failed to sign data: %v", err)
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	keyStore := keys.KeyStore{}
	err = keyStore.SaveAsymmetricData(keys.HybridRequestData{
		SymmetricData:       aesRes,
		AlgSymEnc:           req.AlgorithmType,
		EncyrptedPassphrase: encPassphraseB64,
		Signature:           signatureB64,
		FolderName:          req.FolderName,
		AsymAlgType:         pubKeyType,
	})
	if err != nil {
		return HybResData{}, fmt.Errorf("failed to save asymmetric data: %v", err)
	}

	return HybResData{
		SymmetricData:       aesRes,
		EncryptedPassphrase: encPassphraseB64,
		Signature:           signatureB64,
	}, nil
}

func (he *HybridEncryption) PerformHybridEnOnExistingData(req HybReqData) (HybResData, error) {
	var pubKey interface{}
	var privKey interface{}
	var err error

	kd := keydet.KeyTypeDetection{}

	pubKeyType, err := kd.DetectKeyType(req.PubKey)
	if err != nil {
		return HybResData{}, fmt.Errorf("Error ocurred while detecting pub key type: %v", err)
	}

	privKeyType, err := kd.DetectKeyType(req.PrivKey)
	if err != nil {
		return HybResData{}, fmt.Errorf("Error ocurred while detecting priv key type: %v", err)
	}

	if pubKeyType != privKeyType {
		return HybResData{}, fmt.Errorf("Key type mismatch: Both the public and private keys must be of the same type (either ECC or RSA), but got pub key type: %s and priv key type: %s", pubKeyType, privKeyType)
	}

	switch pubKeyType {
	case "ECC":
		pubKey, err = helpers.ParseECCPublicKey(req.PubKey)
		if err != nil {
			return HybResData{}, fmt.Errorf("failed to parse ECC public key: %v", err)
		}
		privKey, err = helpers.ParseECCPrivateKey(req.PrivKey)
		if err != nil {
			return HybResData{}, fmt.Errorf("failed to parse ECC private key: %v", err)
		}

	case "RSA":
		pubKey, err = helpers.ParseRSAPublicKey(req.PubKey)
		if err != nil {
			return HybResData{}, fmt.Errorf("failed to parse RSA public key: %v", err)
		}
		privKey, err = helpers.ParseRSAPrivateKey(req.PrivKey)
		if err != nil {
			return HybResData{}, fmt.Errorf("failed to parse RSA private key: %v", err)
		}

	default:
		return HybResData{}, fmt.Errorf("unsupported key type")
	}

	var encPassphrase []byte
	switch pubKeyType {
	case "ECC":
		encPassphrase, err = encryptWithECC([]byte(req.Passphrase), pubKey.(*ecdsa.PublicKey))
	case "RSA":
		encPassphrase, err = encryptWithRSA([]byte(req.Passphrase), pubKey.(*rsa.PublicKey))
	}
	if err != nil {
		return HybResData{}, fmt.Errorf("failed to encrypt passphrase: %v", err)
	}
	encPassphraseB64 := base64.StdEncoding.EncodeToString(encPassphrase)

	var signature []byte
	switch pubKeyType {
	case "ECC":
		signature, err = signWithECC([]byte(req.Data), privKey.(*ecdsa.PrivateKey))
	case "RSA":
		signature, err = signWithRSA([]byte(req.Data), privKey.(*rsa.PrivateKey))
	}
	if err != nil {
		return HybResData{}, fmt.Errorf("failed to sign data: %v", err)
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	keyStore := &keys.KeyStore{}
	err = keyStore.SaveAsymmetricData(keys.HybridRequestData{
		SymmetricData:       req.Data,
		AlgSymEnc:           req.AlgorithmType,
		EncyrptedPassphrase: encPassphraseB64,
		Signature:           signatureB64,
		FolderName:          req.FolderName,
		AsymAlgType:         pubKeyType,
	})
	if err != nil {
		return HybResData{}, fmt.Errorf("failed to save asymmetric data: %v", err)
	}

	return HybResData{
		SymmetricData:       req.Data,
		EncryptedPassphrase: encPassphraseB64,
		Signature:           signatureB64,
	}, nil
}

func encryptWithECC(data []byte, pubKey *ecdsa.PublicKey) ([]byte, error) {
	ephemeralPrivKey, err := ecdsa.GenerateKey(pubKey.Curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key pair: %v", err)
	}
	sharedSecretX, _ := pubKey.ScalarMult(pubKey.X, pubKey.Y, ephemeralPrivKey.D.Bytes())
	sharedSecret := sha256.Sum256(sharedSecretX.Bytes())

	block, err := aes.NewCipher(sharedSecret[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM: %v", err)
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}
	encryptedData := aesGCM.Seal(nonce, nonce, data, nil)
	ephemeralPubKey := elliptic.Marshal(pubKey.Curve, ephemeralPrivKey.X, ephemeralPrivKey.Y)

	var buf bytes.Buffer
	buf.Write([]byte{byte(len(ephemeralPubKey) >> 8), byte(len(ephemeralPubKey) & 0xff)})
	buf.Write(ephemeralPubKey)
	buf.Write(encryptedData)
	return buf.Bytes(), nil
}

func encryptWithRSA(data []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt with RSA: %v", err)
	}
	return encryptedData, nil
}

type ECDSASignature struct {
	R, S *big.Int
}

func signWithECC(data []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign with ECC: %v", err)
	}
	sig, err := asn1.Marshal(ECDSASignature{R: r, S: s})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature: %v", err)
	}
	return sig, nil
}

func signWithRSA(data []byte, privKey *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign with RSA: %v", err)
	}
	return signature, nil
}
