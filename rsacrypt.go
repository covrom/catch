package catch

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
)

// GenerateKeyPair generates an RSA key pair of the given bit size
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privkey, &privkey.PublicKey, nil
}

// PrivateKeyToBytes converts an RSA private key to PKCS#1 ASN.1 DER bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(priv)
}

// PublicKeyToBytes converts an RSA public key to PKIX ASN.1 DER bytes
func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

// BytesToPrivateKey converts PKCS#1 ASN.1 DER bytes to an RSA private key
func BytesToPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(priv)
}

// BytesToPublicKey converts PKIX ASN.1 DER bytes to an RSA public key
func BytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	pb, err := x509.ParsePKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	if pub, ok := pb.(*rsa.PublicKey); ok {
		return pub, nil
	}

	return nil, fmt.Errorf("Expected *rsa.PublicKey, got %T", pb)
}

// chunkBy splits a slice into chunks of the given size
func chunkBy[T any](items []T, chunkSize int) (chunks [][]T) {
	for chunkSize < len(items) {
		items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
	}
	return append(chunks, items)
}

// EncryptWithPublicKey encrypts a message using RSA-OAEP with SHA512
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha512.New()

	// Chunk the message into smaller parts
	var chunkSize = pub.N.BitLen()/8 - 2*hash.Size() - 2
	var result []byte
	chunks := chunkBy[byte](msg, chunkSize)
	for _, chunk := range chunks {
		ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, chunk, nil)
		if err != nil {
			return []byte{}, err
		}
		result = append(result, ciphertext...)
	}

	return result, nil
}

// DecryptWithPrivateKey decrypts a message using RSA-OAEP with SHA512
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha512.New()
	dec_msg := []byte("")

	for _, chnk := range chunkBy[byte](ciphertext, priv.N.BitLen()/8) {
		plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, chnk, nil)
		if err != nil {
			return []byte{}, err
		}
		dec_msg = append(dec_msg, plaintext...)
	}

	return dec_msg, nil
}

// SignWithPrivateKey signs a message using RSA PKCS#1v1.5 with SHA256
func SignWithPrivateKey(msg []byte, priv *rsa.PrivateKey) ([]byte, error) {
	mHash := crypto.SHA256
	hasher := mHash.New()
	hasher.Write(msg)

	// Sign the string and return the encoded bytes
	if sigBytes, err := rsa.SignPKCS1v15(rand.Reader, priv, mHash, hasher.Sum(nil)); err == nil {
		return sigBytes, nil
	} else {
		return nil, err
	}
}

// VerifyWithPublicKey verifies a message signature using RSA PKCS#1v1.5 with SHA256
func VerifyWithPublicKey(msg []byte, sig []byte, pubkey *rsa.PublicKey) error {
	mHash := crypto.SHA256
	hasher := mHash.New()
	hasher.Write(msg)

	// Verify the signature
	return rsa.VerifyPKCS1v15(pubkey, mHash, hasher.Sum(nil), sig)
}