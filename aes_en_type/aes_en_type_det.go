package aesentype

type AesTypeDetection struct{}

// if 16 return aes128
// if 24 return aes192
// if 32 return aes256
func (aes_det *AesTypeDetection) DetectAesType(enData string) (string, error) {
	return "", nil
}
