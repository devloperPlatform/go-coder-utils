package coder

import (
	cryptoRand "crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
	"github.com/tjfoc/gmsm/x509"
	"math/rand"
	"time"
)

// Sm4Encrypt sm4加密
func Sm4Encrypt(key, plainText []byte) ([]byte, error) {
	return sm4.Sm4Ecb(key, plainText, true)
}

// Sm4Decrypt sm4解密
func Sm4Decrypt(key, cipherText []byte) ([]byte, error) {
	return sm4.Sm4Ecb(key, cipherText, false)
}

// Sm4RandomKey Sm4随机ke
func Sm4RandomKey() []byte {
	return []byte(GetRandomString(16))[:16]
}

// Sm2Encrypt Sm2加密
func Sm2Encrypt(pemPublicKey string, data []byte) ([]byte, error) {
	key, err := ConvertPemToPublicKey(pemPublicKey)
	if err != nil {
		return nil, err
	}
	encrypt, err := sm2.Encrypt(key, data, cryptoRand.Reader)
	if err != nil {
		return nil, errors.New("加密数据失败")
	}
	return encrypt, err
}

// Sm2Decrypt sn2解密
func Sm2Decrypt(pemPrivateKey string, data []byte) ([]byte, error) {
	key, err := ConvertPemToPrivateKey(pemPrivateKey)
	if err != nil {
		return nil, err
	}
	decrypt, err := sm2.Decrypt(key, data)
	if err != nil {
		return nil, errors.New("解密数据失败")
	}
	return decrypt, nil
}

func Sm2Sign(pemPrivateKey string, data []byte) ([]byte, error) {
	key, err := ConvertPemToPrivateKey(pemPrivateKey)
	if err != nil {
		return nil, err
	}

	return Sm2SignWithKey(key, data)
}

func Sm2VerifySign(pemPubKey string, sign, data []byte) (bool, error) {
	key, err := ConvertPemToPublicKey(pemPubKey)
	if err != nil {
		return false, err
	}
	return Sm2VerifySignWithKey(key, sign, data), nil
}

func Sm2VerifySignWithKey(publicKey *sm2.PublicKey, sign, data []byte) bool {
	return publicKey.Verify(sign, data)
}

func Sm2SignWithKey(privateKey *sm2.PrivateKey, data []byte) ([]byte, error) {
	return privateKey.Sign(cryptoRand.Reader, data, nil)
}

func ConvertPemToPublicKey(pubPem string) (*sm2.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPem))
	if block == nil {
		return nil, errors.New("解析公钥信息失败")
	}
	key, err := x509.ParseSm2PublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("转换公钥信息失败")
	}

	return key, nil
}

func ConvertPemToPrivateKey(privateKeyPem string) (*sm2.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPem))
	if block == nil {
		return nil, errors.New("解析私钥信息失败")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes, nil)
	if err != nil {
		return nil, errors.New("转换私钥信息失败")
	}

	return key, nil
}

func ConvertPemToPubAndPriKey(pubKeyPem, privateKeyPem string) (*sm2.PublicKey, *sm2.PrivateKey, error) {
	pubKey, err := ConvertPemToPublicKey(pubKeyPem)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := ConvertPemToPrivateKey(privateKeyPem)
	if err != nil {
		return nil, nil, err
	}

	return pubKey, privateKey, nil
}

// Sm2DecryptByBase64Data sm2解密，数据格式为Base64
func Sm2DecryptByBase64Data(pemPrivateKey string, data string) ([]byte, error) {
	d, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, errors.New("解析数据失败")
	}
	return Sm2Decrypt(pemPrivateKey, d)
}

// GetRandomString 获取指定长度的随机字符串
func GetRandomString(l int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyz~！@#￥%……&*（）——+」|「P:>?/*-+.+*_*+我爱中国^_^"
	//str := "0123456789abcdefghijklmnopqrstuvwxyz"
	bytes := []rune(str)
	result := make([]rune, l, l)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result[i] = bytes[r.Intn(len(bytes))]
		//result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}
