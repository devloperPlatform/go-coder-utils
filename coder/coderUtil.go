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
	block, _ := pem.Decode([]byte(pemPublicKey))
	if block == nil {
		return nil, errors.New("解析公钥信息失败")
	}
	key, err := x509.ParseSm2PublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("转换公钥信息失败")
	}
	encrypt, err := sm2.Encrypt(key, data, cryptoRand.Reader)
	if err != nil {
		return nil, errors.New("加密数据失败")
	}
	return encrypt, err
}

// Sm2Decrypt sn2解密
func Sm2Decrypt(pemPrivateKey string, data []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	if block == nil {
		return nil, errors.New("解析私钥信息失败")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes, nil)
	if err != nil {
		return nil, errors.New("转换私钥信息失败")
	}
	decrypt, err := sm2.Decrypt(key, data)
	if err != nil {
		return nil, errors.New("解密数据失败")
	}
	return decrypt, nil
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
