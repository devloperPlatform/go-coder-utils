package coder

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestSm4Encrypt(t *testing.T) {
	key := []byte("1234567890123456")
	data := "中国12451231246....564/*/wwersdfa  ws"
	encrypt, err := Sm4Encrypt(key, []byte(data))
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))

	sm4Encrypt, err := Sm4Encrypt(Sm4RandomKey(), []byte(data))
	if err != nil {
		panic(err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(sm4Encrypt))

}

func TestSm4Decrypt(t *testing.T) {
	key := []byte("1234567890123456")
	encryptData := "Rf88eXENS1ws1FgHT1H5QeItkZY/2RN70w4+26+qZz9MsTfjtOiuAfrZG5NxBV3z"
	dataBytes, _ := base64.StdEncoding.DecodeString(encryptData)
	decrypt, err := Sm4Decrypt(key, dataBytes)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(decrypt))

	d := "TbR13baVdMLfS2JKCFYiqNyqNvzOzr2pxeCYLIQ8grmxB2OxWhvNqbegB7AoixcRCuWV6Z2wB5d3ngScocEixafLZV67cfgYGDDBgSkygYpa3+zk5iRYAWwBD6GKHajZ2ffVo9P/+m2///hHkgoVcwUCAexcR50DG5p4SYNoPlar4dwjPg0POgM0WWrd2PIbH+KVbGq8Wc25SDSkjghPo9fpXwefMkVcX8JPwVqISEvnCqcuzW5cKGghkbhPGHtbzweW1sVxMjP0P7RMvAwbx8YKiLeVs3FqYXWQgRWiZoB5/H6rTbufaug8Lo2edRHYr7Of61Ug8ZPK1lM7syaO0l6FzwnLsGrXuB/x9TChVartPCI7OWSKakh1TTOwXXZ1zE5hlHLjlMjEgK0OqvurajlZAhmi+ZZbZ7AXY16SiULOmgyieMcne9mIIGhwr3i+9LuKfNGN0924DrIz6Qtw65QRsucvfQJ6o9b2LEtzagZbAzRNm+LFan/pa4hwhruHToER/oshg3AiElPstPih+TndvQxHpAjEq0a3GDoOLP/vfpIWgodzUCn0nzGqQnYI+aOu/uHgWUyN+lhQ2CwlcT7GRezwCvQe4jBAl9173MIj5jvVhc/W7GItqTgk0SHeGCfFq2LNCMrjgKCkafjrFGNT1jP/gvFJ8IR2NGvBlQDYrqh+y9pcUhBSHLoKqH9x/bSOmTs9azqOgBTgQ1gm+gSlejSPeZ3/mgxy/+4/R9DkfSzqaDPjNWcTyBPf8e9Qt0CNggFuYQiLULLdx+tuE51wxJlu9AybFnIHA0E52uugYHmolQS+wmXLEsyr3TCV7k3aWio4MbNFrQmiKzZqsZ7/rBp5aula5baYucz5hpa5ROaL4TcS3JDbOa0ZZlph15s5437jjasKo/aa7BgBOzXAptRw+KrCJvNSXqQpL+BA6asy773yHKTYObkNtDwOpshrqnGgWblSfPbG8suL3YS9BQpL31mo/a7gO/PgoROYdpnEqu6KjJLrc3q21GyHwQEo0aO0rKEJB+/p9KgDHrzlmUMMbwqwIjyjOD+hdkK7KYxHspGs1uiF4JuRQhhRBDnaZkCgjnFD+HUXXg+PEmI9dcS6GtsoMQ1kDZ01udkq1pljhgiAWMD9cxdjUWdsC+/gcWie0qcDRq8jCrdiLqtkc4KpGVXrCOE0Xn7f8nZ15YEVs1NfTSSwXmT5d6g12M1frDms7P1f9bk9YC6Paw917/CRk0b1Q5iZ59GV20HRUF5OnUXKQwXVRtDVxNNX"
	decodeString, _ := base64.StdEncoding.DecodeString(d)
	sum := md5.Sum([]byte("130481199812060018"))
	result, err := Sm4Decrypt(sum[:], decodeString)
	fmt.Println(result)

}

func TestSm2Encrypt(t *testing.T) {
	pemPublicKey := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEm6olWsLtjbItjHG6FHUepSNMoSoV
zefyiVYdkTIvgYaTQVOTk0VahwHXFkPgK+9OaR9XAkRusIAN/EuxqmDFXg==
-----END PUBLIC KEY-----`
	data := "我爱中国!!!123456.."
	encrypt, err := Sm2Encrypt(pemPublicKey, []byte(data))
	if err != nil {
		t.Error(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypt))
}

func TestSm2Decrypt(t *testing.T) {
	pemPrivateKey := `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQghqNYepKd1uDtw8LV
V6pfB7rGNqq4J3m8+/m4abTafvygCgYIKoEcz1UBgi2hRANCAASbqiVawu2Nsi2M
cboUdR6lI0yhKhXN5/KJVh2RMi+BhpNBU5OTRVqHAdcWQ+Ar705pH1cCRG6wgA38
S7GqYMVe
-----END PRIVATE KEY-----`
	decodeString, _ := base64.StdEncoding.DecodeString("BOAtdabrnhFAtE/s6Tlb/OUwblhBDrr4oqf3Ff/HiH+9yBUuHVuFCKskFIm8xsFgMu2NigBh7oG266t/KtzTyiGWRy9Ufp/gW4tMwr4dRFfGvFM2JgmOogrsuUBC3B2A3ralSaMIS+ykOxji2oTM9g==")
	decrypt, err := Sm2Decrypt(pemPrivateKey, decodeString)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(string(decrypt))
}
