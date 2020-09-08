package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

//
// 封装结构体Rsa的优点
//1.支持PKCS1和PKCS8两种格式的私钥
//2.突破了加解密对数据长度的限制（如果明文长度大于秘钥长度，则需要分段）
//3.签名与验签支持多种数据签名算法

type Rsa struct {
	privateKey    string
	publicKey     string
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  *rsa.PublicKey
}

func NewRsa(publicKey, privateKey string) *Rsa {
	rsaObj := &Rsa{
		privateKey:privateKey,
		publicKey:publicKey,
	}

	rsaObj.init()

	return rsaObj
}

func (this *Rsa) init() {
	if this.privateKey != "" {
		block,_           := pem.Decode([]byte(this.privateKey))

		//pkcs1
		if strings.Index(this.privateKey,"BEGIN RSA") > 0 {
			this.rsaPrivateKey,_ = x509.ParsePKCS1PrivateKey(block.Bytes)
		}else { //pkcs8
			privateKey,_ := x509.ParsePKCS8PrivateKey(block.Bytes)
			this.rsaPrivateKey = privateKey.(*rsa.PrivateKey)
		}
	}

	if this.publicKey != "" {
		block, _ := pem.Decode([]byte(this.publicKey))
		publickKey,_ := x509.ParsePKIXPublicKey(block.Bytes)
		this.rsaPublicKey = publickKey.(*rsa.PublicKey)
	}
}

/**
 * 加密
 */
func (this *Rsa) Encrypt(data []byte) ([]byte, error) {
	blockLength := this.rsaPublicKey.N.BitLen() / 8 - 11
	if len(data) <= blockLength {
		return rsa.EncryptPKCS1v15(rand.Reader, this.rsaPublicKey, []byte(data))
	}

	buffer := bytes.NewBufferString("")

	pages := len(data)/blockLength

	for index :=0; index<= pages; index++ {
		start := index * blockLength
		end   := (index+1) * blockLength
		if index == pages {
			if start == len(data) {
				continue
			}
			end = len(data)
		}

		chunk, err := rsa.EncryptPKCS1v15(rand.Reader, this.rsaPublicKey, data[start: end])
		if err != nil {
			return nil, err
		}
		buffer.Write(chunk)
	}
	return buffer.Bytes(), nil
}

/**
 * 解密
 */
func (this *Rsa) Decrypt(secretData []byte) ([]byte, error) {
	blockLength := this.rsaPublicKey.N.BitLen() / 8
	if len(secretData) <= blockLength {
		return rsa.DecryptPKCS1v15(rand.Reader, this.rsaPrivateKey, secretData)
	}

	buffer := bytes.NewBufferString("")

	pages := len(secretData)/blockLength
	for index :=0; index<= pages; index++ {
		start := index * blockLength
		end   := (index+1) * blockLength
		if index == pages {
			if start == len(secretData) {
				continue
			}
			end = len(secretData)
		}

		chunk, err := rsa.DecryptPKCS1v15(rand.Reader, this.rsaPrivateKey, secretData[start: end])
		if err != nil {
			return nil, err
		}
		buffer.Write(chunk)
	}
	return buffer.Bytes(), nil
}

/**
 * 签名
 */
func (this *Rsa) Sign(data []byte, algorithmSign crypto.Hash) ([]byte, error) {
	hash := algorithmSign.New()
	hash.Write(data)
	sign, err := rsa.SignPKCS1v15(rand.Reader, this.rsaPrivateKey, algorithmSign, hash.Sum(nil))
	if err != nil {
		return nil, err
	}
	return sign, err
}

/**
 * 验签
 */
func (this *Rsa) Verify(data []byte, sign []byte, algorithmSign crypto.Hash) bool {
	h := algorithmSign.New()
	h.Write(data)
	return rsa.VerifyPKCS1v15(this.rsaPublicKey, algorithmSign, h.Sum(nil), sign) == nil
}

/**
 * 生成pkcs1格式公钥私钥
 */
func (this *Rsa) CreateKeys(keyLength int) (privateKey, publicKey string) {
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return
	}

	privateKey = string(pem.EncodeToMemory(&pem.Block{
		Type:   "RSA PRIVATE KEY",
		Bytes:  x509.MarshalPKCS1PrivateKey(rsaPrivateKey),
	}))

	derPkix, err := x509.MarshalPKIXPublicKey(&rsaPrivateKey.PublicKey)
	if err != nil {
		return
	}

	publicKey = string(pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Bytes:   derPkix,
	}))
	return
}

/**
 * 生成pkcs8格式公钥私钥
 */
func (this *Rsa) CreatePkcs8Keys(keyLength int) (privateKey, publicKey string) {
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return
	}

	privateKey = string(pem.EncodeToMemory(&pem.Block{
		Type:   "PRIVATE KEY",
		Bytes:  this.MarshalPKCS8PrivateKey(rsaPrivateKey),
	}))

	derPkix, err := x509.MarshalPKIXPublicKey(&rsaPrivateKey.PublicKey)
	if err != nil {
		return
	}

	publicKey = string(pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Bytes:   derPkix,
	}))
	return
}

func (this *Rsa) MarshalPKCS8PrivateKey(key *rsa.PrivateKey) []byte {
	info := struct {
		Version             int
		PrivateKeyAlgorithm []asn1.ObjectIdentifier
		PrivateKey          []byte
	}{}
	info.Version = 0
	info.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 1)
	info.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	info.PrivateKey = x509.MarshalPKCS1PrivateKey(key)
	k, _ := asn1.Marshal(info)
	return k
}

// 还可使用openssl工具
// 私钥生成 				openssl genrsa -out rsa_private_key.pem 2048
// 公钥: （根据私钥生成） 	openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem

func main() {
	//content   := strings.Repeat("H", 244)+"e"
	content   := strings.Repeat("H", 245)+"e"
	//content   := strings.Repeat("H", 24270)+"e"

	publicKeyBytes, err := ioutil.ReadFile("rsa_public_key.pem")
	if err != nil {
		fmt.Printf("公钥文件加载失败：%v", err)
		os.Exit(-1)
	}
	privateKeyBytes, err := ioutil.ReadFile("rsa_private_key.pem")
	if err != nil {
		fmt.Printf("私钥文件加载失败：%v", err)
		os.Exit(-1)
	}
	publicKey := string(publicKeyBytes)
	privateKey := string(privateKeyBytes)
	//privateKey, publicKey := NewRsa("", "").CreateKeys(2048)
	//privateKey, publicKey := NewRsa("", "").CreatePkcs8Keys(2048)
	fmt.Printf("公钥：%v\n私钥：%v\n", publicKey, privateKey)

	rsaObj := NewRsa(publicKey, privateKey)
	secretData,err := rsaObj.Encrypt([]byte(content))
	if err != nil {
		fmt.Println(err)
	}
	plainData, err := rsaObj.Decrypt(secretData)
	if err != nil {
		fmt.Print(err)
	}

	data := []byte(strings.Repeat(content,200))
	//sign,_ := rsaObj.Sign(data, crypto.SHA1)
	//verify := rsaObj.Verify(data, sign, crypto.SHA1)

	sign,_ := rsaObj.Sign(data, crypto.SHA256)
	verify := rsaObj.Verify(data, sign, crypto.SHA256)

	fmt.Printf(" 加密：%v\n 解密：%v\n 签名：%v\n 验签结果：%v\n",
		hex.EncodeToString(secretData),
		string(plainData),
		hex.EncodeToString(sign),
		verify,
	)
}