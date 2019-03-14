package main

import (
	"os"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
	"fmt"
)

//RSA公钥加密
func RSAEncrypt(src []byte, filename string) []byte {
	// 1. 根据文件名将文件内容从文件中读出
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	// 2. 读文件
	info, _ := file.Stat()
	allText := make([]byte, info.Size())
	file.Read(allText)
	// 3. 关闭文件
	file.Close()

	// 4. 从数据中查找到下一个PEM格式的块
	block, _ := pem.Decode(allText)
	if block == nil {
		return nil
	}
	// 5. 解析一个DER编码的公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil
	}
	pubKey := pubInterface.(*rsa.PublicKey)

	// 6. 公钥加密
	result, _ := rsa.EncryptPKCS1v15(rand.Reader, pubKey, src)
	return result
}

//RSA私钥解密
func RSADecrypt(src []byte, filename string) []byte {
	// 1. 根据文件名将文件内容从文件中读出
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	// 2. 读文件
	info, _ := file.Stat()
	allText := make([]byte, info.Size())
	file.Read(allText)
	// 3. 关闭文件
	file.Close()
	// 4. 从数据中查找到下一个PEM格式的块
	block, _ := pem.Decode(allText)
	// 5. 解析一个pem格式的私钥
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	// 6. 私钥解密
	result, _ := rsa.DecryptPKCS1v15(rand.Reader, privateKey, src)

	return result
}

func main() {
	//RsaGenKey(4096)
	src := []byte("我是小庄, 如果我死了, 肯定不是自杀...")
	cipherText := RSAEncrypt(src, "public.pem")
	plainText := RSADecrypt(cipherText, "private.pem")
	fmt.Println(string(plainText))
}
