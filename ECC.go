package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"fmt"
)

// 1. 生成密钥对
func GenerateEccKey() {
	//1. 使用ecdsa生成密钥对
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	//2. 将私钥写入磁盘
	//- 使用x509进行序列化
	derText, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	//- 将得到的切片字符串放入pem.Block结构体中
	block := pem.Block{
		Type : "ecdsa private key",
		Bytes : derText,
	}
	//- 使用pem编码
	file, err := os.Create("eccPrivate.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(file, &block)
	file.Close()
	//3. 将公钥写入磁盘
	//- 从私钥中得到公钥
	publicKey := privateKey.PublicKey
	//- 使用x509进行序列化
	derText, err = x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	//- 将得到的切片字符串放入pem.Block结构体中
	block = pem.Block{
		Type : "ecdsa public key",
		Bytes : derText,
	}
	//- 使用pem编码
	file, err = os.Create("eccPublic.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(file, &block)
	file.Close()
}

// ecc签名 - 私钥
func EccSignature(plainText []byte, privName string)  (rText, sText []byte){
	//1. 打开私钥文件, 将内容读出来 ->[]byte
	file, err := os.Open(privName)
	if err != nil {
		panic(err)
	}
	info, err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	file.Close()
	//2. 使用pem进行数据解码 -> pem.Decode()
	block, _ := pem.Decode(buf)
	//3. 使用x509, 对私钥进行还原
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//4. 对原始数据进行哈希运算 -> 散列值
	hashText := sha1.Sum(plainText)
	//5. 进行数字签名
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashText[:])
	if err != nil {
		panic(err)
	}
	// 6. 对r, s内存中的数据进行格式化 -> []byte
	rText, err = r.MarshalText()
	if err != nil {
		panic(err)
	}
	sText, err = s.MarshalText()
	if err != nil {
		panic(err)
	}
	return
}

// ecc签名认证
func EccVerify(plainText, rText, sText []byte, pubFile string) bool {
	//1. 打开公钥文件, 将里边的内容读出 -> []byte
	file, err := os.Open(pubFile)
	if err != nil {
		panic(err)
	}
	info, err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	file.Close()
	//2. pem解码 -> pem.Decode()
	block, _ := pem.Decode(buf)
	//3. 使用x509对公钥还原
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//4. 将接口 -> 公钥
	publicKey := pubInterface.(*ecdsa.PublicKey)
	//5. 对原始数据进行哈希运算 -> 得到散列值
	hashText := sha1.Sum(plainText)
	// 将rText, sText -> int数据
	var r, s big.Int
	r.UnmarshalText(rText)
	s.UnmarshalText(sText)
	//6. 签名的认证 - > ecdsa  (问题,api的设计为什么在这个地方要传地址,直接传值比较不是更好吗?)
	bl := ecdsa.Verify(publicKey, hashText[:], &r, &s)
	return bl
}

func main() {
	GenerateEccKey()
	src := []byte("渡远荆门外，来从楚国游。山随平野尽，江入大荒流。月下飞天境，云生结海楼。仍怜故乡水，万里送行舟。")
	rText, sText := EccSignature(src, "eccPrivate.pem")
	bl := EccVerify(src, rText, sText, "eccPublic.pem")
	fmt.Println(string(rText))
	fmt.Println(string(sText))
	fmt.Println(bl)
}
