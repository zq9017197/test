package main

import (
	"crypto/aes"
	"crypto/cipher"
	"bytes"
	"fmt"
	"encoding/base64"
)

// AES加密
func AESEncrypt(src, key []byte) []byte{
	// 1. 创建一个使用AES加密的块对象
	block, err := aes.NewCipher(key)
	if err != nil{
		panic(err)
	}
	// 2. 最后一个分组进行数据填充
	src = PKCS5Padding(src, block.BlockSize())
	// 3. 创建一个分组为链接模式, 底层使用AES加密的块模型对象
	blockMode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	// 4. 加密
	dst := src
	blockMode.CryptBlocks(dst, src)
	return dst
}

// AES解密
func AESDecrypt(src, key []byte) []byte{
	// 1. 创建一个使用AES解密的块对象
	block, err := aes.NewCipher(key)
	if err != nil{
		panic(err)
	}
	// 2. 创建分组为链接模式, 底层使用AES的解密模型对象
	blockMode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	// 3. 解密
	dst := src
	blockMode.CryptBlocks(dst, src)
	// 4. 去掉尾部填充的字
	dst = PKCS5UnPadding(dst)
	return dst
}

// 使用pks5的方式填充
func PKCS5Padding(ciphertext []byte, blockSize int) []byte{
	// 1. 计算最后一个分组缺多少个字节
	padding := blockSize - (len(ciphertext)%blockSize)
	// 2. 创建一个大小为padding的切片, 每个字节的值为padding
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	// 3. 将padText添加到原始数据的后边, 将最后一个分组缺少的字节数补齐
	newText := append(ciphertext, padText...)
	return newText
}

// 删除pks5填充的尾部数据
func PKCS5UnPadding(origData []byte) []byte{
	// 1. 计算数据的总长度
	length := len(origData)
	// 2. 根据填充的字节值得到填充的次数
	number := int(origData[length-1])
	// 3. 将尾部填充的number个字节去掉
	return origData[:(length-number)]
}

//测试
func main() {
	// 加密
	key := []byte("1234567812345678")
	result := AESEncrypt([]byte("床前明月光, 疑是地上霜. 举头望明月, 低头思故乡."), key)
	fmt.Println("AES加密之后的数据: ", result)
	fmt.Println("AES加密之后的base64数据: ", base64.StdEncoding.EncodeToString(result))
	// 解密
	result = AESDecrypt(result, key)
	fmt.Println("AES解密之后的数据: ", string(result))
}

/*
AES加密之后的数据:  [250 223 177 140 253 90 31 5 94 80 76 69 42 241 251 120 128 139 11 97 7 219 14 32 137 219 12 86 163 19 254 166 157 1 202 230 15 92 14 189 156 193 117 121 246 63 28 75 167 130 199 227 114 123 157 40 20 223 124 65 242 85 122 87 41 9 226 173 109 227 201 27 188 68 17 241 131 63 206 239]
AES加密之后的base64数据:  +t+xjP1aHwVeUExFKvH7eICLC2EH2w4gidsMVqMT/qadAcrmD1wOvZzBdXn2PxxLp4LH43J7nSgU33xB8lV6VykJ4q1t48kbvEQR8YM/zu8=
AES解密之后的数据:  床前明月光, 疑是地上霜. 举头望明月, 低头思故乡.
*/
