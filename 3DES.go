package main

import (
	"crypto/des"
	"crypto/cipher"
	"fmt"
	"encoding/base64"
	"bytes"
)

// 3DES加密
func TripleDESEncrypt(src, key []byte) []byte {
	// 1. 创建并返回一个使用3DES算法的cipher.Block接口
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	// 2. 对最后一组明文进行填充
	src = PKCS5Padding3(src, block.BlockSize())
	// 3. 创建一个密码分组为链接模式, 底层使用3DES加密的BlockMode模型
	blockMode := cipher.NewCBCEncrypter(block, key[:8])
	// 4. 加密数据
	dst := src
	blockMode.CryptBlocks(dst, src)
	return dst
}

// 3DES解密
func TripleDESDecrypt(src, key []byte) []byte {
	// 1. 创建3DES算法的Block接口对象
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	// 2. 创建密码分组为链接模式, 底层使用3DES解密的BlockMode模型
	blockMode := cipher.NewCBCDecrypter(block, key[:8])
	// 3. 解密
	dst := src
	blockMode.CryptBlocks(dst, src)
	// 4. 去掉尾部填充的数据
	dst = PKCS5UnPadding3(dst)
	return dst
}

// 使用pks5的方式填充
func PKCS5Padding3(ciphertext []byte, blockSize int) []byte {
	// 1. 计算最后一个分组缺多少个字节
	padding := blockSize - (len(ciphertext) % blockSize)
	// 2. 创建一个大小为padding的切片, 每个字节的值为padding
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	// 3. 将padText添加到原始数据的后边, 将最后一个分组缺少的字节数补齐
	newText := append(ciphertext, padText...)
	return newText
}

// 删除pks5填充的尾部数据
func PKCS5UnPadding3(origData []byte) []byte {
	// 1. 计算数据的总长度
	length := len(origData)
	// 2. 根据填充的字节值得到填充的次数
	number := int(origData[length-1])
	// 3. 将尾部填充的number个字节去掉
	return origData[:(length - number)]
}

//测试
func main() {
	// 加密
	key := []byte("123456781234567812345678")
	result := TripleDESEncrypt([]byte("床前明月光, 疑是地上霜. 举头望明月, 低头思故乡."), key)
	fmt.Println("3DES加密之后的数据: ", result)
	fmt.Println("3DES加密之后的base64数据: ", base64.StdEncoding.EncodeToString(result))
	// 解密
	result = TripleDESDecrypt(result, key)
	fmt.Println("3DES解密之后的数据: ", string(result))
}

/*
3DES加密之后的数据:  [212 59 108 139 6 206 6 70 206 171 66 58 68 10 124 83 26 170 200 186 97 118 239 165 98 173 43 164 158 24 72 197 41 168 46 173 72 104 31 54 68 89 175 143 81 217 218 200 21 185 89 61 56 129 155 27 143 56 210 125 117 84 92 138 150 189 99 237 39 18 130 187]
3DES加密之后的base64数据:  1DtsiwbOBkbOq0I6RAp8UxqqyLphdu+lYq0rpJ4YSMUpqC6tSGgfNkRZr49R2drIFblZPTiBmxuPONJ9dVRcipa9Y+0nEoK7
3DES解密之后的数据:  床前明月光, 疑是地上霜. 举头望明月, 低头思故乡.
*/
