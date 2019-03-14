package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"encoding/base64"
)

// 生成消息认证码
func GenerateHMAC(src, key []byte) []byte {
	// 1. 创建一个底层采用sha256算法的 hash.Hash 接口
	myHmac := hmac.New(sha256.New, key)
	// 2. 添加测试数据
	myHmac.Write(src)
	// 3. 计算结果
	result := myHmac.Sum(nil)

	return result
}

//验证消息认证码
func VerifyHMAC(res, src, key []byte) bool {
	// 1. 创建一个底层采用sha256算法的 hash.Hash 接口
	myHmac := hmac.New(sha256.New, key)
	// 2. 添加测试数据
	myHmac.Write(src)
	// 3. 计算结果
	result := myHmac.Sum(nil)
	// 4. 比较结果
	return hmac.Equal(res, result)
}

func main() {
	key := []byte("我是消息认证码秘钥")
	src := []byte("我是消息认证码测试数据")
	result := GenerateHMAC(src, key)
	fmt.Println("result bytes=", result)
	fmt.Println("result base64=", base64.StdEncoding.EncodeToString(result))
	final := VerifyHMAC(result, src, key)
	if final {
		fmt.Println("消息认证码认证成功!!!")
	} else {
		fmt.Println("消息认证码认证失败 ......")
	}
}
