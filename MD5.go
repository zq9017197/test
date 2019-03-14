package main

import (
	"crypto/md5"
	"fmt"
	"encoding/hex"
)

//计算Md5的方式1
func getMD5_1(str []byte) string {
	// 1. 计算数据的md5
	result := md5.Sum(str)
	fmt.Println(result)
	fmt.Printf("%x\n", result)
	// 2. 数据格式化为16进制格式字符串
	res := fmt.Sprintf("%x", result)
	fmt.Println(res)
	// --- 这是另外一种格式化切片的方式
	res = hex.EncodeToString(result[:])
	fmt.Println("res: ", res)
	return res
}

//计算Md5的方式2
func getMD5_2(str []byte) string {
	// 1. 创建一个使用MD5校验的Hash对象`
	myHash := md5.New()
	// 2. 通过io操作将数据写入hash对象中
	//io.WriteString(myHash, string(str))
	myHash.Write(str)
	// 3. 计算结果
	result := myHash.Sum(nil)
	fmt.Println(result)
	// 4. 将结果转换为16进制格式字符串
	res := fmt.Sprintf("%x", result)
	fmt.Println(res)
	// --- 这是另外一种格式化切片的方式
	res = hex.EncodeToString(result)
	fmt.Println(res)

	return res
}

func main() {
	str := "事后诸葛亮"
	getMD5_1([]byte(str))
	fmt.Println("--------------------------")
	getMD5_2([]byte(str))
}
