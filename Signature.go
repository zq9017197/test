package main

import (
	"errors"
	"os"
	"fmt"
	"encoding/pem"
	"crypto/x509"
	"crypto/sha256"
	"crypto/rsa"
	"crypto/rand"
	"crypto"
	"encoding/base64"
)

//生成数字签名 - 私钥
func SignatureRSA(str []byte) ([]byte, error) {
	// 1. 从秘钥文件中读生成的秘钥内容
	fp, err := os.Open("private.pem")
	if err != nil {
		return nil, errors.New("打开私钥文件 - private.pem 失败!!!")
	}
	// 2. 读文件内容
	fileInfo, _ := fp.Stat()
	all := make([]byte, fileInfo.Size())
	_, err = fp.Read(all)
	if err != nil {
		return nil, errors.New("读文件内容失败!!!")
	}
	//fmt.Println("文件内容: ", string(all))
	// 3. 关闭文件
	defer fp.Close()
	// 4. 将数据解析成pem格式的数据块
	block, _ := pem.Decode(all)
	// 5. 解析pem数据块, 得到私钥
	priv_Key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("解析私钥失败!!!")
	}

	// 6. 将数据通过哈希函数生成信息摘要
	myHash := sha256.New()
	myHash.Write(str)
	result := myHash.Sum(nil)
	// 7. 生成签名
	mySignature, err := rsa.SignPKCS1v15(rand.Reader, priv_Key, crypto.SHA256, result)
	if err != nil {
		return nil, errors.New("生成签名失败!!!")
	}

	return mySignature, nil
}

//验证数字签名 - 公钥
func VerifyRSA(str []byte, sign []byte) (error) {
	// 1. 从秘钥文件中读生成的秘钥内容
	fp, err := os.Open("public.pem")
	if err != nil {
		return errors.New("打开公钥文件 - public.pem 失败!!!")
	}
	// 2. 读文件内容
	fileInfo, _ := fp.Stat()
	all := make([]byte, fileInfo.Size())
	_, err = fp.Read(all)
	if err != nil {
		return errors.New("读文件内容失败!!!")
	}
	//fmt.Println("文件大小: ", num)
	// 3. 关闭文件
	defer fp.Close()
	// 4. 将公钥数据解析为pem格式的数据块
	block, _ := pem.Decode(all)
	// 5. 将公钥从pem数据块中提取出来
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errors.New("解析公钥失败!!!")
	}
	// 6. 公钥接口转换为公钥对象
	pubKey := pubInterface.(*rsa.PublicKey)
	// 7. 将数据通过哈希函数生成信息摘要
	myHash := sha256.New()
	myHash.Write(str)
	result := myHash.Sum(nil)

	// 7. 数据认证
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, result, sign)
	if err != nil {
		return err
	}

	fmt.Println("数字签名验证成功, 恭喜o(*￣︶￣*)o恭喜")
	return nil
}

func main() {
	str := []byte("渡远荆门外，来从楚国游。山随平野尽，江入大荒流。月下飞天境，云生结海楼。仍怜故乡水，万里送行舟。")
	sign, _ := SignatureRSA(str)
	fmt.Println("sign bytes=", sign)
	fmt.Println("sign base64=", base64.StdEncoding.EncodeToString(sign))
	VerifyRSA(str, sign)
}
