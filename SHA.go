package main

import (
	"crypto/sha1"
	"encoding/hex"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

func Sha(typ int, str []byte) string {
	myHash := sha1.New()
	if typ == 256 {
		myHash = sha256.New()
	}
	if typ == 512 {
		myHash = sha512.New()
	}

	myHash.Write(str)
	tmp1 := myHash.Sum(nil)
	result := hex.EncodeToString(tmp1)
	return result
}

func main() {
	b := []byte("事后诸葛亮")
	fmt.Println("sha1: ", Sha(0, b))
	fmt.Println("sha256: ", Sha(256, b))
	fmt.Println("sha512: ", Sha(512, b))
}
