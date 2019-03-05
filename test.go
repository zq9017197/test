package main

import (
	"encoding/base64"
	"fmt"
)

func main() {
	str := "imCKWl9E7p9KAcYA9TyUYYmo/QdvQxTRL8MaKhY/zaRu/EOlNZ3YmL4xXBq95FANwwvtVg/7YuiyD5l1tPELHuDMl6Uzab34"
	result,_ := base64.StdEncoding.DecodeString(str)
	fmt.Println(result)
}
