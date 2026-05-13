package main

import (
	"encoding/base64"
	"fmt"

	"github.com/jiaminglinn/gincaptcha/utils"
)

func main() {
	bkey := utils.MustGenerateRandomKey(32)
	key := base64.StdEncoding.EncodeToString(bkey)
	fmt.Println(key)
}
