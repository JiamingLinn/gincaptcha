package main

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/jiaminglinn/gincaptcha/code"
	"github.com/jiaminglinn/gincaptcha/utils"
)

func main() {
	cs, err := code.New(code.Options{
		FontPath: "./static/fonts/",
	})
	if err != nil {
		panic(err)
	}

	usedTokens := sync.Map{}

	server := gin.Default()
	server.GET("/code", cs.GetCodeHandler)
	server.POST("/code/verify", cs.VerifyCodeHandler)
	server.POST("/verify", func(ctx *gin.Context) {
		type Form struct {
			Token string
		}
		var form Form
		if err := ctx.ShouldBindJSON(&form); err != nil {
			utils.ErrorWith(ctx, http.StatusBadRequest, err.Error())
			return
		}

		t, _, err := cs.VerifyToken(form.Token)
		if err != nil {
			utils.ErrorWith(ctx, http.StatusUnauthorized, err.Error())
			return
		}

		if _, ok := usedTokens.Load(t.Rand); ok {
			utils.ErrorWith(ctx, http.StatusUnauthorized, "验证码已使用")
			return
		}
		usedTokens.Store(t.Rand, nil)

		utils.OkWith(ctx, "验证码正确")
	})
	server.Static("/static", "./static")
	server.Run(":8080")
}
