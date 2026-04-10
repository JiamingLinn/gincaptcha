package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func OkWith(ctx *gin.Context, data any) {
	ctx.JSON(http.StatusOK, gin.H{
		"Success": true,
		"Data":    data,
	})
}

func ErrorWith(ctx *gin.Context, code int, message string) {
	ctx.JSON(code, gin.H{
		"Success":  false,
		"Messsage": message,
	})
}

func NotFount(ctx *gin.Context, message string) {
	ErrorWith(ctx, http.StatusNotFound, message)
}

func BadRequest(ctx *gin.Context, message string) {
	ErrorWith(ctx, http.StatusBadRequest, message)
}

func Unauth(ctx *gin.Context, message string) {
	ErrorWith(ctx, http.StatusUnauthorized, message)
}

func Forbidden(ctx *gin.Context, message string) {
	ErrorWith(ctx, http.StatusForbidden, message)
}
