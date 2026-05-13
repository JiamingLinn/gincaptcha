package code

import (
	"errors"
)

var ErrInvalid = errors.New("ErrInvalid")
var ErrExpired = errors.New("ErrExpired")

type AckToken struct {
	Code      string
	Mark      string
	ExpiredAt int64
}

type Token struct {
	Rand      string
	Mark      string
	ExpiredAt int64
}

type VerifyCodeForm struct {
	Code string
}

type CodeCacheItem struct {
	Code  string
	Image []byte
}
