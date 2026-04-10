package code

import "errors"

var ErrInvalid = errors.New("ErrInvalid")
var ErrExpired = errors.New("ErrExpired")

type AckToken struct {
	Code      string
	ExpiredAt int64
}

type Token struct {
	Salt      []byte
	ExpiredAt int64
}

type VerifyCodeForm struct {
	Code string
}
