# gin 验证码中间件
example
```golang
import "github.com/jiaminglinn/gincaptcha/code"


codeService := code.New(code.Options{})

router.GET("/captcha", codeService.GetCodeHandler)
router.GET("/captcha/verify", codeService.VerifyCodeHandler)

router.GET("/.../login", func(c *gin.Context) {
    // 提取出 VerifyCodeHandler 发送的Code
    ... 
    _, err := codeService.VerifyToken(form.Code)
    if err == code.ErrInvalid {
        ...
    }
    if err == code.ErrExpired {
        ...
    }
})
```