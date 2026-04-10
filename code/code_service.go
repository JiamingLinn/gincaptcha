package code

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jiaminglinn/gin-captcha/utils"
	captcha "github.com/lifei6671/gocaptcha"
)

type Options struct {
	CaptchaCookieName string
	EncryptKeyBase64  string
	Expire            time.Duration
	ExpireString      string
	FontPath          string
	ImageX            int
	ImageY            int
	RamdonTextLen     int
}

type CodeService struct {
	opts Options
	asm  utils.AESGCM
}

func New(opts Options) (cs *CodeService, err error) {
	cs = &CodeService{}

	var key []byte
	if opts.CaptchaCookieName == "" {
		opts.CaptchaCookieName = "captcha_code"
	}
	if opts.EncryptKeyBase64 == "" {
		key, _ = utils.GenerateRandomKey(32)
	} else {
		if key, err = base64.StdEncoding.DecodeString(opts.EncryptKeyBase64); err != nil {
			return
		}
	}
	if opts.Expire == 0 && opts.ExpireString == "" {
		opts.Expire = 5 * time.Minute
	} else if opts.ExpireString != "" {
		opts.Expire, err = time.ParseDuration(opts.ExpireString)
		return
	}
	if opts.FontPath != "" {
		if err = captcha.SetFontPath(opts.FontPath); err != nil {
			return
		}
	}
	if opts.ImageX == 0 {
		opts.ImageX = 150
	}
	if opts.ImageY == 0 {
		opts.ImageY = 50
	}
	if opts.RamdonTextLen == 0 {
		opts.RamdonTextLen = 4
	}

	cs.asm = *utils.NewAESGCM(key)
	cs.opts = opts
	return
}

func (cs *CodeService) GetCodeHandler(ctx *gin.Context) {
	ci, code, err := cs.render()
	if err != nil {
		ctx.Error(err)
		return
	}

	var encryptedCode string
	{
		ct := AckToken{
			Code:      code,
			ExpiredAt: time.Now().Add(cs.opts.Expire).UnixNano(),
		}
		if encryptedCode, err = cs.encrypt(&ct); err != nil {
			ctx.Error(err)
			return
		}
	}
	ctx.SetCookie(cs.opts.CaptchaCookieName, encryptedCode, 300, "/", "", false, true)

	if err := ci.Encode(ctx.Writer, captcha.ImageFormatJpeg); err != nil {
		ctx.Error(err)
		return
	}
}

// VerifyCode 验证验证码, 流程如下
func (cs *CodeService) VerifyCodeHandler(ctx *gin.Context) {
	defer ctx.SetCookie(cs.opts.CaptchaCookieName, "", -1, "/", "", false, true)

	cepherBase64, err := ctx.Cookie(cs.opts.CaptchaCookieName)
	if err != nil {
		ctx.Error(err)
		return
	}
	form := VerifyCodeForm{}
	if err := ctx.ShouldBindJSON(&form); err != nil {
		ctx.Error(err)
		return
	}

	ct := AckToken{}
	if err := cs.decrypt(cepherBase64, &ct); err != nil {
		ctx.Error(err)
		return
	}
	if time.Now().UnixNano() > ct.ExpiredAt {
		utils.ErrorWith(ctx, http.StatusUnauthorized, "验证码过期")
		return
	}
	if form.Code != ct.Code {
		utils.ErrorWith(ctx, http.StatusUnauthorized, "验证码错误4")
		return
	}

	act := Token{
		ExpiredAt: time.Now().UnixNano(),
	}
	act.Salt, _ = utils.GenerateRandomKey(32)
	t, err := cs.encrypt(&act)
	if err != nil {
		ctx.Error(err)
		return
	}
	utils.OkWith(ctx, t)
}

func (cs *CodeService) VerifyToken(token string) (tobj Token, ok bool, err error) {
	if err = json.Unmarshal([]byte(token), &tobj); err != nil {
		err = ErrInvalid
		return
	}
	if time.Now().UnixNano() > tobj.ExpiredAt {
		err = ErrExpired
		return
	}
	return
}

func (cs *CodeService) encrypt(data any) (string, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	ib, err := cs.asm.Encrypt(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ib), nil
}

func (cs *CodeService) decrypt(cipherText string, v any) error {
	b, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return err
	}
	ib, err := cs.asm.Decrypt(b)
	if err != nil {
		return err
	}
	return json.Unmarshal(ib, v)
}

func (cs *CodeService) render() (*captcha.CaptchaImage, string, error) {
	randText := captcha.RandText(cs.opts.RamdonTextLen)
	captchaImage := captcha.New(cs.opts.ImageX, cs.opts.ImageY, captcha.RandLightColor())
	err := captchaImage.
		DrawBorder(captcha.RandDeepColor()).
		DrawNoise(captcha.NoiseDensityHigh, captcha.NewTextNoiseDrawer(captcha.DefaultDPI)).
		DrawNoise(captcha.NoiseDensityLower, captcha.NewPointNoiseDrawer()).
		DrawLine(captcha.NewBezier3DLine(), captcha.RandDeepColor()).
		DrawText(captcha.NewTwistTextDrawer(captcha.DefaultDPI, captcha.DefaultAmplitude, captcha.DefaultFrequency), randText).
		DrawLine(captcha.NewBeeline(), captcha.RandDeepColor()).
		DrawBlur(captcha.NewGaussianBlur(), captcha.DefaultBlurKernelSize, captcha.DefaultBlurSigma).
		Error

	return captchaImage, randText, err
}
