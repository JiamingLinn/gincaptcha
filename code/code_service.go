package code

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jiaminglinn/gincaptcha/utils"
	captcha "github.com/lifei6671/gocaptcha"
	"github.com/samber/lo"
)

type Options struct {
	CaptchaCookieName string        // 验证码cookie名称
	EncryptKeyBase64  string        // 加密key的base64编码
	Expire            time.Duration // 过期时间
	ExpireString      string        // 过期时间字符串
	FontPath          string        // 字体路径
	ImageX            int           // 图片宽度
	ImageY            int           // 图片高度
	RamdonTextLen     int           // 验证码长度
	CacheCapacity     int           // 缓存数量
	TokenMark         string        // 验证码Token标记
}

type CodeService struct {
	opts  Options
	asm   utils.AESGCM
	cache []CodeCacheItem
	mu    sync.RWMutex
}

func New(opts Options) (cs *CodeService, err error) {
	cs = &CodeService{}

	opts.CaptchaCookieName = lo.Ternary(opts.CaptchaCookieName == "",
		"captcha_code", opts.CaptchaCookieName)

	var key []byte
	if opts.EncryptKeyBase64 == "" {
		key = utils.MustGenerateRandomKey(32)
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

	opts.ImageX = lo.Ternary(opts.ImageX == 0, 150, opts.ImageX)
	opts.ImageY = lo.Ternary(opts.ImageY == 0, 50, opts.ImageY)
	opts.RamdonTextLen = lo.Ternary(opts.RamdonTextLen == 0, 4, opts.RamdonTextLen)
	opts.CacheCapacity = lo.Ternary(opts.CacheCapacity == 0, 100, opts.CacheCapacity)
	opts.TokenMark = lo.Ternary(opts.TokenMark == "",
		"gocaptchatoken.TSdGsXFuIYAo9DuzbB2t7LtsufKWsH", opts.TokenMark)

	cs.asm = *utils.NewAESGCM(key)
	cs.opts = opts
	cs.cache, err = newCodeCaches(&opts)
	if err != nil {
		err = fmt.Errorf("newCodeCaches: %w", err)
		return
	}
	go func() {
		for {
			time.Sleep(10 * time.Second)
			caches, err := newCodeCaches(&opts)
			if err != nil {
				return
			}
			cs.mu.Lock()
			cs.cache = caches
			cs.mu.Unlock()
		}
	}()
	return
}

func newCodeCaches(opts *Options) ([]CodeCacheItem, error) {
	res := make([]CodeCacheItem, opts.CacheCapacity)
	for i := range res {
		code := captcha.RandText(opts.RamdonTextLen)

		image := captcha.New(opts.ImageX, opts.ImageY, captcha.RandLightColor())
		err := image.
			DrawBorder(captcha.RandDeepColor()).
			DrawNoise(captcha.NoiseDensityHigh, captcha.NewTextNoiseDrawer(captcha.DefaultDPI)).
			DrawNoise(captcha.NoiseDensityLower, captcha.NewPointNoiseDrawer()).
			DrawLine(captcha.NewBezier3DLine(), captcha.RandDeepColor()).
			DrawText(captcha.NewTwistTextDrawer(captcha.DefaultDPI, captcha.DefaultAmplitude, captcha.DefaultFrequency), code).
			DrawLine(captcha.NewBeeline(), captcha.RandDeepColor()).
			DrawBlur(captcha.NewGaussianBlur(), captcha.DefaultBlurKernelSize, captcha.DefaultBlurSigma).
			Error
		if err != nil {
			return nil, err
		}
		buf := bytes.NewBuffer(nil)
		if err = image.Encode(buf, captcha.ImageFormatJpeg); err != nil {
			return nil, err
		}

		res[i] = CodeCacheItem{
			Code:  code,
			Image: buf.Bytes(),
		}
	}
	return res, nil
}

func (cs *CodeService) GetCodeHandler(ctx *gin.Context) {
	cs.mu.RLock()
	item := cs.cache[rand.Intn(len(cs.cache))]
	cs.mu.RUnlock()

	var err error

	var encryptedCode string
	{
		ct := AckToken{
			Code:      item.Code,
			Mark:      cs.opts.TokenMark,
			ExpiredAt: time.Now().Add(cs.opts.Expire).UnixNano(),
		}
		if encryptedCode, err = cs.encrypt(&ct); err != nil {
			ctx.Error(err)
			return
		}
	}
	ctx.SetCookie(cs.opts.CaptchaCookieName, encryptedCode, 300, "/", "", false, true)

	if _, err := ctx.Writer.Write(item.Image); err != nil {
		ctx.Error(err)
		return
	}
}

// VerifyCode 验证验证码, 流程如下
func (cs *CodeService) VerifyCodeHandler(ctx *gin.Context) {
	defer ctx.SetCookie(cs.opts.CaptchaCookieName, "", -1, "/", "", false, true)

	cepherBase64, err := ctx.Cookie(cs.opts.CaptchaCookieName)
	if err != nil {
		utils.ErrorWith(ctx, http.StatusBadRequest, "请求参数错误1")
		return
	}
	form := VerifyCodeForm{}
	if err := ctx.ShouldBindJSON(&form); err != nil {
		utils.ErrorWith(ctx, http.StatusBadRequest, "请求参数错误2")
		return
	}

	atk := AckToken{}
	if err := cs.decrypt(cepherBase64, &atk); err != nil {
		utils.ErrorWith(ctx, http.StatusBadRequest, "请求参数错误3")
		return
	}
	if time.Now().UnixNano() > atk.ExpiredAt {
		utils.ErrorWith(ctx, http.StatusBadRequest, "验证码过期")
		return
	}
	if atk.Mark != cs.opts.TokenMark {
		utils.ErrorWith(ctx, http.StatusUnauthorized, "验证码错误3")
		return
	}
	if form.Code != atk.Code {
		utils.ErrorWith(ctx, http.StatusUnauthorized, "验证码错误4")
		return
	}

	tk := Token{
		Rand:      base64.StdEncoding.EncodeToString(utils.MustGenerateRandomKey(64)),
		ExpiredAt: time.Now().Add(cs.opts.Expire).UnixNano(),
		Mark:      cs.opts.TokenMark,
	}
	t, err := cs.encrypt(&tk)
	if err != nil {
		utils.ErrorWith(ctx, http.StatusInternalServerError, "服务器错误")
		return
	}
	utils.OkWith(ctx, t)
}

func (cs *CodeService) VerifyToken(token string) (tobj Token, ok bool, err error) {
	if err = cs.decrypt(token, &tobj); err != nil {
		return
	}
	if tobj.Mark != cs.opts.TokenMark {
		err = ErrInvalid
		return
	}
	if time.Now().UnixNano() > tobj.ExpiredAt {
		err = ErrExpired
		return
	}
	return tobj, true, nil
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
