package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

// AESGCM 加密工具结构体（无状态，高并发安全）
type AESGCM struct {
	key []byte
}

// NewAESGCM 创建加密工具实例（全局单例即可，无并发风险）
// key：密钥（16/24/32 字节 = AES-128/192/256）
func NewAESGCM(key []byte) *AESGCM {
	return &AESGCM{
		key: key,
	}
}

// Encrypt 加密
// plain：原始明文
// 返回：base64 编码的密文，错误
func (a *AESGCM) Encrypt(plain []byte) ([]byte, error) {
	// 1. 创建 AES 密码块（每次调用独立创建，无并发冲突）
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	// 2. 创建 GCM 模式实例（线程安全，每次新建）
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 3. 生成随机 IV（GCM 标准：12 字节，安全且高效）
	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// 4. 加密（ Seal 会自动追加认证标签，防篡改）
	cipherText := gcm.Seal(iv, iv, plain, nil)

	return cipherText, nil
}

func (a *AESGCM) EncryptToBase64(plainText string) (string, error) {
	en, err := a.Encrypt([]byte(plainText))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(en), nil
}

// Decrypt 解密
// cipherText：base64 编码的密文
// 返回：原始明文，错误
func (a *AESGCM) Decrypt(cipherData []byte) ([]byte, error) {
	// 2. 创建 AES 密码块
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	// 3. 创建 GCM 模式实例
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 4. 校验密文长度
	nonceSize := gcm.NonceSize()
	if len(cipherData) < nonceSize {
		return nil, err
	}

	// 5. 拆分 IV 和密文
	iv, cipherByte := cipherData[:nonceSize], cipherData[nonceSize:]

	// 6. 解密 + 自动校验（GCM 认证失败会直接返回错误，防篡改）
	plainText, err := gcm.Open(nil, iv, cipherByte, nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func (a *AESGCM) DecryptBase64(cipherText string) (string, error) {
	// 1. base64 解码
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	d, err := a.Decrypt(data)
	if err != nil {
		return "", nil
	}
	return string(d), nil
}

// GenerateRandomKey 生成安全的随机密钥（推荐 32 字节 = AES-256）
func GenerateRandomKey(size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}
