package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

type JWT struct {
	key string
}

func NewJwt(key string) *JWT {
	return &JWT{key: key}
}

// CreateToken :生成token
func (jwt *JWT) CreateToken(payload map[string]string, timeout int64) (string, error) {
	header := Header{
		Typ: "JWT",
		Alg: HS256,
	}
	headerJson, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerBase64 := base64.URLEncoding.EncodeToString(headerJson)
	payloadJson, err := json.Marshal(Payload{
		Payload: payload,
		Timeout: timeout,
	})
	if err != nil {
		return "", err
	}
	payloadBase64 := base64.URLEncoding.EncodeToString(payloadJson)
	Signature, err := signatureToHS256(headerBase64+"."+payloadBase64, jwt.key)
	if err != nil {
		return "", err
	}
	return headerBase64 + "." + payloadBase64 + "." + Signature, nil
}

// VerificationSignature ：验证token签名
func (jwt *JWT) VerificationSignature(token Token) error {
	encodedString := token.tokenStr[:strings.LastIndex(token.tokenStr, ".")]
	signature, err := signatureToHS256(encodedString, jwt.key)
	if err != nil {
		return err
	}
	if signature != token.Signature {
		return errors.New("token authentication failed")
	}
	return nil
}

// TokenFormatString :将token转换为token结构体
func TokenFormatString(token string) (Token, error) {
	tokenStr := strings.Split(token, ".")
	if len(tokenStr) != 3 {
		return Token{}, errors.New("token illegal")
	}
	decodeHeader, err := base64.URLEncoding.DecodeString(tokenStr[0])
	if err != nil {
		return Token{}, err
	}
	var header Header
	err = json.Unmarshal(decodeHeader, &header)
	if err != nil {
		return Token{}, err
	}
	decodePayload, err := base64.URLEncoding.DecodeString(tokenStr[1])
	if err != nil {
		return Token{}, err
	}
	var payload Payload
	err = json.Unmarshal(decodePayload, &payload)
	if err != nil {
		return Token{}, err
	}

	return Token{
		Header:    header,
		Payload:   payload,
		Signature: tokenStr[2],
		tokenStr:  token,
	}, nil
}

// signatureToHS256 :使用HS256加密生成签名
func signatureToHS256(base64Str string, key string) (string, error) {
	hash := hmac.New(sha256.New, []byte(key))
	_, err := hash.Write([]byte(base64Str))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
