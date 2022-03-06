package jwt

import (
	"fmt"
	"testing"
	"time"
)

func TestJWT(t *testing.T) {
	type tok struct {
		Name string `json:"name" validate:"required"`
		Age  int    `json:"age"`
	}

	jwt := NewJwt("f0950ead-a6c4-498b-ab3c-35ca91a730ad")
	token, err := jwt.CreateToken(tok{
		//Name: "asd",
		Age: 16,
	}, int64(time.Hour))
	if err != nil {
		panic(err)
	}

	tokenr, err := TokenFormatString(token)
	if err != nil {
		panic(err)
	}
	err = jwt.VerificationSignature(tokenr)
	if err != nil {
		panic(err)
	}
	var tr tok
	err = tokenr.Payload.Unmarshal(&tr)
	if err != nil {
		panic(err)
	}

	fmt.Println(tr)
}
