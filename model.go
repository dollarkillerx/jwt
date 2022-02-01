package jwt

type AlgType string

const (
	HS256 AlgType = "HS256"
)

type Header struct {
	Typ string  `json:"typ"`
	Alg AlgType `json:"alg"`
}

type Token struct {
	Header    Header  `json:"header"`    // 头
	Payload   Payload `json:"payload"`   // 主要载荷
	Signature string  `json:"signature"` // 签名
	tokenStr  string  //  生成出来的token
}

type Payload struct {
	Payload map[string]string `json:"payload"`
	Timeout int64             `json:"timeout"`
}
