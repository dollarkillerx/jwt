package jwt

type AlgType string

const (
	HS256 AlgType = "HS256"
)

type Header struct {
	Typ string
	Alg AlgType
}

type Token struct {
	Header    Header                 // 头
	Payload   map[string]interface{} // 主要载荷
	Signature string                 // 签名
	tokenStr  string                 //  生成出来的token
}
