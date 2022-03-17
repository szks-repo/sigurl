package sigurl

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	ErrMissingURLParameter      = errors.New("some parameters are missing")
	ErrIllegalURLParameter      = errors.New("illegal parameter found")
	ErrURLExpired               = errors.New("url was expired")
	ErrBeforeStartDate          = errors.New("before the start date")
	ErrPrivateKeyNotSet         = errors.New("private key not set")
	ErrParameterKeyAlreadyExist = errors.New("parameter key already exist")
)

var nowFunc = time.Now

const (
	ISO8601 = "20060102T150405Z"

	paramKeyAlgo         = "Algorithm"
	paramKeyDate         = "Date"
	paramKeyExpires      = "Expires"
	paramKeySignature    = "Signature"
	paramKeyCustomPolicy = "CustomPolicy"

	SignAlgoRSASHA256 = "RSA-SHA256"

	EncodingHex    encoding = "Hex"
	EncodingBase64 encoding = "Base64"
)

type encoding string

type SigUrl struct {
	privateKey      []byte
	publicKey       []byte
	verifyFuncStack []func() bool
	config          *Config
}

type Config struct {
	Prefix       string
	Encoding     encoding
	Location     *time.Location
	CustomPolicy *CustomPolicy
}

func defaultConfig() *Config {
	return &Config{
		Prefix:       "X-Sig",
		Encoding:     EncodingHex,
		Location:     time.Local,
		CustomPolicy: NewCustomPolicy(),
	}
}

func New(privateKey, publicKey []byte, cfg *Config) *SigUrl {
	if cfg == nil {
		cfg = defaultConfig()
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "X-Sig"
	}
	if cfg.Encoding == "" {
		cfg.Encoding = EncodingHex
	}
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	if cfg.CustomPolicy == nil {
		cfg.CustomPolicy = NewCustomPolicy()
	}

	return &SigUrl{
		privateKey: privateKey,
		publicKey:  publicKey,
		config:     cfg,
	}
}

//RegisterAdditionalVerifyFunc unimplemented
func (s *SigUrl) RegisterAdditionalVerifyFunc(fn func() bool) {
	s.verifyFuncStack = append(s.verifyFuncStack, fn)
}

type SignedInfo struct {
	//署名付きURLが使用可能になる日付と時刻
	Date time.Time
	//署名付きURLの有効期間
	//Dateに格納された値からの秒数で表されます。
	Expires int
	//署名値
	Signature string
	//署名対象メッセージ（正規化する）
	Message string
	//ポリシー
	CustomPolicy string
}

func (s *SigUrl) Sign(baseUrl string, date time.Time, expires uint32) (string, error) {
	if s.privateKey == nil {
		return "", ErrPrivateKeyNotSet
	}
	netUrl, err := url.Parse(baseUrl)
	if err != nil {
		return "", err
	}
	if !s.checkUrlCanSign(netUrl) {
		return "", ErrParameterKeyAlreadyExist
	}

	query := netUrl.Query()
	query.Set(s.paramKey(paramKeyAlgo), SignAlgoRSASHA256)
	query.Set(s.paramKey(paramKeyDate), date.Format(ISO8601))
	query.Set(s.paramKey(paramKeyExpires), fmt.Sprintf("%d", expires))
	message := s.buildURL(netUrl, query)

	signature, err := s.sign(message, s.privateKey)
	if err != nil {
		return "", err
	}

	query.Set(s.paramKey(paramKeySignature), signature)
	return s.buildURL(netUrl, query), nil
}

func (s *SigUrl) checkUrlCanSign(netUrl *url.URL) bool {
	if netUrl == nil {
		return false
	}

	query := netUrl.Query()
	for _, v := range []string{
		paramKeyAlgo,
		paramKeyDate,
		paramKeyExpires,
		paramKeySignature,
	} {
		if query.Has(s.paramKey(v)) {
			return false
		}
	}

	return true
}

func (s *SigUrl) sign(message string, privateKeyBytes []byte) (ret string, err error) {
	private, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return "", err
	}

	h := sha256.Sum256([]byte(message))
	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}

	switch s.config.Encoding {
	case EncodingBase64:
		ret = base64.StdEncoding.EncodeToString(signatureBytes)
		break
	case EncodingHex:
		ret = fmt.Sprintf("%x", signatureBytes)
	}

	return
}

func (s *SigUrl) Verify(rawUrl string) error {
	parsed, err := url.Parse(rawUrl)
	if err != nil {
		return err
	}

	signedInfo, err := s.SignedInfoFromUrl(parsed)
	if err != nil {
		return err
	}

	if nowFunc().Before(signedInfo.Date) {
		//使用開始時刻になっていない
		return ErrBeforeStartDate
	}

	expiresAt := signedInfo.Date.Add(time.Second * time.Duration(signedInfo.Expires))
	if expiresAt.Before(nowFunc()) {
		//有効期限切
		return ErrURLExpired
	}

	var pubKey *rsa.PublicKey
	maybePubKey, err := x509.ParsePKIXPublicKey(s.publicKey)
	if err == nil {
		var ok bool
		if pubKey, ok = maybePubKey.(*rsa.PublicKey); !ok {
			return fmt.Errorf("unsupported public key: %T", maybePubKey)
		}
	} else if err != nil && strings.Contains(err.Error(), "instead") {
		if pubKey, err = x509.ParsePKCS1PublicKey(s.publicKey); err != nil {
			return err
		}
	}

	signatureBytes, err := signedInfo.SignatureBytes(s.config.Encoding)
	if err != nil {
		return err
	}

	h := sha256.Sum256([]byte(signedInfo.Message))
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h[:], signatureBytes)
}

func (s *SigUrl) SignedInfoFromUrl(parsedUrl *url.URL) (*SignedInfo, error) {
	query := parsedUrl.Query()
	algo := query.Get(s.paramKey(paramKeyAlgo))
	if algo == "" {
		return nil, ErrMissingURLParameter
	} else if algo != SignAlgoRSASHA256 {
		return nil, fmt.Errorf("%v: algo %q", ErrIllegalURLParameter, algo)
	}

	signature := query.Get(s.paramKey(paramKeySignature))
	if signature == "" {
		return nil, ErrMissingURLParameter
	}

	expiresStr := query.Get(s.paramKey(paramKeyExpires))
	if expiresStr == "" {
		return nil, ErrMissingURLParameter
	}
	expires, _ := strconv.Atoi(expiresStr)
	if expires <= 0 {
		return nil, fmt.Errorf("%v: expires %d", ErrIllegalURLParameter, expires)
	}

	dateStr := query.Get(s.paramKey(paramKeyDate))
	if dateStr == "" {
		return nil, ErrMissingURLParameter
	}

	date, err := time.ParseInLocation(ISO8601, dateStr, s.config.Location)
	if err != nil {
		return nil, fmt.Errorf("%v: date %w", ErrIllegalURLParameter, err)
	}

	//Normalize URL
	query2 := s.cloneQuery(query)
	query2.Del(s.paramKey(paramKeySignature))
	normalizedUrl := s.buildURL(parsedUrl, query2)

	return &SignedInfo{
		Expires:   expires,
		Date:      date,
		Signature: signature,
		Message:   normalizedUrl,
	}, nil
}

func (s *SigUrl) cloneQuery(q1 url.Values) url.Values {
	q2 := url.Values{}
	for k, v := range q1 {
		if len(v) > 0 {
			q2.Set(k, v[0])
		}
	}
	return q2
}

func (s *SigUrl) paramKey(k string) string {
	return s.config.Prefix + "-" + k
}

func (s *SigUrl) buildURL(netURL *url.URL, params url.Values) (ret string) {
	if netURL == nil {
		return
	}
	if netURL.Scheme != "" {
		ret += netURL.Scheme + "://"
	}
	if netURL.Hostname() != "" {
		ret += netURL.Hostname()
	}
	ret += netURL.Path
	if len(params) > 0 {
		ret += "?" + params.Encode()
	}
	if netURL.Fragment != "" {
		ret += "#" + netURL.Fragment
	}

	return
}

func (si *SignedInfo) SignatureBytes(e encoding) ([]byte, error) {
	switch e {
	case EncodingHex:
		return hex.DecodeString(si.Signature)
	case EncodingBase64:
		return base64.StdEncoding.DecodeString(si.Signature)
	}
	return nil, errors.New("unreachable error")
}
