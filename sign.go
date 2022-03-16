package sigurl

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

/*
https://storage.googleapis.com/example-bucket/cat.jpeg
?X-Goog-Algorithm=GOOG4-RSA-SHA256
&X-Goog-Credential=example%40example-project.iam.gserviceaccount.com%2F20181026%2Fus-central1%2Fstorage%2Fgoog4_request
&X-Goog-Date=20181026T181309Z
&X-Goog-Expires=900
&X-Goog-SignedHeaders=host
&X-Goog-Signature=247a2aa45f169edf4d187d54e7cc46e4731b1e6273242c4f4c39a1d2507a0e58706e25e3a85a7dbb891d62afa849
6def8e260c1db863d9ace85ff0a184b894b117fe46d1225c82f2aa19efd52cf21d3e2022b3b868dc
c1aca2741951ed5bf3bb25a34f5e9316a2841e8ff4c530b22ceaa1c5ce09c7cbb5732631510c2058
0e61723f5594de3aea497f195456a2ff2bdd0d13bad47289d8611b6f9cfeef0c46c91a455b94e90a
66924f722292d21e24d31dcfb38ce0c0f353ffa5a9756fc2a9f2b40bc2113206a81e324fc4fd6823
a29163fa845c8ae7eca1fcf6e5bb48b3200983c56c5ca81fffb151cca7402beddfc4a76b13344703
2ea7abedc098d2eb14a7
*/

var (
	ErrMissingURLParameter = errors.New("some parameters are missing")
	ErrIllegalURLParameter = errors.New("illegal parameter found")
	ErrURLExpired          = errors.New("url was expired")
	ErrBeforeStartDate     = errors.New("before the start date")
	ErrPrivateKeyNotSet    = errors.New("private key not set")
)

var nowFunc = time.Now

const (
	ISO8601 = "20060102T150405Z"

	paramKeyAlgo      = "Algorithm"
	paramKeyDate      = "Date"
	paramKeyExpires   = "Expires"
	paramKeySignature = "Signature"

	SignAlgoRSASHA256 = "RSA-SHA256"

	EncodingHex    encoding = "Hex"
	EncodingBase64 encoding = "Base64"
)

type encoding string

type SigUrl struct {
	ParamKeyPrefix string
	encoding       encoding
	privateKey     string
	publicKey      string
}

func New(prefix string, encoding encoding, privateKey, publicKey string) *SigUrl {
	if prefix == "" {
		prefix = "X-Sig"
	}

	return &SigUrl{
		ParamKeyPrefix: prefix,
		encoding:       encoding,
		privateKey:     privateKey,
		publicKey:      publicKey,
	}
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
	//その他
	//X-Goog-SignedHeaders: 署名付きURLを使用するリクエストの一部として含める必要があるヘッダー。
}

func (s *SigUrl) Sign(baseUrl string, date time.Time, expires uint32) (string, error) {
	if s.privateKey == "" {
		return "", ErrPrivateKeyNotSet
	}
	netURL, err := url.Parse(baseUrl)
	if err != nil {
		return "", err
	}

	query := netURL.Query()
	query.Set(s.paramKey(paramKeyAlgo), SignAlgoRSASHA256)
	query.Set(s.paramKey(paramKeyDate), date.Format(ISO8601))
	query.Set(s.paramKey(paramKeyExpires), fmt.Sprintf("%d", expires))
	message := s.buildURL(netURL, query)
	signature, err := s.sign(message, s.privateKey)
	if err != nil {
		return "", err
	}

	query.Set(s.paramKey(paramKeySignature), signature)
	return s.buildURL(netURL, query), nil
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

	return signedInfo.verify(rawUrl, s.publicKey)
}

func (s *SigUrl) checkURLCanSign(parsed url.URL) bool {
	query := parsed.Query()
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

func (s *SigUrl) sign(message string, privateKeyStr string) (ret string, err error) {
	keyBytes, err := base64.StdEncoding.DecodeString(privateKeyStr)
	if err != nil {
		return "", nil
	}

	private, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write(([]byte)(message))
	digest := hash.Sum(nil)

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, digest)
	if err != nil {
		return "", err
	}

	switch s.encoding {
	case EncodingBase64:
		ret = base64.StdEncoding.EncodeToString(signatureBytes)
		break
	case EncodingHex:
		ret = fmt.Sprintf("%x", signatureBytes)
	}

	return
}

func (si *SignedInfo) verify(message string, pubKeyStr string) error {
	if nowFunc().Before(si.Date) {
		//使用開始時刻になっていない
		return ErrBeforeStartDate
	}

	expiresAt := si.Date.Add(time.Second * time.Duration(si.Expires))
	if expiresAt.Before(nowFunc()) {
		//有効期限切
		return ErrURLExpired
	}

	//署名を検証
	return si.verifySignature(message, pubKeyStr, si.Signature)
}

func (si *SignedInfo) verifySignature(message string, pubKeyStr string, signature string) error {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyStr)
	if err != nil {
		return err
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return err
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	hash := crypto.Hash.New(crypto.SHA256)
	hash.Write([]byte(message))
	digest := hash.Sum(nil)

	return rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, digest, signatureBytes)
}

func (s *SigUrl) SignedInfoFromUrl(parsedUrl *url.URL) (*SignedInfo, error) {
	query := parsedUrl.Query()
	algo := query.Get(s.paramKey(paramKeyAlgo))
	if algo == "" {
		return nil, ErrMissingURLParameter
	} else if algo != SignAlgoRSASHA256 {
		return nil, ErrIllegalURLParameter
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
		return nil, ErrIllegalURLParameter
	}

	dateStr := query.Get(s.paramKey(paramKeyDate))
	if dateStr == "" {
		return nil, ErrMissingURLParameter
	}
	date, err := time.Parse(dateStr, ISO8601)
	if err != nil {
		return nil, ErrIllegalURLParameter
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
	return s.ParamKeyPrefix + "-" + k
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
