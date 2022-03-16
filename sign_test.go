package sigurl

import (
	"fmt"
	"testing"
	"time"
)

func setup() (privateKey string, publicKey string) {
	return "", ""
}

func Test_Do(t *testing.T) {

	privateKey, publicKey := setup()

	t.Run("", func(t *testing.T) {

		sig := New("X-Amzn", EncodingHex, privateKey, publicKey)
		signedUrl, err := sig.Sign("", time.Now(), 7200)
		if err != nil {
			t.Error(err)
		}

		fmt.Println(signedUrl)
		if err := sig.Verify(signedUrl); err != nil {
			t.Error(err)
		}

	})
}
