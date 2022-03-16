package sigurl

import (
	"fmt"
	"github.com/szks-repo/sigurl/test/testutil"
	"testing"
	"time"
)

func Test_Do(t *testing.T) {

	t.Run("", func(t *testing.T) {

		privateKey, publicKey := testutil.GenerateRSAKeyPairAsPem()
		sigUrlInstance := New("", EncodingBase64, privateKey.Bytes, publicKey.Bytes)

		signedUrl, err := sigUrlInstance.Sign("https://www.example.com/blog/001?param1=a", time.Now(), 7200)
		fmt.Println(signedUrl)
		if err != nil {
			t.Error(err)
		}

		if err := sigUrlInstance.Verify(signedUrl); err != nil {
			t.Error(err)
		}

	})
}
