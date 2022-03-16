package sigurl

import (
	"errors"
	"fmt"
	"github.com/szks-repo/sigurl/test/testutil"
	"testing"
	"time"
)

func Test_Do(t *testing.T) {

	t.Run("ok", func(t *testing.T) {
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

	t.Run("future date", func(t *testing.T) {
		privateKey, publicKey := testutil.GenerateRSAKeyPairAsPem()
		sigUrlInstance := New("", EncodingBase64, privateKey.Bytes, publicKey.Bytes)
		signedUrl, err := sigUrlInstance.Sign("https://www.example.com/blog/001?param1=a", time.Now().Add(time.Minute*1), 7200)
		if err != nil {
			t.Error(err)
		}

		if err := sigUrlInstance.Verify(signedUrl); !errors.Is(err, ErrBeforeStartDate) {
			t.Error("unexpected result")
		}
	})

	t.Run("expires", func(t *testing.T) {
		privateKey, publicKey := testutil.GenerateRSAKeyPairAsPem()
		sigUrlInstance := New("", EncodingBase64, privateKey.Bytes, publicKey.Bytes)
		signedUrl, err := sigUrlInstance.Sign("https://www.example.com/blog/001?param1=a", time.Now(), 1)
		if err != nil {
			t.Error(err)
		}

		time.Sleep(time.Second * 2)

		if err := sigUrlInstance.Verify(signedUrl); !errors.Is(err, ErrURLExpired) {
			t.Error("unexpected result")
		}
	})
}
