package sigurl

import (
	"errors"
	"github.com/szks-repo/sigurl/test/testutil"
	"testing"
	"time"
)

func TestSuccess(t *testing.T) {
	for _, v := range []string{
		"https://www.example.com",
		"https://www.example.com/blog/001?param1=a",
		"https://www.example.com/blog/001?param1=a&param2=b",
		"https://www.example.com/#Id1",
		"https://www.example.com/blog/001?param1=a&param2=b#Id1",
		"/path/to/resource",
	} {
		t.Run("ok", func(t *testing.T) {
			privateKey, publicKey := testutil.GenerateRSAKeyPairAsPem()
			sigUrlInstance := New(privateKey.Bytes, publicKey.Bytes, &Config{
				Encoding:     EncodingBase64,
				CustomPolicy: NewCustomPolicy(),
			})
			sigUrlInstance.RegisterAdditionalVerifyFunc(nil)

			signedUrl, err := sigUrlInstance.Sign(v, time.Now(), 7200)
			if err != nil {
				t.Error(err)
			}

			if err := sigUrlInstance.Verify(signedUrl); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestFail(t *testing.T) {
	t.Run("future date", func(t *testing.T) {
		privateKey, publicKey := testutil.GenerateRSAKeyPairAsPem()
		sigUrlInstance := New(privateKey.Bytes, publicKey.Bytes, &Config{
			Encoding:     EncodingBase64,
			CustomPolicy: NewCustomPolicy(),
		})
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
		sigUrlInstance := New(privateKey.Bytes, publicKey.Bytes, &Config{
			Encoding:     EncodingBase64,
			CustomPolicy: NewCustomPolicy(),
		})
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
