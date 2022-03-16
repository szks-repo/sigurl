# sigurl

generate signed url and verify signed url

```go
package main

import (
	"fmt"
	"time"

	"github.com/szks-repo/sigurl"
)

var sigUrlInstance *sigurl.SigUrl

func main() {

	sigUrlInstance = sigurl.New("", sigurl.EncodingHex, "YOUR_PRIVATE_KEY", "YOUR_PURLIC_KEY")
	
	signedUrl, err := sigUrlInstance.Sign("https://www.example.com/page/1?paramA=value&paramB=value", time.Now(), 7200)
	if err != nil {
		panic(err)
	}
	fmt.Println(signedUrl)
	/*
	Output:
	https://www.example.com/page/1?paramA=value&paramB=value?X-Sig-Algorithm=RSA-SHA256&X-Sig-Date=20210101T123012Z&X-Sig-Expires=7200&X-Sig
	*/
	
	if err := sigUrlInstance.Verify(signedUrl); err != nil {
		panic(err)
	}
}
```
