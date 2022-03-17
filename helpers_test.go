package sigurl

import (
	"net/url"
	"reflect"
	"testing"
)

func Test_cloneQuery(t *testing.T) {
	t.Run("case1", func(t *testing.T) {
		original := url.Values{}
		original.Set("key1", "value1")
		original.Set("key2", "value2")

		copied := cloneQuery(original)
		copied.Set("key1", "valueUpdated")
		copied.Set("keyCopied", "valueCopies")

		if reflect.DeepEqual(original, copied) {
			t.Errorf("clone failed")
		}
	})
}
