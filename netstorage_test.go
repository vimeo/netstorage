package netstorage

import (
	"testing"
)

func Test_Signing(t *testing.T) {
	// spec page 15
	key := "key1"
	secret := "abcdefghij"
	rel_path := "/dir1/dir2/file.ext"
	action := "version=1&action=upload&md5=0123456789abcdef0123456789abcdef&mtime=1260000000"
	id := 382644692
	timestamp := 1280000000
	const expected_data = "5, 0.0.0.0, 0.0.0.0, 1280000000, 382644692, key1"
	// spec says expected is "vuCWPzdEW5OUlH1rLfHokWAZAWSdaGTM8yX3bgIDWtA="
	// but contact says it's "Ix98xZYkwygidinpmtKVk9+xPNn5QjozWDMROLjVWSo=" which seems to be the correct one
	const expected_signature = "Ix98xZYkwygidinpmtKVk9+xPNn5QjozWDMROLjVWSo="
	api := NewApi(key, secret)
	data, signature := api.sign(rel_path, action, id, timestamp)
	if data != expected_data {
		t.Errorf("expected data: %s\nreal data: %s", expected_data, data)
	}
	if signature != expected_signature {
		t.Errorf("exected signature: %s\nreal signature: %s\ndata: %s", expected_signature, signature, data)
	}
}
