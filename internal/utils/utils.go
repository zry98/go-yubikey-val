package utils

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
)

// Strtr translates characters, works just like the strtr() function in php (but here only with strings).
// Source: https://github.com/syyongx/php2go/blob/c265c351e6b33f39c7e7996ccdb03679e21741c2/php.go#L536
func Strtr(str string, from string, to string) string {
	trlen, lt := len(from), len(to)
	if trlen > lt {
		trlen = lt
	}
	if trlen == 0 {
		return str
	}
	result := make([]uint8, len(str))
	var xlat [256]uint8
	var i int
	var j uint8
	if trlen == 1 {
		for i = 0; i < len(str); i++ {
			if str[i] == from[0] {
				result[i] = to[0]
			} else {
				result[i] = str[i]
			}
		}
		return string(result)
	}
	for {
		xlat[j] = j
		if j++; j == 0 {
			break
		}
	}
	for i = 0; i < trlen; i++ {
		xlat[from[i]] = to[i]
	}
	for i = 0; i < len(str); i++ {
		result[i] = xlat[str[i]]
	}
	return string(result)
}

// Sign signs a HTTP query string in the array of key-value pairs, it returns a base64 encoded HMAC hash.
func Sign(params []string, apiKey string) string {
	// Alphabetically sort the set of key/value pairs by key order
	// Reference: https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html#_generating_signatures
	sort.Strings(params)

	var str string
	for _, param := range params {
		str += param + "&"
	}
	str = str[:len(str)-1]

	h := hmac.New(sha1.New, []byte(apiKey))
	h.Write([]byte(str))

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// GenerateNonce generates a random MD5 hash as a nonce.
func GenerateNonce() string {
	b := make([]byte, 10)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	h := md5.New()
	h.Write(b)

	return hex.EncodeToString(h.Sum(nil))
}

// Fgetcsv parses the line it reads for fields in CSV format and returns an array containing the fields read.
// It works just like the fgetcsv() function in php.
// Source: https://github.com/syyongx/php2go/blob/c265c351e6b33f39c7e7996ccdb03679e21741c2/php.go#L1604
func Fgetcsv(handle io.Reader, length int, delimiter rune) ([][]string, error) {
	reader := csv.NewReader(handle)
	reader.Comma = delimiter
	// TODO: length limit

	return reader.ReadAll()
}

// InArray works just like the in_array() function in php.
// Source: https://www.php2golang.com/method/function.in-array.html
func InArray(needle interface{}, haystack interface{}) bool {
	switch key := needle.(type) {
	case string:
		for _, item := range haystack.([]string) {
			if key == item {
				return true
			}
		}
	case int32:
		for _, item := range haystack.([]int32) {
			if key == item {
				return true
			}
		}
	case int64:
		for _, item := range haystack.([]int64) {
			if key == item {
				return true
			}
		}
	default:
		return false
	}
	return false
}

// ParseStr works like the parse_str() function in php (BUT ONLY FOR USING IN THIS PROJECT).
// Source: https://github.com/syyongx/php2go/blob/c265c351e6b33f39c7e7996ccdb03679e21741c2/php.go#L245
func ParseStr(encodedString string, result map[string]interface{}) error {
	// build nested map.
	var build func(map[string]interface{}, []string, interface{}) error

	build = func(result map[string]interface{}, keys []string, value interface{}) error {
		length := len(keys)
		// trim ',"
		key := strings.Trim(keys[0], "'\"")
		if length == 1 {
			result[key] = value
			return nil
		}

		// The end is slice. like f[], f[a][]
		if keys[1] == "" && length == 2 {
			// todo nested slice
			if key == "" {
				return nil
			}
			val, ok := result[key]
			if !ok {
				result[key] = []interface{}{value}
				return nil
			}
			children, ok := val.([]interface{})
			if !ok {
				return fmt.Errorf("expected type '[]interface{}' for key '%s', but got '%T'", key, val)
			}
			result[key] = append(children, value)
			return nil
		}

		// The end is slice + map. like f[][a]
		if keys[1] == "" && length > 2 && keys[2] != "" {
			val, ok := result[key]
			if !ok {
				result[key] = []interface{}{}
				val = result[key]
			}
			children, ok := val.([]interface{})
			if !ok {
				return fmt.Errorf("expected type '[]interface{}' for key '%s', but got '%T'", key, val)
			}
			if l := len(children); l > 0 {
				if child, ok := children[l-1].(map[string]interface{}); ok {
					if _, ok := child[keys[2]]; !ok {
						_ = build(child, keys[2:], value)
						return nil
					}
				}
			}
			child := map[string]interface{}{}
			_ = build(child, keys[2:], value)
			result[key] = append(children, child)

			return nil
		}

		// map. like f[a], f[a][b]
		val, ok := result[key]
		if !ok {
			result[key] = map[string]interface{}{}
			val = result[key]
		}
		children, ok := val.(map[string]interface{})
		if !ok {
			return fmt.Errorf("expected type 'map[string]interface{}' for key '%s', but got '%T'", key, val)
		}

		return build(children, keys[1:], value)
	}

	// split encodedString.
	parts := strings.Split(encodedString, "&")
	for _, part := range parts {
		pos := strings.Index(part, "=")
		if pos <= 0 {
			continue
		}
		key, err := url.QueryUnescape(part[:pos])
		if err != nil {
			return err
		}
		for key[0] == ' ' {
			key = key[1:]
		}
		if key == "" || key[0] == '[' {
			continue
		}
		value, err := url.QueryUnescape(part[pos+1:])
		if err != nil {
			return err
		}

		// split into multiple keys
		var keys []string
		left := 0
		for i, k := range key {
			if k == '[' && left == 0 {
				left = i
			} else if k == ']' {
				if left > 0 {
					if len(keys) == 0 {
						keys = append(keys, key[:left])
					}
					keys = append(keys, key[left+1:i])
					left = 0
					if i+1 < len(key) && key[i+1] != '[' {
						break
					}
				}
			}
		}
		if len(keys) == 0 {
			keys = append(keys, key)
		}
		// first key
		first := ""
		for i, chr := range keys[0] {
			if chr == ' ' || chr == '.' || chr == '[' {
				first += "_"
			} else {
				first += string(chr)
			}
			if chr == '[' {
				first += keys[0][i+1:]
				break
			}
		}
		keys[0] = first

		// build nested map
		if err := build(result, keys, value); err != nil {
			return err
		}
	}

	return nil
}
