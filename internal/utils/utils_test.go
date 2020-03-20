package utils

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStrtr(t *testing.T) {
	type in struct {
		str      string
		from, to string
	}
	var tests = []struct {
		in       in
		expected string
	}{
		{in{"baabc", "ab", "01"},
			"1001c"},
		{in{"cby.pbjjjjjjytxbiuycxugkkxcdpehigkbpjecd.hgy", "jxe.uidchtnbpygk", "cbdefghijklnrtuv"},
			"interncccccctkbngftibfuvvbihrdjguvnrcdihejut"},
		{in{"cby.pbjjjjjjutbughp..djnijegbcbdkpjhpxtcinb.", "jxe.uidchtnbpygk", "cbdefghijklnrtuv"},
			"internccccccfknfujreehclgcduninhvrcjrbkiglne"},
	}

	for _, test := range tests {
		actual := Strtr(test.in.str, test.in.from, test.in.to)
		assert.Equal(t, test.expected, actual)
	}
}

func TestSign(t *testing.T) {
	type in struct {
		params []string
		apiKey string
	}
	var tests = []struct {
		in       in
		expected string
	}{
		{in{[]string{
			"t=2006-01-02T15:04:05Z0123",
			"otp=internccccchtkbvcgljntutbhfjufgvjedddlltitgt",
			"nonce=sadasdsadavfdvdsfesfda",
			"sl=0",
			"status=MISSING_PARAMETER",
		}, "QSO8AU9Zg/12fwpw0zDe11XNNPM="},
			"SsoM4E4pvdtAuDltA88nTaiKrtI="},
	}

	for _, test := range tests {
		actual := Sign(test.in.params, test.in.apiKey)
		assert.Equal(t, test.expected, actual)
	}
}

func TestGenerateNonce(t *testing.T) {
	previousNonce := GenerateNonce()
	assert.Regexp(t, `^[a-f0-9]{32}$`, previousNonce)

	for i := 0; i < 10; i++ {
		nonce := GenerateNonce()
		assert.Regexp(t, `^[a-f0-9]{32}$`, nonce)
		assert.NotEqual(t, previousNonce, nonce)
		previousNonce = nonce
	}
}

func TestFgetcsv(t *testing.T) {
	var tests = []struct {
		in       string
		expected [][]string
	}{
		{"1,1,1582235608,0mXxHfATd/N/mCmVhU2eK9kC9PQ=,client1@test.email,client1's notes,\n" +
			"2,1,1584675403,QDMMOL85xs11qlwUpqg4qlLDtvs=,client2@test.email,client2's notes,interncccccctkbngftibfuvvbihrdjguvnrcdihejut" +
			"",
			[][]string{
				{"1", "1", "1582235608", "0mXxHfATd/N/mCmVhU2eK9kC9PQ=", "client1@test.email", "client1's notes", "",},
				{"2", "1", "1584675403", "QDMMOL85xs11qlwUpqg4qlLDtvs=", "client2@test.email", "client2's notes", "interncccccctkbngftibfuvvbihrdjguvnrcdihejut",},
			}},
		{"1,1576710055,1576928952,interncccccc,1,3,56979,141,f1f5719a65d9de40cd9adb137495c8f9,\n" +
			"1,1576941345,1576941345,interncccccd,1,0,40027,143,f1f5719a65d9de40cd9adb137495c8f0,test\n",
			[][]string{
				{"1", "1576710055", "1576928952", "interncccccc", "1", "3", "56979", "141", "f1f5719a65d9de40cd9adb137495c8f9", "",},
				{"1", "1576941345", "1576941345", "interncccccd", "1", "0", "40027", "143", "f1f5719a65d9de40cd9adb137495c8f0", "test",},
			}},
	}

	for _, test := range tests {
		var mockedStdin bytes.Buffer
		mockedStdin.Write([]byte(test.in))

		actual, err := Fgetcsv(&mockedStdin, 0, ',')
		assert.NoError(t, err)
		assert.Equal(t, test.expected, actual)
	}
}

func TestInArray(t *testing.T) {
	haystack1 := []string{
		"192.168.1.100",
		"10.0.0.101",
	}
	type in struct {
		needle, haystack interface{}
	}
	var tests = []struct {
		in       in
		expected bool
	}{
		{in{"192.168.1.100", haystack1},
			true},
		{in{"10.0.0.102", haystack1},
			false},
	}

	for _, test := range tests {
		actual := InArray(test.in.needle, test.in.haystack)
		assert.Equal(t, test.expected, actual)
	}
}
