package ksm

import (
	"github.com/stretchr/testify/assert"
	"go-yubikey-val/internal/config"
	"io"
	"net/http"
	"testing"
)

func TestOtp2KsmUrls(t *testing.T) {
	config.Ksm.Urls = []string{
		"http://127.0.0.1:80/wsapi/decrypt",
		"http://127.0.0.1:8002/wsapi/decrypt",
	}
	otp := "interncccccbcbevjvdifndbljhrlljurbfgglnfjcfu"
	expected := []string{
		"http://127.0.0.1:80/wsapi/decrypt?otp=interncccccbcbevjvdifndbljhrlljurbfgglnfjcfu",
		"http://127.0.0.1:8002/wsapi/decrypt?otp=interncccccbcbevjvdifndbljhrlljurbfgglnfjcfu",
	}

	actual := Otp2KsmUrls(otp, 1)
	assert.Equal(t, expected, actual)
}

func TestKsmDecryptOtp(t *testing.T) {
	expected := OtpInfo{
		SessionCounter: 1,
		Low:            34495,
		High:           131,
		UseCounter:     4,
	}

	mockServer := startHttpMockServer()
	defer mockServer.Close()

	urls := []string{
		"http://127.0.0.1:8111/wsapi/decrypt?otp=interncccccbcbevjvdifndbljhrlljurbfgglnfjcfu",
		"http://127.0.0.1:8112/wsapi/decrypt?otp=interncccccbcbevjvdifndbljhrlljurbfgglnfjcfu",
	}
	ok, actual := KsmDecryptOtp(urls)

	assert.Equal(t, true, ok)
	assert.Equal(t, expected, actual)
}

func startHttpMockServer() *http.Server {
	srv := &http.Server{Addr: ":8112"}
	http.HandleFunc("/wsapi/decrypt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "OK counter=0001 low=86bf high=83 use=04\n")
	})

	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			panic(err)
		}
	}()

	return srv
}
