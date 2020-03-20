package ksm

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"go-yubikey-val/internal/asynchttp"
	"go-yubikey-val/internal/config"
)

type OtpInfo struct {
	SessionCounter int32
	Low            int32
	High           int32
	UseCounter     int32
}

// Otp2KsmUrls converts an OTP array to an array of YK-KSM URLs for decrypting OTP for client.
// The URLs must be fully qualified, i.e., containing the OTP itself.
func Otp2KsmUrls(otp string, clientId int32) []string {
	//if clientId == 42 {
	//	return []string{"https://another-ykksm.example.com/wsapi/decrypt?otp=" + otp}
	//}
	//
	//if match, _ := regexp.Match(`^dteffujehknh`, []byte(otp)); match {
	//	return []string{"https://different-ykksm.example.com/wsapi/decrypt?otp=" + otp}
	//}
	var ksmUrls []string
	for _, url := range config.Ksm.Urls {
		ksmUrls = append(ksmUrls, url+"?otp="+otp)
	}

	return ksmUrls
}

// KsmDecryptOtp decrypts OTP with YK-KSM.
func KsmDecryptOtp(urls []string) (bool, OtpInfo) {
	var ret OtpInfo

	responses := asynchttp.RetrieveUrlAsync("YK-KSM", urls, 1, "^OK", false, 10)
	if responses == nil {
		log.Debug("YK-KSM response is empty")
		return false, ret
	}
	// TODO: array_shift()?
	response := responses[0]
	log.Debug("YK-KSM response:", response)

	count, err := fmt.Sscanf(response, "OK counter=%04x low=%04x high=%02x use=%02x",
		&ret.SessionCounter, &ret.Low, &ret.High, &ret.UseCounter)
	if err != nil || count != 4 {
		return false, ret
	}

	return true, ret
}
