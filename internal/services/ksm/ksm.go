package ksm

import (
	"encoding/hex"
	"fmt"
	"github.com/conformal/yubikey"
	log "github.com/sirupsen/logrus"
	"go-yubikey-val/internal/asynchttp"
	"go-yubikey-val/internal/config"
	"go-yubikey-val/internal/database"
)

type OtpInfo struct {
	SessionCounter int32
	TimestampLow   int32
	TimestampHigh  int32
	UseCounter     int32
}

// DecryptOtp decrypts OTP.
func DecryptOtp(otpString string, clientId int32) (OtpInfo, error) {
	if config.Ksm.UseBuiltin {
		return BuiltInDecryptOtp(otpString)
	}

	ksmUrls := Otp2KsmUrls(otpString, clientId)
	if ksmUrls == nil {
		log.Error("Otp2KsmUrls returned an empty result, please check the config")
		return OtpInfo{}, fmt.Errorf("Empty KSM URLs")
	}
	return KsmDecryptOtp(ksmUrls)
}

// BuiltInDecryptOtp decrypts OTP with Built-in KSM.
func BuiltInDecryptOtp(otpString string) (OtpInfo, error) {
	var otpInfo OtpInfo

	yubikeyPublicName, otp, err := yubikey.ParseOTPString(otpString)
	if err != nil {
		log.Info("error parsing OTP string: ", err)
		return otpInfo, err
	}

	secretKeyString, err := database.GetSecretKey(string(yubikeyPublicName))
	if err != nil {
		log.Error("error getting secret key for yubikey: ", err)
		return otpInfo, err
	}

	keyBytes, err := hex.DecodeString(secretKeyString)
	if err != nil {
		log.Error("error decoding key: ", err)
		return otpInfo, err
	}
	key := yubikey.NewKey(keyBytes)
	token, err := otp.Parse(key)
	if err != nil {
		log.Error("yubikey.Parse error: ", err)
		return otpInfo, err
	}

	otpInfo = OtpInfo{
		SessionCounter: int32(token.Ctr),
		TimestampLow:   int32(token.Tstpl),
		TimestampHigh:  int32(token.Tstph),
		UseCounter:     int32(token.Use),
	}

	return otpInfo, nil
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
func KsmDecryptOtp(urls []string) (OtpInfo, error) {
	var otpInfo OtpInfo

	responses := asynchttp.RetrieveUrlAsync("YK-KSM", urls, 1, "^OK", false, 10)
	if responses == nil {
		return otpInfo, fmt.Errorf("YK-KSM response is empty")
	}
	// TODO: array_shift()?
	response := responses[0]
	log.Debug("YK-KSM response: ", response)

	count, err := fmt.Sscanf(response, "OK counter=%04x low=%04x high=%02x use=%02x",
		&otpInfo.SessionCounter, &otpInfo.TimestampLow, &otpInfo.TimestampHigh, &otpInfo.UseCounter)
	if err != nil || count != 4 {
		return otpInfo, fmt.Errorf("Error parsing YK-KSM response: %v", err)
	}

	return otpInfo, nil
}
