package validation

import (
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"go-yubikey-val/internal/config"
	"go-yubikey-val/internal/database"
	"go-yubikey-val/internal/services/ksm"
	"go-yubikey-val/internal/services/sync"
	"go-yubikey-val/internal/utils"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Verify handles a validation request.
func Verify(ctx *fasthttp.RequestCtx) {
	paramSignature := getHttpVal(ctx, "h", "")
	paramClientId := getHttpVal(ctx, "id", "")
	paramTimestamp := getHttpVal(ctx, "timestamp", "")
	paramOtp := strings.ToLower(getHttpVal(ctx, "otp", ""))

	// convert Dvorak OTP
	if match, _ := regexp.MatchString(`^[jxe.uidchtnbpygk]+$`, paramOtp); match {
		paramOtp = utils.Strtr(paramOtp, "jxe.uidchtnbpygk", "cbdefghijklnrtuv")
	}

	/**
	 * Construct response parameters
	 */
	var extra []string
	extra = append(extra, "otp="+paramOtp)

	paramSyncLevel := getHttpVal(ctx, "sl", "")
	//paramTimeout := getHttpVal(ctx, "timeout", "")
	paramNonce := getHttpVal(ctx, "nonce", "")
	/* Nonce is required from protocol 2.0 */
	if paramNonce == "" {
		sendResp(ctx, S_MISSING_PARAMETER, "", nil)
		return
	}
	/* Add nonce to response parameters */
	extra = append(extra, "nonce="+paramNonce)

	/**
	 * Sanity check HTTP parameters
	 *
	 * otp: one-time password
	 * id: client id
	 * timeout: timeout in seconds to wait for external answers, optional: if absent the server decides
	 * nonce: random alphanumeric string, 16 to 40 characters long. Must be non-predictable and changing for each request, but need not be cryptographically strong
	 * sl: "sync level", percentage of external servers that needs to answer (integer 0 to 100), or "fast" or "secure" to use server-configured values
	 * h: signature (optional)
	 * timestamp: requests timestamp/counters in response
	 */
	var syncLevel int32
	if paramSyncLevel != "" {
		tempInt64, err := strconv.ParseInt(paramSyncLevel, 10, 32)
		if err == nil {
			syncLevel = int32(tempInt64)
			if syncLevel < 0 || syncLevel > 100 {
				log.Info("SL is provided but not correct")
				sendResp(ctx, S_MISSING_PARAMETER, "", nil)
				return
			}
		} else {
			if strings.EqualFold(paramSyncLevel, "fast") {
				syncLevel = config.Sync.FastLevel
			} else if strings.EqualFold(paramSyncLevel, "secure") {
				syncLevel = config.Sync.SecureLevel
			}
		}
	} else {
		syncLevel = config.Sync.DefaultLevel
	}

	// TODO: implement sync (with the timeout param)
	//var timeout int32
	//if len(paramTimeout) == 0 {
	//	timeout = config.Sync.DefaultTimeout
	//} else {
	//	tempInt64, err := strconv.ParseInt(paramTimeout, 10, 32)
	//	if err != nil {
	//		log.Info("timeout is provided but not correct")
	//		sendResp(ctx, S_BACKEND_ERROR, "", nil)
	//		return
	//	}
	//	timeout = int32(tempInt64)
	//}

	var otp string
	if paramOtp == "" {
		log.Info("OTP is missing")
		sendResp(ctx, S_MISSING_PARAMETER, "", nil)
		return
	}
	if len(paramOtp) < TOKEN_LEN || len(paramOtp) > OTP_MAX_LEN {
		log.Info("Incorrect OTP length:", paramOtp)
		sendResp(ctx, S_BAD_OTP, "", nil)
		return
	}
	if match, _ := regexp.MatchString(`^[cbdefghijklnrtuv]+$`, paramOtp); !match {
		log.Info("Invalid OTP:", paramOtp)
		sendResp(ctx, S_BAD_OTP, "", nil)
		return
	}
	otp = paramOtp

	var clientId int32
	if paramClientId == "" {
		sendResp(ctx, S_MISSING_PARAMETER, "", nil)
		return
	}
	tempInt64, err := strconv.ParseInt(paramClientId, 10, 32)
	if err != nil {
		log.Info("id provided in request must be an integer")
		sendResp(ctx, S_MISSING_PARAMETER, "", nil)
		return
	}
	if tempInt64 == 0 {
		log.Info("Client ID is missing")
		sendResp(ctx, S_MISSING_PARAMETER, "", nil)
		return
	}
	clientId = int32(tempInt64)

	var nonce string
	if paramNonce != "" {
		if match, _ := regexp.MatchString(`^[A-Za-z0-9]+$`, paramNonce); !match {
			log.Info("NONCE is provided but not correct")
			sendResp(ctx, S_MISSING_PARAMETER, "", nil)
			return
		}
		if len(paramNonce) < 16 || len(paramNonce) > 40 {
			log.Info("Nonce too short or too long")
			sendResp(ctx, S_MISSING_PARAMETER, "", nil)
			return
		}
	}
	nonce = paramNonce

	client, err := database.GetClientData(clientId)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Info("Invalid client id", clientId)
			sendResp(ctx, S_NO_SUCH_CLIENT, "", nil)
			return
		} else {
			log.Error(err)
			sendResp(ctx, S_BACKEND_ERROR, "", nil)
			return
		}
	}
	log.Debug("Client data:", client)

	/**
	 * Check client signature
	 */
	bytes, err := base64.StdEncoding.DecodeString(client.Secret)
	if err != nil {
		log.Error("Error decoding client's API Key", err)
	}
	apiKey := string(bytes)
	if paramSignature != "" {
		// Create the signature using the API key
		allParams := getAllHttpVal(ctx)
		temp := make([]string, 0, len(allParams)-1)
		for _, v := range allParams {
			if !strings.HasPrefix(v, "h=") {
				temp = append(temp, v)
			}
		}

		h := utils.Sign(allParams, apiKey)
		// subtle.ConstantTimeCompare() works like the hash_equals() function in php
		if subtle.ConstantTimeCompare([]byte(h), []byte(paramSignature)) == 0 {
			log.Debug("client h=" + paramSignature + ", server h=" + h)
			sendResp(ctx, S_BAD_SIGNATURE, apiKey, nil)
			return
		}
	}

	otpInfo, err := ksm.DecryptOtp(otp, clientId)
	if err != nil {
		log.Error(err)
		/**
		 * FIXME
		 *
		 * Return S_BACKEND_ERROR if there are connection issues,
		 *    e.g. misconfigured otp2ksmurls.
		 */
		sendResp(ctx, S_BAD_OTP, apiKey, nil)
		return
	}
	log.Debug("Decrypted OTP:", otpInfo)

	// get YubiKey data from database
	publicId := otp[0 : len(otp)-TOKEN_LEN]
	localParams, err := database.GetLocalParams(publicId)
	if err != nil {
		log.Info("Invalid Yubikey", publicId)
		sendResp(ctx, S_BACKEND_ERROR, apiKey, nil)
		return
	}

	log.Debug("Auth data:", localParams)
	if localParams.Active == false {
		log.Info("De-activated Yubikey", publicId)
		sendResp(ctx, S_BAD_OTP, apiKey, nil)
		return
	}

	/* Build OTP params */
	otpParams := database.Params{
		YubiKey: database.YubiKey{
			ModifiedAt:     int32(time.Now().Unix()),
			PublicName:     publicId,
			SessionCounter: otpInfo.SessionCounter,
			UseCounter:     otpInfo.UseCounter,
			TimestampLow:   otpInfo.TimestampLow,
			TimestampHigh:  otpInfo.TimestampHigh,
			Nonce:          nonce,
		},
		Otp: otp,
	}

	/* First check if OTP is seen with the same nonce, in such case we have an replayed request */
	if sync.CountersEqual(localParams, otpParams) && localParams.Nonce == otpParams.Nonce {
		log.Info("Replayed request")
		sendResp(ctx, S_REPLAYED_REQUEST, apiKey, extra)
		return
	}

	/* Check the OTP counters against local db */
	if sync.CountersHigherThanOrEqual(localParams, otpParams) {
		log.Info("replayed OTP: Local counters higher")
		log.Info("replayed OTP: Local counters ", localParams)
		log.Info("replayed OTP: Otp counters ", otpParams)
		sendResp(ctx, S_REPLAYED_OTP, apiKey, extra)
		return
	}

	/* Valid OTP, update database. */
	if sync.UpdateDbCounters(otpParams) == false {
		log.Error("Failed to update yubikey counters in database")
		sendResp(ctx, S_BACKEND_ERROR, apiKey, nil)
		return
	}

	if otpParams.SessionCounter == localParams.SessionCounter &&
		otpParams.UseCounter > localParams.UseCounter {
		ts := (otpParams.TimestampHigh << 16) + otpParams.TimestampLow
		seenTs := (localParams.TimestampHigh << 16) + localParams.TimestampLow
		tsDiff := ts - seenTs
		tsDelta := float32(tsDiff) * TS_SEC

		elapsed := float32(time.Now().Unix() - int64(localParams.ModifiedAt))
		deviation := float32(math.Abs(float64(elapsed - tsDelta)))

		// Time delta server might validation multiple OTPs in a row. In such case validation server doesn't
		// have time to tick a whole second and we need to avoid division by zero.
		var percent float32
		if elapsed != 0 {
			percent = deviation / elapsed
		} else {
			percent = 1
		}

		log.Info("Timestamp", map[string]interface{}{
			"seen":  seenTs,
			"this":  ts,
			"delta": tsDiff,
			"secs":  tsDelta,
			"accessed": fmt.Sprintf("%s (%s)",
				localParams.ModifiedAt,
				time.Unix(int64(localParams.ModifiedAt), 0).
					Format("2006-01-02 15:04:05")),
			"now": fmt.Sprintf("%v (%s)",
				time.Now().Unix(),
				time.Now().Format("2006-01-02 15:04:05")),
			"elapsed":   elapsed,
			"deviation": fmt.Sprintf("%v secs or %v%%", deviation, math.Round(float64(100*percent))),
		})

		if deviation > TS_ABS_TOLERANCE && percent > TS_REL_TOLERANCE {
			log.Info("OTP failed phishing test")

			// FIXME
			// This was wrapped around if (0). should we nuke or enable?
			// sendResp(ctx, S_DELAYED_OTP, apiKey, extra)
		}
	}

	/**
	 * Fill up with more response parameters
	 */
	extra = append(extra, fmt.Sprintf("sl=%v", 0)) // TODO: implement sync

	if paramTimestamp == "1" {
		extra = append(extra, fmt.Sprintf("timestamp=%v", (otpParams.TimestampHigh<<16)+otpParams.TimestampLow))
		extra = append(extra, fmt.Sprintf("sessioncounter=%v", otpParams.SessionCounter))
		extra = append(extra, fmt.Sprintf("sessionuse=%v", otpParams.UseCounter))
	}

	sendResp(ctx, S_OK, apiKey, extra)
	return
}
