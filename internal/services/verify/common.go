package verify

import (
	"fmt"
	"github.com/valyala/fasthttp"
	"go-yubikey-val/internal/utils"
	"strconv"
	"time"
)

const (
	S_OK                    = "OK"
	S_BAD_OTP               = "BAD_OTP"
	S_REPLAYED_OTP          = "REPLAYED_OTP"
	S_DELAYED_OTP           = "DELAYED_OTP"
	S_BAD_SIGNATURE         = "BAD_SIGNATURE"
	S_MISSING_PARAMETER     = "MISSING_PARAMETER"
	S_NO_SUCH_CLIENT        = "NO_SUCH_CLIENT"
	S_OPERATION_NOT_ALLOWED = "OPERATION_NOT_ALLOWED"
	S_BACKEND_ERROR         = "BACKEND_ERROR"
	S_NOT_ENOUGH_ANSWERS    = "NOT_ENOUGH_ANSWERS"
	S_REPLAYED_REQUEST      = "REPLAYED_REQUEST"

	TS_SEC           float32 = 1 / 8
	TS_REL_TOLERANCE float32 = 0.3
	TS_ABS_TOLERANCE float32 = 20

	TOKEN_LEN   = 32
	OTP_MAX_LEN = 48
)

// getHttpVal extracts specific HTTP request parameter value by its key, prefers value from the POST request.
func getHttpVal(ctx *fasthttp.RequestCtx, key string, defaultValue string) string {
	if ctx.IsPost() {
		return string(ctx.PostArgs().Peek(key))
	}
	return string(ctx.QueryArgs().Peek(key))
}

// getAllHttpVal extracts all parameters' values in a HTTP request, prefers values from the POST request.
func getAllHttpVal(ctx *fasthttp.RequestCtx) []string {
	var params []string
	var args *fasthttp.Args
	if ctx.IsPost() {
		args = ctx.PostArgs()
	} else {
		args = ctx.QueryArgs()
	}
	args.VisitAll(func(key []byte, value []byte) {
		params = append(params, string(key)+"="+string(value))
	})

	return params
}

func sendResp(ctx *fasthttp.RequestCtx, status string, apiKey string, extra []string) {
	var a []string

	a = append(a, "status="+status)

	now := time.Now()
	t := strconv.FormatInt(now.UnixNano(), 10)[10:13]
	t = now.Format("2006-01-02T15:04:05Z0") + t
	a = append(a, "t="+t)

	for _, v := range extra {
		a = append(a, v)
	}

	h := utils.Sign(a, apiKey)

	var body string
	body += "h=" + h + "\r\n"
	body += "t=" + t + "\r\n"
	for _, v := range extra {
		body += v + "\r\n"
	}
	body += "status=" + status + "\r\n"
	body += "\r\n"

	_, _ = fmt.Fprint(ctx, body)
}
