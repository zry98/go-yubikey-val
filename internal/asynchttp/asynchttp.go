package asynchttp

import (
	"context"
	"errors"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"time"
)

type httpResponse struct {
	url  string
	body []byte
	err  error
}

var (
	transport *http.Transport
	client    *http.Client
)

func init() {
	transport = &http.Transport{
		DisableKeepAlives: true,
	}
}

// RetrieveUrlAsync retrieves from URLs asynchronously.
func RetrieveUrlAsync(ident string, urls []string, ansReq int32, pattern string, retUrl bool, timeout int32) []string {
	reqTimeout := time.Second * time.Duration(timeout)
	client = &http.Client{
		Transport: transport,
		Timeout:   reqTimeout,
	}
	ctx, cancel := context.WithTimeout(context.Background(), reqTimeout)
	defer cancel()

	var answers []string
	ch := make(chan *httpResponse, len(urls))
	for _, url := range urls {
		go func() {
			ch <- httpGet(ctx, url)
		}()
	}
	for range urls {
		select {
		case res := <-ch:
			if res.err != nil || res.body == nil {
				// TODO: errno
				log.Info(ident, "errno/error:", res.err)
				continue
			}
			if match, _ := regexp.Match(pattern, res.body); match {
				log.Debug(ident, "response matches", pattern)
			}
			if retUrl {
				answers = append(answers, "url="+res.url+"\n"+string(res.body))
			} else {
				answers = append(answers, string(res.body))
			}
			if int32(len(answers)) >= ansReq {
				return answers
			}

		case <-ctx.Done():
			log.Info("all timeout")
			return nil
		}
	}

	return nil
}

// httpGet gets response from the URL by GET request.
func httpGet(ctx context.Context, url string) *httpResponse {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return &httpResponse{url, nil, err}
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	resp, err := client.Do(req)
	if err != nil {
		return &httpResponse{url, nil, err}
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp.Body != nil {
		if resp.StatusCode == 200 {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return &httpResponse{url, nil, err}
			}
			return &httpResponse{url, body, nil}
		}
		_, err = io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			return &httpResponse{url, nil, nil}
		}
	}

	return &httpResponse{url, nil, errors.New("Empty response body")}
}
