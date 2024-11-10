package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"os"
)

func Request(req *http.Request, protocol string) (body []byte, err error) {
	f, err := os.OpenFile("./sslkeylogfile/sshkey.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, KeyLogWriter: f},
		},
	}

	url := req.Host + req.URL.String()
	r, _ := http.NewRequest(req.Method, protocol+url, req.Body)
	defer r.Body.Close()
	r.Header = req.Header
	resp, e := c.Do(r)
	if e != nil {
		return nil, e
	}

	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	return body, err
}
