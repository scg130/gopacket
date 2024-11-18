package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/lqqyt2423/go-mitmproxy/web"
)

type AddHeader struct {
	proxy.BaseAddon
	count int
}

func (a *AddHeader) Request(f *proxy.Flow) {
	a.count += 1
	// f.Response.Header.Add("x-count", strconv.Itoa(a.count))
	fmt.Println(string(f.Request.Body))
	// fmt.Println(f.Request.Header)
	// fmt.Println(f.Request.URL)
}

func (a *AddHeader) Response(f *proxy.Flow) {
	a.count += 1
	// fmt.Println(f.Response.Header)
	if f.Request.URL.Path == "/app/course/selectCourse" {
		f.Response.Body = []byte(`{"code":200,"data":"ok"}`)
	}
	// fmt.Println(string(f.Request.Body))
}

func main() {
	opts := &proxy.Options{
		Debug:             0,
		Addr:              ":8080",
		StreamLargeBodies: 1024 * 1024 * 5,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	p.AddAddon(&AddHeader{})
	p.AddAddon(web.NewWebAddon(":8081"))

	log.Fatal(p.Start())
}
