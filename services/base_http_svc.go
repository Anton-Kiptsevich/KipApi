package services

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"

	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
	"github.com/Anton-Kiptsevich/KipApi/utils"
)

func MakeHttpRequest(req *hm.Request) (hm.Response, error) {
	err := utils.ValidateHttpRequest(req)
	if err != nil { 
		return returnHttpError(err) 
	}
	var body io.Reader
	if req.Body != "" { 
		body = strings.NewReader(req.Body) 
	}
	hReq, err := http.NewRequest(req.Method, req.BaseUrl+req.Path, body)
	if err != nil { 
		return returnHttpError(err) 
	}
	for _, h := range req.Headers {
		if h.Value != nil { 
			hReq.Header.Add(h.Name, *h.Value) 
		}
		if h.Values != nil { 
			for _, v := range h.Values { 
				hReq.Header.Add(h.Name, v) 
			} 
		}
	}
	httpClient := &http.Client{}
	if req.TlsCert != nil {
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{*req.TlsCert}}}
	}
	hRes, err := httpClient.Do(hReq)
	if err != nil { 
		return returnHttpError(err) 
	}
	defer hRes.Body.Close()
	resBody, err := io.ReadAll(hRes.Body)
	if err != nil { 
		return returnHttpError(err) 
	}
	res := hm.Response{Status: hRes.Status, Body: string(resBody)}
	for name, values := range hRes.Header {
		for _, value := range values {
			valueCopy := value
			res.Headers = append(res.Headers, hm.Header{Name: name, Value: &valueCopy})
		}
	}
	return res, nil
}

func returnHttpError(err error) (hm.Response, error) { 
	return hm.Response{}, err 
}
