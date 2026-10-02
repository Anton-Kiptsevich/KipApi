package services

import (
	"io"
	"net/http"
	"strings"

	"github.com/Anton-Kiptsevich/KipApi/models"
	"github.com/Anton-Kiptsevich/KipApi/utils"
)

func MakeHttpRequest(req *models.HttpRequest) (models.HttpResponse, error) {
	err := utils.ValidateHttpRequest(req)
	if err != nil {
		return returnHttpError(err)
	}
	var body io.Reader
	var hReq *http.Request
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	
	hReq, err = http.NewRequest(
		req.Method,
		req.BaseUrl + req.Path,
		body,
	)
	
	if err != nil {
		return returnHttpError(err)
	}

	for _, h := range req.Headers {
		if h.Value != nil {
			hReq.Header.Add(h.Name, *h.Value)
		}
		if h.Values != nil {
			for _, v := range h.Values {
				hReq.Header.Add(h.Name, *v)
			}
		}
	}

	httpClient := &http.Client{}

	hRes, err := httpClient.Do(hReq)
	if err != nil {
		return returnHttpError(err)
	}
	defer hRes.Body.Close()
	
	resBody, err := io.ReadAll(hRes.Body)
	if err != nil {
		return returnHttpError(err)
	}
	res := models.HttpResponse{
		Status: hRes.Status,
		Body: string(resBody),
	}

	return res, nil
}

func returnHttpError(err error) (models.HttpResponse, error) {
	return models.HttpResponse{}, err
}