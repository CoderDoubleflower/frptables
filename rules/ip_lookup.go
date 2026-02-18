package rules

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type zengwuLookupResponse struct {
	Result   int32  `json:"result,omitempty"`
	Country  string `json:"country,omitempty"`
	Province string `json:"province,omitempty"`
	City     string `json:"city,omitempty"`
}

type ipAPILookupResponse struct {
	Status     string `json:"status"`
	Country    string `json:"country"`
	RegionName string `json:"regionName"`
	City       string `json:"city"`
	Message    string `json:"message"`
}

const ipAPICooldown = 10 * time.Minute

var ipAPICooldownUntil atomic.Int64

func lookupIPLocation(ip string) (country, region, city string, ok bool) {
	if country, region, city, ok = lookupFromIPAPI(ip); ok {
		return country, region, city, true
	}
	return lookupFromZengwu(ip)
}

func lookupFromIPAPI(ip string) (country, region, city string, ok bool) {
	if time.Now().Unix() < ipAPICooldownUntil.Load() {
		return "", "", "", false
	}

	req, err := http.NewRequest(
		http.MethodGet,
		"http://ip-api.com/json/"+ip+"?lang=zh-CN&fields=status,country,regionName,city,message",
		nil,
	)
	if err != nil {
		return "", "", "", false
	}

	resp, err := ipLookupClient.Do(req)
	if err != nil {
		return "", "", "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", "", false
	}

	var data ipAPILookupResponse
	if err = json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", "", "", false
	}

	if data.Status == "success" {
		return data.Country, data.RegionName, data.City, true
	}

	if strings.Contains(strings.ToLower(data.Message), "limit") {
		ipAPICooldownUntil.Store(time.Now().Add(ipAPICooldown).Unix())
	}

	return "", "", "", false
}

func lookupFromZengwu(ip string) (country, region, city string, ok bool) {
	req, err := http.NewRequest(http.MethodGet, "https://ip.zengwu.com.cn?ip="+ip, nil)
	if err != nil {
		return "", "", "", false
	}

	resp, err := ipLookupClient.Do(req)
	if err != nil {
		return "", "", "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", "", false
	}

	var data zengwuLookupResponse
	if err = json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", "", "", false
	}
	if data.Result != 0 {
		return "", "", "", false
	}

	return data.Country, data.Province, data.City, true
}
