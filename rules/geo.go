//MIT License
//
//Copyright (c) 2021 zngw
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

package rules

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

type GeoInfo struct {
	Lat       float64 `json:"lat"`
	Lon       float64 `json:"lon"`
	QueryTime int64   `json:"query_time"`
	Success   bool    `json:"success"`
}

var geoCache = sync.Map{} // ip -> *GeoInfo

const (
	geoCacheTTL        = 24 * time.Hour
	geoFailureCacheTTL = 10 * time.Minute
)

var geoHTTPClient = &http.Client{Timeout: 4 * time.Second}

// GetGeoInfo 获取 IP 地理坐标（带缓存）
// 使用 ip-api.com 免费 API，限制每分钟 45 次
func GetGeoInfo(ip string) (lat, lon float64, err error) {
	now := time.Now().Unix()

	// 检查缓存
	if v, ok := geoCache.Load(ip); ok {
		geo := v.(*GeoInfo)
		ttl := int64(geoCacheTTL.Seconds())
		if !geo.Success {
			ttl = int64(geoFailureCacheTTL.Seconds())
		}
		if now-geo.QueryTime <= ttl {
			return geo.Lat, geo.Lon, nil
		}
		geoCache.Delete(ip)
	}

	// 调用 ip-api.com
	resp, err := geoHTTPClient.Get("http://ip-api.com/json/" + ip + "?lang=zh-CN&fields=status,lat,lon")
	if err != nil {
		geoCache.Store(ip, &GeoInfo{QueryTime: now, Success: false})
		return 0, 0, err
	}
	defer resp.Body.Close()

	var result struct {
		Status string  `json:"status"`
		Lat    float64 `json:"lat"`
		Lon    float64 `json:"lon"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		geoCache.Store(ip, &GeoInfo{QueryTime: now, Success: false})
		return 0, 0, err
	}

	if result.Status != "success" {
		geoCache.Store(ip, &GeoInfo{QueryTime: now, Success: false})
		return 0, 0, nil // 返回 0,0 但不报错
	}

	// 存入缓存
	geoCache.Store(ip, &GeoInfo{
		Lat:       result.Lat,
		Lon:       result.Lon,
		QueryTime: now,
		Success:   true,
	})

	return result.Lat, result.Lon, nil
}

// EnrichHistoryWithGeo 为 history 添加地理坐标
func EnrichHistoryWithGeo(h *history) {
	if h.Lat != 0 || h.Lon != 0 {
		return // 已有坐标
	}
	lat, lon, _ := GetGeoInfo(h.Ip)
	h.Lat = lat
	h.Lon = lon
}
