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
	"github.com/zngw/golib/log"
)

func Check(text string) {
	err, ip, name, port := parse(text)
	if err != nil {
		if err.Error() != "not tcp link" {
			log.Trace("net", err.Error())
		}

		return
	}

	// 记录 IP 访问历史（用于 Web 统计）
	h := getIpHistory(ip)
	h.Add()

	// 获取 IP 地理位置信息（如果没有）
	if !h.HasInfo {
		country, region, city, ok := lookupIPLocation(ip)
		if ok {
			h.HasInfo = true
			h.Country = country
			h.Region = region
			h.City = city
			lat, lon, _ := GetGeoInfo(ip)
			h.Lat = lat
			h.Lon = lon
		}
	}

	rules(ip, name, port)

	return
}
