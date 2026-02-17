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

package config

import (
	"embed"
	"io"
	"net/http"
	"os"

	"gopkg.in/yaml.v2"
)

//go:embed web/dist/*
var WebFS embed.FS

// InitWebServer 初始化 Web 服务和 API 路由
// handlers 参数: statsHandler, blockedHandler
func InitWebServer(statsHandler, blockedHandler http.HandlerFunc) {
	// API 路由
	http.HandleFunc("/api/stats", statsHandler)
	http.HandleFunc("/api/blocked", blockedHandler)
	http.HandleFunc("/api/config", handleConfig)

	// 静态文件服务（前端页面）
	http.HandleFunc("/", handleStatic)
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// 返回当前配置文件内容
		data, err := os.ReadFile(cfgFile)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/yaml")
		w.Write(data)

	case "POST":
		// 保存新配置
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		// 验证 YAML 语法
		var tmp Conf
		if err := yaml.Unmarshal(body, &tmp); err != nil {
			http.Error(w, "Invalid YAML: "+err.Error(), 400)
			return
		}

		// 写入文件
		if err := os.WriteFile(cfgFile, body, 0644); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		// 热重载配置
		if err := Cfg.Load(cfgFile); err != nil {
			http.Error(w, "Reload failed: "+err.Error(), 500)
			return
		}

		w.Write([]byte("OK"))

	default:
		http.Error(w, "Method not allowed", 405)
	}
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}

	data, err := WebFS.ReadFile("web/dist" + path)
	if err != nil {
		// 返回 index.html 支持前端路由
		data, err = WebFS.ReadFile("web/dist/index.html")
		if err != nil {
			http.Error(w, "Not found", 404)
			return
		}
	}

	// 根据扩展名设置 Content-Type
	w.Header().Set("Content-Type", getContentType(path))
	w.Write(data)
}

func getContentType(path string) string {
	switch {
	case len(path) > 5 && path[len(path)-5:] == ".html":
		return "text/html"
	case len(path) > 4 && path[len(path)-4:] == ".css":
		return "text/css"
	case len(path) > 3 && path[len(path)-3:] == ".js":
		return "application/javascript"
	case len(path) > 4 && path[len(path)-4:] == ".json":
		return "application/json"
	case len(path) > 4 && path[len(path)-4:] == ".png":
		return "image/png"
	case len(path) > 4 && path[len(path)-4:] == ".jpg", len(path) > 5 && path[len(path)-5:] == ".jpeg":
		return "image/jpeg"
	case len(path) > 4 && path[len(path)-4:] == ".svg":
		return "image/svg+xml"
	default:
		return "application/octet-stream"
	}
}
