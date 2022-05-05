# Xray



### 项目地址

* https://github.com/chaitin/xray

### 官方文档

* https://docs.xray.cool/

### 使用

#### 爬虫爬取

```
xray webscan --basic-crawler http://testphp.vulnweb.com --html-output vuln.html
```

被动扫描

```
xray ws --listen 127.0.0.1:7777 --html-output proxy.html
.\xray_windows_amd64.exe webscan --listen 127.0.0.1:7777 --html-output 0315.html
```

### 漏洞扫描

#### 漏洞扫描

```
xray ws -u http://testphp.vulnweb.com --html-output report.html
```

#### 批量poc

```
xray ws -p /pentest/xray/pocs/\* -u http://testphp.vulnweb.com --html-output report.html
```

#### 指定poc

```
xray ws -p "./xxx.yml" -u http://example.com/?a=b
shiro

xray webscan --plugins shiro --url-file target.txt --html-output x.html
```

#### 代理

burp 转发给 xray

xray 监听 127.0.0.1:7777

burp Upstream Proxy Servers 中配置 127.0.0.1 7777 即可转发

转发给 burp 查看流量

burp 监听 127.0.0.1:8080

config.yaml 中配置 proxy: “http://127.0.0.1:8080" ,在 burp 中查看流量即可

## 参考链接

* https://docs.xray.cool/#/configration/reverse
* https://www.ctfiot.com/15485.html
