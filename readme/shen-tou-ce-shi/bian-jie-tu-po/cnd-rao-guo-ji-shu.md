# CND绕过技术



## 真实IP

绕过CDN去寻找主机的真实IP，能更容易发现脆弱资产，Bypass CDN是寻找企业网络脆弱资产的至关重要一点。

### 验证是否存在CDN || 是否为真实IP

1.全球ping服务测试，观察对应IP地址是否唯一，若不唯一则多半是使用了CDN

* 在线ping网站：
  * http://ping.chinaz.com/
  * https://ping.aizhan.com/
  * http://itools.com/tool/just-ping

2.nslookup命令探测,原理同上，域名解析返回多个IP则用了CDN技术

```
nslookup www.163.com
```

### 寻找真实IP方法

1.查询域名的历史解析记录

该可能会找到网站使用CDN前的解析记录，从而获取真实IP。

在线查询网站： - 微步在线：https://x.threatbook.cn/ - DNS查询：https://dnsdb.io/zh-cn/ - https://viewdns.info/iphistory/ - https://securitytrails.com/

2.查询子域名

CDN与反向代理成本不低，很多站长可能只会针对主站、大流量网站做CDN，子域名、新子域名可能未来得及加入CDN与反向代理、而这些小站往往跟主站在同一台服务器或者同一个C段、可以通过查询子域名对应的IP来辅助查找真实IP。

如subdomainbrute

```
python3 subdomainbrute.py baidu.com --full -w
```

收集子域名后尝试以解析ip不在cdn上的ip解析主站，真实ip成功被获取到。

3.网络空间资产搜索

在线网站： - shodan：https://www.shodan.io/ - fofa： https://fofa.info

例子：(很多时候能获取网站的真实IP)

```
title:"网站title关键字"
body: "网站的body特征"
```

4.利用SSL证书寻找真实原始IP

该方法准确率较高

**原理** 假如你在123.com上托管了一个服务，原始服务器IP是133.23.63.44。而CloudFlare则会为你提供DDoS保 护，Web应用程序防火墙和其他一些安全服务，以保护你的服务免受攻击。为此，你的Web服务器就必须支持SSL 并具有证书，此时CloudFlare与你的服务器之间的通信，就像你和CloudFlare之间的通信一样，会被加密（即没有 灵活的SSL存在）。这看起来很安全，但问题是，当你在端口443（https://133.23.63.44:443）上直接连接到IP 时，SSL证书就会被暴露。 此时，如果攻击者扫描0.0.0.0/0，即整个互联网，他们就可以在端口443上获取在123.com上的有效证书， 进而获取提供给你的Web服务器IP。

目前Censys工具就能实现对整个互联网的扫描,Censys每天都会扫描IPv4地址空间，以搜索所有联网设备并收集相关的信 息，并返回一份有关资源（如设备、网站和证书）配置和部署信息的总体报告。

在线网站：https://censys.io/certificates?q=

语法：`parsed.names: www.xxx.com and tags.raw: trusted`

5.网站漏洞查询

通过网站的信息泄露漏洞获取真实IP，如PHPinfo、github信息泄露、命令执行ipconfig、XSS盲打、SSRF等。

拿到目标网站管理员CDN账号，可以通过CND配置找到网站的真实IP

6.网站邮件订阅查找 RSS邮件订阅，很多网站自带sendmail会发邮件给我们，此时查看邮件源码里面就会包含服务器的真实IP。

利用网站中有用到邮件的位置，例如注册发邮件、找回密码发邮件等等，查看邮件原文寻找真实IP

7.国外Ping

**原理** 目标对于国外用户没有做CDN，直接Ping可得到真实IP

https://check-host.net/check-ping? http://port.ping.pe/

案例：看到大量国外的服务器去Ping，得到IP都一样，极大概率是真实IP

8.通过ICO图标哈希

原理：图片有一串唯一哈希，网络空间测绘引擎会收集全网IP的信息进行排序收录，那么这些图标的信息，也自然会采集在测绘解析的目标中。

FOFA

查询语句：https://xxx/favicon.co

也可以直接上传ico图片

9.网站证书查询

复制证书的序列号(十六进制)，转为十进制

fofa查询语句：`cert="xxxxxxxxxxx"`

10.理想zmap法

首先从 apnic 网络信息中心获取ip段，然后使用Zmap的 banner-grab 对扫描出来 80 端口开放的主机进行banner抓取，最后在 http-req中的Host写我们需要寻找的域名，然后确认是否有相应的服务器响应。

11.F5 LTM解码法 当服务器使用F5 LTM做负载均衡时，通过对set-cookie关键字的解码真实ip也可被获取，例如：Set-Cookie: BIGipServerpool\_8.29\_8030=487098378.24095.0000，先把第一小节的十进制数即487098378取出来，然后将其转为十六进制数1d08880a，接着从后至前，以此取四位数出来，也就是0a.88.08.1d，最后依次把他们转为十进制数10.136.8.29，也就是最后的真实ip。

#### 相关文章

* https://www.anquanke.com/post/id/163348
* https://www.freebuf.com/articles/web/288784.html web渗透实用操作----11招找真实IP
