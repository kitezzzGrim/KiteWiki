# JS信息收集

### FindSomething

快速获取JS中的URL链接、接口、手机号、IP、域名等，无需一个个打开JS查看



JS常见敏感关键字：admin、config、password、token、email、.conf

### JSFinder

项目地址：https://github.com/Threezh1/JSFinder

某厂商的网络监控平台

使用 JSFinder 扫描

访问 main.html 越权访问后台，同样目录爆破也可以做到...

* 简单爬取

`python JSFinder.py -u http://www.mi.com`

这个命令会爬取 http://www.mi.com 这单个页面的所有的js链接，并在其中发现url和子域名

* 深度爬取

`python JSFinder.py -u http://www.mi.com -d`

* 批量指定URL/指定JS

```
python JSFinder.py -f text.txt
python JSFinder.py -f text.txt -j
```
