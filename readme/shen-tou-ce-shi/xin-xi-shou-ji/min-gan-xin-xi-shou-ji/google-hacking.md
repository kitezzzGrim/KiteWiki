# Google信息收集

### 前言

google作为一款发达的搜索引擎，每天都会爬取各种各样的网站，收录的东西也很多，合理利用Google的搜索语法，可能发现很多敏感的数据信息。

### 基础语法

* intitle: 检索含有指定标题内容的网页
* inurl: 检索含有指定内容的URL
* intext：检索在正文部分含有指定内容的网页
* site: 检索与指定网站有联系的所有已收录的网页 如：site:xxx.edu.cn
* filetype: 检索指定文件格式的网页

### 常用语法

```
**intext**
site:huoxian.cn intext:管理|后 台|登陆|用户名|密码|验证码|系统|帐号|manage|admin|login|system
site:huoxian.cn intext:"手册"
site:huoxian.cn intext:"文档"（其他自己发挥）
site:huoxian.cn intext:"忘记密码"
site:huoxian.cn intext:"工号"
site:huoxian.cn intext:"优秀员工"
site:huoxian.cn intext:"身份证号码"
site:huoxian.cn intext:"手机号"

**inurl**
site:huoxian.cn inurl:login|admin|manage|manager|admin_login|login_admin|system
site:huoxian.cn inurl:token
```

### 参考链接

* https://zone.huoxian.cn/d/618 信息收集之“骚”姿势&#x20;
* [https://mp.weixin.qq.com/s/2UJ-wjq44lCF9F9urJzZAA](https://mp.weixin.qq.com/s/2UJ-wjq44lCF9F9urJzZAA) 浏览器搜索语法-完整篇(GoogleHacking)
