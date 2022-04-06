# Google信息收集

### 前言

google作为一款发达的搜索引擎，每天都会爬取各种各样的网站，收录的东西也很多，合理利用Google的搜索语法，可能发现很多敏感的数据信息。

### 基础语法

```
* intitle: 搜索网页标题中必须包含某个词
* inurl: 搜索网页url包含的关键字
* intext：搜索网页中必须包含某个关键字
* site: 搜索特定网站 如：site:.edu.cn
* filetype: 检索指定文件格式的网页
    - filetype:txt
    - filetype:pdf
* allinurl:搜索网页url包含以下所有关键字
    - allinurl:渗透 安全
* allintext: 搜索网页中包含所有关键字
* 精确搜索：给关键字加引号
    * "渗透"
    * '渗透'
* - 减号: 搜索结果排除特定字词
* + 加号：只显示加号后面的内容
* link : Google返回跟此URL做了链接的网站 如link:weixin.com
```
### 渗透-Google语法

- 寻找目标网站后台地址
```
site:xxx.com intext:管理|后台|登录|登陆|用户名|密码|系统|账号|login|system|admin
inurl:edu.cn intitle:管理
site:xxx.com inurl:login|inurl:admin|inurl:admin_login|inurl:system
site:xxx.com intitle:管理|后台|后台管理|登录|登陆
inurl:login|admin|admin_login|login_admin|system|user
site:xxx.com
```

- 寻找文本内容
```
site:xxx.com intext:管理|后台|登录|用户名|密码|验证码|系统|admin|login|username|password
```

- 寻找可注入点
```
site:xxx.com inurl:aspx|jsp|php|asp
site:xxx.com inurl:php?id=
```

- 社工信息
```
site:xxx.com intitle:账号|密码|工号|学号|身份证
site:huoxian.cn intext:"手册"
site:huoxian.cn intext:"文档"（其他自己发挥）
site:huoxian.cn intext:"忘记密码"
site:huoxian.cn intext:"工号"
site:huoxian.cn intext:"优秀员工"
site:huoxian.cn intext:"身份证号码"
site:huoxian.cn intext:"手机号"
```

- 搜索各类开源的网站上面的信息
```
site:github.com intext:xiaodi8.com
```

- 查找文件上传漏洞
```
site:xxx.com inurl:file|load|editor|files|
```

- 查找eweb编辑器
```
site:xxx.com inurl:ewebeditor|editor|uploadfile|eweb|edit
```

- 查找目录遍历漏洞
```
site:xxx.com intitle:index of
```

- 查找存在的数据库
```
site:xxx.com filetype:mdb
site:xxx.com filetype:数据库格式
```

- 查看脚本类型(网站语言类型)
```
site:xxx.com filetype:asp/aspx/php/jsp
site:xxx.com filetype:php
```

- 获取人员类相关信息
```
获取二级域名
site:xxx.com
获取邮箱地址
site:xxx.com intext:*@xxx.com
获取电话信息
site:xxx.com intext:电话
```
在搜集到信息后，可以生成社工字典，使用工具进行跑一遍



### 参考链接

* https://zone.huoxian.cn/d/618 信息收集之“骚”姿势
* https://www.exploit-db.com/google-hacking-database Google Hacking数据库
* https://mp.weixin.qq.com/s/2UJ-wjq44lCF9F9urJzZAA 浏览器搜索语法-完整篇（GoogleHacking）

