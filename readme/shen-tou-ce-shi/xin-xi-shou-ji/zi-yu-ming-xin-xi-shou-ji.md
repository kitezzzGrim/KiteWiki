# 子域名信息收集

### layer子域名挖掘

工具地址：https://github.com/lijiejie/subDomainsBrute

`pip install aiodns` `python3 subDomainsBrute.py iflytek.com`

上面自动化整理子域名：

```py
python3 subdomain-collection.py 1.txt
# 输出output.txt
```

### OneForall

工具地址：https://github.com/shmilylty/OneForAll

```bash
python3 oneforall.py --target example.com run
python3 oneforall.py --targets ./example.txt run
```

### 在线接口

```
https://crt.sh/
https://censys.io/
https://transparencyreport.google.com/https/certificates
https://dnsdumpster.com/
https://hackertarget.com/find-dns-host-records/
https://x.threatbook.cn/
https://www.virustotal.com/gui/home/search
https://phpinfo.me/domain/
https://site.ip138.com/baidu.com/domain.htm
https://www.t1h2ua.cn/tools/
http://tool.chinaz.com/subdomain/
https://spyse.com/site/not-found?q=domain%3A%22github%22&criteria=cert
```
