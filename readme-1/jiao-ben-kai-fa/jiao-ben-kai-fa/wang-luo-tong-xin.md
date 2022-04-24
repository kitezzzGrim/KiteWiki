# 网络通信

## 前言

在实际的渗透中，协议是建立据点网络通道的基础，可以通过网络通道对内部的服务器进行控制

锻炼个人对于协议的理解和对网络通道建立的使用方法，有了这个基础可以实现一些比如远控木马、端口扫描、服务爆破方面的工具。

1、理解TCP、UDP协议的原理及特点
2、分别使用 TCP、UDP 协议实现数据通讯

## 操作

1.客户端
```py
#!/usr/bin/python3

import socket
import sys

# 创建 socket 对象
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 获取本地主机名
host = socket.gethostname()

# 设置端口号
port = 9999

# 连接服务，指定主机和端口
s.connect((host, port))

# 接收小于 1024 字节的数据
msg = s.recv(1024)

s.close()

print (msg.decode('utf-8'))
```

2.服务端
```py
#!/usr/bin/python3

import socket
import sys

# 创建 socket 对象
serversocket = socket.socket(
    socket.AF_INET, socket.SOCK_STREAM)

# 获取本地主机名
host = socket.gethostname()

port = 9999

# 绑定端口号
serversocket.bind((host, port))

# 设置最大连接数，超过后排队
serversocket.listen(5)

while True:
    # 建立客户端连接
    clientsocket,addr = serversocket.accept()
    print("连接地址: %s" % str(addr))
    msg='你已访问到服务端'+ "\r\n"
    clientsocket.send(msg.encode('utf-8'))
    clientsocket.close()
```

## 参考链接

- https://blog.csdn.net/qq_44176343/article/details/108312131
- https://www.runoob.com/python3/python3-socket.html