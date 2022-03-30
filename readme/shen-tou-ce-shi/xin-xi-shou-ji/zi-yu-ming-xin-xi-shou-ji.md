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

优点：字典较全，自带600万域名字典

缺点：慢，一个域名20分钟左右

```bash
python3 oneforall.py --target example.com run
python3 oneforall.py --targets ./example.txt run
```

### 在线子域名接口

微步在线

优点：及时、方便

缺点：有次数限制
