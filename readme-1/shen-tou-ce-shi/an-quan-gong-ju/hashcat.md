---
description: 密码恢复工具
---

# Hashcat

> 内容来源于[1earn-hashcat](https://github.com/ffffffff0x/1earn/blob/267adbbbefc10ff9c036af2b2ca67d09c0ff210f/1earn/Security/%E5%AE%89%E5%85%A8%E5%B7%A5%E5%85%B7/Hashcat.md)

爆破drupal7的密码hash

```
echo "\$S\$DvQI6Y600iNeXRIeEMF94Y6FvN8nujJcEDTCP9nS5.i38jnEKuDR" > source.txt
echo "\$S\$DWGrxef6.D0cwB5Ts.GlnLw15chRRWH2s1R3QBwC0EkvBQ/9TCGg" >> source.txt

hashcat -m 7900 -a 0 source.txt pass01.txt

-m 指定要破解的 hash 类型，如果不指定类型，则默认是 MD5
-a 指定要使用的破解模式，其值参考后面对参数。“-a 0”字典攻击，“-a 1” 组合攻击；“-a 3”掩码攻击。
source.txt 你要爆破的 hash 列表
pass01.txt 你的密码表
```
