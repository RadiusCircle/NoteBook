# 羊城杯-2021-网络安全大赛高职组-你问我我问谁战队-WP 之前一份不全，请以这份为准

## 1、签到题 ##

![image-20210912090318117](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912090318117.png)

因为题目要求的数字范围是1-30，所以猜测是28

![image-20210912090422672](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912090422672.png)

八卦图，猜测是08

![image-20210912090447961](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912090447961.png)

而立之年，就是30岁，猜测是30

![image-20210912090527259](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912090527259.png)

北斗七星，猜测是07

![image-20210912090552986](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912090552986.png)

江南四大才子，猜测是04

![image-20210912090627029](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912090627029.png)

歼20，猜测是20

![image-20210912090647616](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912090647616.png)

两个黄鹂鸣翠柳，猜测是02

![image-20210912090718082](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912090718082.png)

这图本来猜测是05，发现不是，仔细观察后才发现，“一起”谐音17

![image-20210912090857285](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912090857285.png)

不用多说了，23

![image-20210912090918041](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912090918041.png)

一马当先，猜测01

![image-20210912090938976](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912090938976.png)

十二星座，猜测12

![image-20210912091006755](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912091006755.png)

新闻联播，每天19：00首播，猜测19

连起来就是28-08-30-07-04-20-02-17-23-01-12-19

![image-20210912091520725](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912091520725.png)

MD5加密后，得到flag

## 2、misc520 ##

先放提示

![image-20210912091706526](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912091706526.png)

打开压缩包后发现里面套了好多压缩包

![image-20210912091816591](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912091816591.png)

在150.zip中发现一半flag

![image-20210912124502792](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912124502792.png)

依据提示，flag开头为GWHT

查表知，GWHT的ascii码为71、87、72、84

分析可知，为凯撒加密

解密得GWHT{W3lCom3_

全部解开后发现png图片

![image-20210912092436439](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912092436439.png)

根据提示我们可以确定是lsb隐写

用StegSolve查看

发现red 0、green 0和blue 0三个通道存在异常

![image-20210912092642307](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912092642307.png)

![image-20210912092709060](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912092709060.png)

![image-20210912092802726](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912092802726.png)

尝试解密，发现压缩包

![image-20210912092958777](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912092958777.png)

保存分离后尝试打开，发现需要密码

![image-20210912093058627](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912093058627.png)

仔细查看提示，没有发现与密码相关的信息，遂爆破

![image-20210912093417877](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912093417877.png)

得到密码，解开压缩包

wireshrak打开后发现是usb数据

使用

```
tshark -r usb.pcap -T fields -e usb.capdata | sed '/^\s*$/d' > usbdata.txt
```

提取并去除空行后得到cap date数据

![image-20210912095007114](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912095007114.png)

数据长度4个字节，所以是鼠标移动数据

在每个字节后加上冒号

```python
f=open('usbdata.txt','r')
fi=open('out.txt','w')
while 1:
    a=f.readline().strip()
    if a:
        if len(a)==8: # 鼠标流量的话len改为8，键盘改为16
            out=''
            for i in range(0,len(a),2):
                if i+2 != len(a):
                    out+=a[i]+a[i+1]+":"
                else:
                    out+=a[i]+a[i+1]
            fi.write(out)
            fi.write('\n')
    else:
        break

fi.close()
```

得到

![image-20210912095358236](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912095358236.png)

使用脚本获取鼠标移动路径

```python
nums = []
keys = open('out.txt','r')
f = open('xyzp.txt','w')
posx = 0
posy = 0
for line in keys:
    if len(line) != 12 :
        continue
    x = int(line[3:5],16)
    y = int(line[6:8],16)
    if x > 127 :
        x -= 256
    if y > 127 :
        y -= 256
    posx += x
    posy += y
    btn_flag = int(line[0:2],16)  # 1 for left , 2 for right , 0 for nothing
    if btn_flag == 0 : # 1 代表左键
        f.write(str(posx))
        f.write(' ')
        f.write(str(posy))
        f.write('\n')

f.close()
```

得到左键与右键得移动路径

左键

![image-20210912125522949](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912125522949.png)

右键

![image-20210912125539381](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912125539381.png)

用gnuplot将`xy.txt与xyz.txt`里的坐标转化成图像

![image-20210912125657758](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912125657758.png)

![image-20210912125730893](C:\Users\Gundam\AppData\Roaming\Typora\typora-user-images\image-20210912125730893.png)

修整后得到两串数据

130 63 111 

与

94 51 114 139 146

与上面一样，是凯撒解密

得到t0_与M!sc}

组合后得到flag

Sangfor{W3lCom3_t0_M!sc}

## 3、Baby_Forenisc  ##

查看镜像

![](wp.assets/微信图片_20210912175936.png)

在桌面发现可疑信息

![](wp.assets/微信图片_20210912175929.png)

发现ssh，导出

解码base64，得到账户

![](D:/桌面/新建文件夹/微信图片_20210912180459.png)

在github上搜索邮箱，找到用户，下载文件

![image-20210912172610631](wp.assets/image-20210912172610631.png)

得到flag

![image-20210912172538002](wp.assets/image-20210912172538002.png)
