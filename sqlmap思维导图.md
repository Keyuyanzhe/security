# SQLMAP作用
1. 判断可注入的参数
2. 判断可以用哪种SQL注入技术来注入
3. 识别出哪种数据库
4.  根据用户选择，读取哪些数据

# 五种注入模式
1. 基于布尔的盲注，即可以根据返回页面判断条件真假的注入。
2. 基于时间的盲注，即不能根据页面返回内容判断任何信息，用条件语句查看时间延迟语句是否执行（即页面返回时间是否增加）来判断。
3. 基于报错注入，即页面会返回错误信息，或者把注入的语句的结果直接返回在页面中。
4. 联合查询注入，可以使用union的情况下的注入
5. 堆查询注入，可以同时执行多条语句的执行时的注入。

# 支持哪些数据库注入？
- MySQL
- Oracle
- PostgreSQL
- Microsoft SQL Server
- Microsoft Access
- IBM DB2
- SQLite
- Firebird
- Sybase
- SAP MaxDB

# 必备参数
## 观察数据
**-v参数，共有7个等级，默认为1**
- -v 0  只显示python错误以及严重的信息
- -v 1  同时显示基本信息和警告信息。（默认）
- -v 2  同时显示debug信息。
- -v 3  同时显示注入的payload。
- -v 4  同时显示HTTP请求。
- -v 5  同时显示HTTP相应头。
- -v 6 同时显示HTTP相应页面。

如果想看到SQLmap发送的测试payload最好的等级就是3
## 获取目标方式
1. 直接连接到数据库  

参数：-d   

对单个数据库实例运行SQLmap
```
python sqlmap.py -d "mysql://admin:admin@127.0.0.1:3306/db"
```
2. 目标URL</br>
参数：-u或者--url
```
python sqlmap.py -u "http(s)://targeturl:[port]/[...]" 
```
3. 从Burp或者WebScarab代理中获取日志  
参数：-l   
从日志直接导出来交给sqlmap检测
4. 从文本中获取多个目标扫描
	参数：-m
	url保存在文本中，sqlmap一个一个检测
5. 从文件中加载HTTP请求
	参数：-r
	可以跳过设置一些其他参数比如cookie，POST数据
	*当请求是HTTPS的时候需要配合这个--force-ssl参数使用，或者可以在Host头后面加上:443*
6. 处理Google的搜索结果
	参数：-g
	sqlmap可以测试注入Google的搜索结果中的GET参数
```
python sqlmap.py -g "inurl:\".php?id=1\""
```
7. 配置加载选项INI文件
	参数：-c
	加载sqlmap.conf文件里面的相关配置

## 请求方式
1. HTTP数据 
	参数：--data
	把数据以POST方式提交,sqlmap会像检测GET参数一样检测POST的参数
```
python sqlmap.py -u "http://www.target.com/vuln.php" --data="id=1"
```
2. 参数拆分字符
	参数：-param-del
	当GET或POST的数据需要用其他字符分割测试参数的时候需要用到此参数
```
python sqlmap.py -u "http://www.target.com/vuln.php" --data="query=foobar;id=1" --param-del=";" 
```
3. HTTP cookie头
	参数：--cookie, --load-cookies, --drop-set-cookie
	web应用需要登录的时候
	在这些头参数中测试SQL注入时
	*如果不想接受Set-Cookie可以使用--drop-set-cookie参数来拒接*
4. HTTP User-Agent头
	参数：--user-agent, --random-agent
	可以使用--user-agent参数来修改，同时也可以使用--random-agent参数随机从./txt/user-agents.txt中获取
	*当--level参数设定为3或者3以上时，会尝试对User-Agent进行注入*
5. HTTP host头
	参数：--host
	可以手动设置HTTP host的值
6. HTTP Referer头：
	参数：--referer
	sqlmap可以在请求中伪造HTTP中的referer，当--level参数设定为3或者3以上的时候会尝试对referer注入
7. 额外的HTTP头
	参数：--headers
	可以通过--headers参数来增加额外的http头
8. HTTP认证保护
	参数：--auth-type, --auth-cred
	登录HTTP的认证保护支持三种方式：
    - Basic
    - Digest
    - NTLM
```
python sqlmap.py -u "http://192.168.1.1/sqlmap/mysql/basic/get_int.php?id=1" --auth-type Basic --auth-cred "testuser:testpass"
```
9. HTTP协议的证书认证
	参数：--auth-type, --auth-cert
	当web服务器需要端客户证书进行身份验证时，需要提供两个文件：key_file, cert_file
	key_file是格式为PEM文件，包含着你的私钥，cert_file是格式为PEM的连接文件
10. HTTP协议私有密钥身份验证
	参数：--auth-private
	这个选项应该在情况下，web服务器需要使用适当的客户端私钥进行身份验证，提供的价值应该是PEM格式key_file包含你的私钥
11. HTTP(S)代理
	参数：--proxy, --proxy-cred, --ignore-proxy
	使用--proxy代理格式为：http://url:port/
	当HTTP(S)代理需要认证是可以使用--proxy-cre参数：username:password
	--ignore-proxy拒绝使用本地局域网的HTTP(S)代理
12. Tor网络匿名
	参数：--tor, --tor-port, --tor-type和--check-tor
	如果你需要保持匿名，而不是经过一个预定义的HTTP(S)代理服务器，你可以配置一个Tor客户在一起Privoxy（或类似的）在你的机器上解释Tor安装指南，然后你可以使用一个开关--tor和sqlmap将尝试自动设置Tor代理连接设置
13. HTTP请求延迟
	参数：--delay
	设定两个HTTP(S)请求间的延迟，设定为0.5的时候是半秒，默认是没有延迟的
14. 设定超时时间
	参数：--timeout
	可以设定一个HTTP(S)请求超过15多久判定为超时，默认是30秒
15. 设定重试超时
	参数：--retries
	当HTTP(S)超时时，可以设定重新尝试连接次数，默认是3次
16. 设定随机改变的参数值
	参数：--randomize
	可以设定某一个参数值在每一次请求中随机的变化，长度和类型会与提供的初始值一样
17. 利用正则过滤目标网址
	参数：--scope
```
python sqlmap.py -l burp.log --scope="(www)?\.target\.(com|net|org)"
```
18. 避免过多的错误请求被屏蔽
	参数：--safe-url, --safe-freq
	有的web应用程序会在你多次访问错误的请求时屏蔽掉你以后的所有请求，这样在sqlmap进行探测或者注入的时候可能造成错误请求而触发这个策略，导致以后无法进行。
    - --safe-url：提供一个安全不错误的连接，每隔一段时间都会访问一下
    - --safe-freq：提供一个安全不错误的连接，每次测试请求之后都会再访问一遍安全连接
19. 使用SSL/HTTPS
	参数：--force-ssl
	如果用户想要强迫使用SSL/HTTPS请求目标，可以使用此参数
20. 关掉URL参数值编码
	参数：--skip-urlencode
	根据参数位置，他的值默认将会被URL编码，但是有些时候后端的web服务器不遵守RFC标准只接受不经过URL编码的值，这时候就需要用--skip-urlencode参数
21. 每次请求时候执行自定义的python代码
	参数：--eval
	有些时候需要根据某个参数的变化，而修改另一个参数，才能形成正常的请求，这时可以用--eval参数在每次请求时根据所写python代码做完修改后请求
```
python sqlmap.py -u "http://www.target.com/vuln.php?id=1&hash=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib;hash=hashlib.md5(id).hexdigest()"
```

## 优化
1. 收集优化
	参数：-o
	这个参数是一个别名，隐式地设置以下选项和交换机
    - --keep-alive
    - --null-connection
    - --threads=3
2. 输出预测
    参数：--predict-output
	这里是用于推理算法顺序检索的值的字符统计预测
3. HTTP活动
	参数：--keep-alive
	指示sqlmap HTTP(S)使用持久连接
4. HTTP空连接
	参数：--null-connection
	可以用在盲目注入技术来区分True从False响应
5. 并发HTTP(S)请求
	参数：-threads
	可以指定并发HTTP(S)请求的最大数量

## 探测
1. 测试参数
	参数：-p, -skip
	当使用--level的值很大但是有个别参数 不想测试的时候可以使用--skip参数，
```
--skip="user-agent.referer"
```
2. URL注入点
	参数：-u
```
python sqlmap.py -u "http://targeturl/param/value*/
```
3. 指定数据库
	参数：-dbms
	默认情况sqlmap会自动探测web应用后端的数据库
4. 风险等级
	参数：--risk
	共有三个风险等级，默认是1会测试大部分的测试语句，2会增加基于事件的测试语句，3会增加OR语句的SQL注入测试
5. 页面比较
	参数：--string, --not-string, --regexp, --code
	默认情况下sqlmap通过判断返回页面的不同来判断真假，但有时候这会产生误差，因为有的页面在每次刷新的时候都会返回不同的代码，比如页面当中包含一个动态的广告或者其他内容，这会导致sqlmap的误判。此时用户可以提供一个字符串或者一段正则匹配，在原始页面与真条件下的页面都存在的字符串，而错误页面中不存在（使用--string参数添加字符串，--regexp添加正则），同时用户可以提供一段字符串在原始页面与真条件下的页面都不存在的字符串，而错误页面中存在的字符串（--not-string添加）。用户也可以提供真与假条件返回的HTTP状态码不一样来注入，例如，响应200的时候为真，响应401的时候为假，可以添加参数--code=200。
	参数：--text-only, --titles
	有些时候用户知道真条件下的返回页面与假条件下返回页面是不同位置在哪里可以使用--text-only（HTTP响应体中不同）--titles（HTML的title标签中不同）。

## 注入技术
1. 测试是否是注入点
   参数：--technique
    - B:Boolean-based blind SQL injection（布尔型注入）
    - E:Error-based SQL injection（报错型注入）
    - U:UNION query SQL injection（可联合查询注入）
    - S:Stacked queries SQL injection（可多语句查询注入）
    - T:Time-based blind SQL injection（基于时间查询注入）
2. 设定延迟注入的时间
    参数： --time-sec
    当使用基于时间的盲注时，使用--time-sec参数设定延迟时间，默认是5秒
3. 设定UNION查询字段数
	参数：--union-cols
	默认情况下sqlmap测试UNION查询注入会测试1-10字段数，当--level为5的时候，他会增加测试到50个字段数，设定--union-cols的值应该是一段整数，如：12-16
4. 设定UNION查询使用的字符
	参数：--union-char
	默认情况下sqlmap针对UNION查询的注入会使用NULL字符，但是有些情况下会造成页面返回失败，而一个随机整数是成功的，这时你可用--union-char指定UNION查询的字符
5. DNS泄露攻击
	参数：--dns-domain
	如果用户是控制一台机器注册为DNS域服务器（例如域attacker.com）他可以打开使用这个选项
6. 二阶SQL注入
	参数：--second-order
	有些时候注入点输入的数据看返回结果的时候并不是当前的页面，而是另外的一个页面，这时候就需要你指定到哪个页面获取响应判断的真假，--second-order后面跟一个判断页面的URL地址

## 指纹
	数据库管理系统指纹
	参数：-f或--fingerprint
	通过指纹判别数据库类型
## 列数据
1. 标志
	参数：-b, --banner
	获取当前数据库版本
2. 用户
	参数：--current-user
3. 当前数据库
	参数：--current-db
4. 当前用户是否为管理员
	参数：--is--dba
5. 列数据库管理用户
	参数：--users
	当前用户有权限读取包含所有用户的表的权限时，就可以列出所有管理用户
6. 列出并破解数据库用户的hash
	参数：--passwords
	当前用户有权限读取包含用户密码的表的权限时，就可以列出hash，并尝试破解
	*也可以提供-U参数来指定爆破某个用户的hash*
```
python sqlmap.py -u "http://192.168.1.1/sqlmap/pgsql/get_int.php?id=1" --passwords -v 1
```
7. 列出数据库管理员权限
	参数：--privileges
	当前用户有权限读取包含所有用户的表的权限时，很可能列举出每个用户的权限，sqlmap将会告诉你哪个是数据库的超级管理员，也可以用-U参数指定某个用户
8. 列出数据库管理员角色
 	参数：--roles
	当前用户有权限读取包含所有用户的表的权限，很可能列举出每个用户的角色，也可以用-U参数指定你想看某个用户的角色
	*仅适用于当前数据库是Oracle的时候*
9. 列出数据库系统的数据库
	参数：--dbs
	当前用户有权限读取包含所有数据库列表信息的表中的时候，即可列出所有的数据库
10. 列举数据库表
	参数：--tables, --exclude-sysdbs, -D
	如果不提供-D参数来列指定的一个数据的时候，sqlmap会列出所有的数据库的所有表
	--exclude-sysdbs参数是指包含了所有的系统数据库
	*需要注意的是在Oracle中需要提供的是TABLESPACE_NAME而不是数据库名称*
11. 列举数据库中的字段
	参数：--columns, -C, -T, -D
	如果没有使用-D参数指定数据库时，默认会使用当前数据库
12. 列举数据库系统的架构
	参数：--schema, --exclude-sysdbs
	可以用此参数获取数据库的架构，包含所有的数据库，表和字段，以及各自的类型
	*加上--exclude-sysdbs参数，将不会获取数据库自带的系统库内容*
13. 获取表中数据个数
	参数：--count
14. 获取整个表的数据
	参数：--dump, -C, -T, -D, --start, --stop, --first, --last
	如果当前管理员有权限读取数据库其中一个表的话，就能获取整个表的所有内容
	使用-D, -T参数指定数据库和表，不使用-D参数时，默认使用当前库
	可以获取指定库中的所有表的内容，只用-dump和-D参数（不使用-T与-C参数）
15. 获取所有数据库表的内容
	参数：--dump-all, --exclude-sysdbs
	使用--dump-all参数获取所有数据库表的内容，可同时加上--exclude-sysdbs只获取用户数据库的表，需要注意在Microsoft SQL Server中maser数据库没有考虑成为一个系统数据库，因为有的管理员会把他当成用户数据库一样使用
16. 搜索字段，表，数据库
	参数：--search, -C, -T, -D
	--search可以用来寻找特定的数据库名，所有数据库中的特定表名，所有数据库中的特定字段
	-C后跟着用逗号分隔的列名，将会在所有数据库表中搜索指定的列名
	-T后跟着用逗号分隔的表名，将会在所有数据库中搜索指定的表名
	-D后跟着用逗号分隔的库名，将会在所有数据库中搜索指定的库名
17. 运行自定义的SQL语句
	参数：--sql-query, --sql-shell
	如果是SELECT查询语句，sqlmap将会输出结果，如果通过SQL注入执行其他语句，需要测试是否支持多语句执行

## 爆破
1. 暴力破解表名
	参数：--common-tables
	当使用--tables无法获取到数据库的表时，可以使用此参数
2. 暴力破解列名
	参数：--common-columns
	与暴力破解表名一样，暴力跑的列名在txt/common-columns.txt中

## 用户自定义函数注入
	用户自定义函数（UDF）
	参数：--udf-inject, --shared-lib
	你可以通过反编译MySQL注入你自定义的函数（UDFs)或PostgreSQL在Windows中共享库，DLL，或者Linux/Unix中共享对象，sqlmap将会问你一些问题，上传到服务器数据库自定义函数，然后根据你的选择执行他们，当你注入完成后，sqlmap将会移除它们。
## 系统文件操作
1. 从数据库服务器中读取文件
	参数：--file-read
	当数据库为MySQL，PostgreSQL或Microsoft SQL Server，并且当前用户有权限使用特定的函数，读取的文件可以是文本也可以是二进制文件
2. 把文件上传到数据库服务器中
	参数：--file-write, --file-dest
	当数据库为MySQL，PostgreSQL或Microsoft SQL Server，并且当前用户有权限使用特定的函数，上传的文件可以是文本也可以是二进制文件

## 操作系统
1. 运行任意操作系统命令
	参数：--os-cmd
	当数据库为MySQL，PostgreSQL或Microsoft SQL Server，并且当前用户有权限使用特定的函数
	在MySQL，PostgreSQL，sqlmap上传一个二进制库，包含用户自定义的函数，sys_exec()和sys_eval()
2. 写入真实的shell
	参数：--os-shell
	网站绝对路径
    - ASP
    - ASP.NET
    - JSP
    - PHP
3. Meterperter配合使用
	参数：--os-pwn, --os-smbrelay, --os-bof, --priv-esc, --msf-path, --tmp-path
    - 通过用户自定义的sys_bineval()函数在内存中执行Metasploit的shellcode，支持MySQL和PostgreSQL数据库，参数：--os-pwn
    - 通过用户自定义的函数上传一个独立的payload执行 ，MySQL和PostgreSQL的sys_exec()函数，Microsoft SQL Server的xp_cmdshell()函数，参数：--os-pwn
    - 通过SMB攻击（MS08-068）来执行Metasploit的shellcode，当sqlmap获取到的权限足够高时（Linux/Unix的uid=0，Windows是Administrator），参数：--os--smbrelay
    - 通过溢出Microsoft SQL Server 2000和2005的sp_replwritetovarbin存储过程（MS09-004），在内存中执行Metersploit的payload，参数：--os-bof

## 对Windows注册表的操作
1. 读取注册表值
	参数：--reg-read
2. 写入注册表值
	参数：--reg-add
3. 删除注册表值
	参数： --reg-del
4. 注册表辅助选项
	参数： --reg-key, --reg-value, --reg-data, --reg-type
## 其他的一些参数
1. 使用参数缩写
	参数：-z
	有使用参数太长太复杂，可以使用缩写模式
2. 成功SQL注入时警告
	参数：-alert
3. 设定回答
	参数：--answers
	当sqlmap提出输入时，自动输入自己想要的回答
4. 发现SQL注入时发出蜂鸣声
	参数：--beep
5. 启发式检测WAF/IPS/IDS保护
	参数：--check-waf
	WAF/IPS/IDS保护可能会对sqlmap造成很大的困扰，如果怀疑目标有防护的话，可以使用此参数来测试，sqlmap将会使用一个不存在的参数来注入测试
6. 清理sqlmap注入产生的UDF(s)和表
	参数：--cleanup
7. 禁用彩色输出
	参数：--disable-coloring
8. 使用指定的Google结果页面
	参数：--gpage
	默认sqlmap使用前100个URL地址作为注入测试，结合此选项，可以指定页面的URL测试
9. 使用HTTP参数污染
	参数：-hpp
	HTTP参数污染可能会绕过WAF/IPS/IDS保护机制，这个对ASP/IIS与ASP.NET/IIS平台很有效
10. 测试WAF/IPS/IDS保护
	参数：--identify-waf
	sqlmap可以尝试找出WAF/IPS/IDS保护，方便用户做出绕过方式
11. 模仿智能手机
	参数：--mobile
12. 安全的删除output目录的文件
	参数：--purge-output
	删除文件而不被恢复
13. 启发式判断注入
	参数：--smart
	有时对目标非常多的URL进行测试，为节省时间，只对能够快速判断为注入的报错点进行注入
14. 选择测试的有效荷载/标题
	参数：--text-filter
	如果你想过滤测试的有效荷载/标题可以使用这个参数
15. 初级用户向导参数
	参数：--wizard
	面向初级用户的参数，可以一步一步教你如何输入针对目标注入
