# FrameScan

## 工具简介

FrameScan是一款python3编写的简易的cms漏洞检测利用框架，支持漏洞检测与简单利用方式，支持大多数CMS，可以自定义CMS类型及自行编写POC。旨在帮助有安全经验的安全工程师对已知的应用快速发现漏洞。

## 支持平台

- Windows  
- Linux  
- MAC（请自测）

## 工具特点

- 单URL批量检测
- 单URL单漏洞检测
- 单URL指定CMS检测
- 多URL单漏洞检测
- 单URL单漏洞检测
- 单URL指定CMS检测
- 单URL 漏洞利用
- 多URL 漏洞利用

详细参数如下：

```

         _____                         ____
        |  ___| __ __ _ _ __ ___   ___/ ___|  ___ __ _ _ __
        | |_ | '__/ _` | '_ ` _ \ / _ \___ \ / __/ _` | '_ \
        |  _|| | | (_| | | | | | |  __/___) | (_| (_| | | | |
        |_|  |_|  \__,_|_| |_| |_|\___|____/ \___\__,_|_| |_|

    Options:                          Code by qianxiao996
    --------------------------------------------------------------
    All:
        -u          Target URL               目标URL
        -f          Load urls file           文件路径
        -m          mode:poc or exp          选择运行模式(默认POC)

    POC Mode:
        -n          Use poc name             使用单个漏洞检测POC
        -cms        Specify CMS              指定webapp or CMS类型

    EXP Mode:
        -v          Use exp name             指定漏洞EXP名称
        -cmd        RCE Command(whoami)      执行cmd命令(默认:whoami)
        -shell      Return webshell          反弹Webshell(127.0.0.1:8080)

    Search:
        -ls         List Specify CMS poc     查找关键词漏洞(匹配漏洞名称)
        -la         List CMS POC             列出指定CMS漏洞(匹配CMS)
        -l          List avalible pocs       列出所有POC

    Output:
        -txt        Save Result(txt)         输出扫描结果（txt）
        -html       Save Result(html)        输出扫描结果（html）

    Other:
        -r          Reload POC               重新加载POC
        -t          Threads                  指定线程数量，默认10
        -h          Get help                 帮助信息
        --timeout   Scan timeout time(10s)   请求超时时间(10s)

    Example:
        python3 FrameScan.py -u http://example.com -cms thinkphp
        python3 FrameScan.py -f url.txt -m exp -v CVE-2019-2729
        python3 FrameScan.py -u http://example.com:7001 -m exp -v CVE-2019-2729
        python3 FrameScan.py -f list.txt -txt results.txt
    --------------------------------------------------------------
    FrameScan  V1.6 20210521         Blog:blog.qianxiao996.cn
```


## 使用方法

下载项目

```python
git clone https://github.com/qianxiao996/FrameScan
```

安装依赖

```
python3 -m pip install requirements.txt
```

单URL批量检测

```
python3 FrameScan.py -u URL
```

单URL单漏洞检测（POC_NAME可以用 -l、-s、-la进行查询）

```
python3 FrameScan.py -u URL -n POC_NAME
```

单URL指定CMS检测

```
python3 FrameScan.py -u URL -cms CMS_NAME
```

多URL批量检测

```
python3 FrameScan.py -f 文件名
```

多URL单漏洞检测

```
python3 FrameScan.py -f 文件名  -n  POC_NAME
```

多URL指定CMS检测

```
python3 FrameScan.py -f 文件名  -cms  CMS_NAME
```

输出到TXT或者HTML文件

```
python3 FrameScan.py -u URL -txt   文件名
python3 FrameScan.py -u URL -html  文件名
```

单URL漏洞利用

```
python3 FrameScan.py -u URL -m exp -v exp_name 
python3 FrameScan.py -u URL -m exp -v exp_name -c whoami
python3 FrameScan.py -u URL -m exp -v exp_name -shell 127.0.0.1:8080  #127.0.0.1:8080为反弹shell的端口
```

多URL漏洞利用

```
python3 FrameScan.py -f 文件  -m exp -v exp_name 
python3 FrameScan.py -f 文件  -m exp -v exp_name -c whoami
python3 FrameScan.py -f 文件  -m exp -v exp_name -shell
```

## 插件模板

### python插件

插件命名格式为Plugins_插件名.py。请规范编写。脚本中为示例代码。插件模板与GUI统一，可以相互调用。

```python
# -*- coding: UTF-8 -*-
#!/usr/bin/python
import requests
def vuln_info():
    info={
        'vuln_name': 'POC测试漏洞',  #漏洞名称
        'vuln_referer':'http://baidu.com',  #漏洞来源
        'vuln_author':'qianxiao996',  #插件作者
        'cms_name':'test',#cms_name需要和上级目录保持一致。扫描器自动添加会调用。GUI版本不会调用
        'vuln_description':'''漏洞描述''',
        'vuln_identifier':'''漏洞编号。''',
        'vuln_class':'漏洞分类',#如：信息泄漏、远程命令执行、任意文件上传、SQL注入、XML注入、任意文件读取、本地文件包含、认证绕过/未认证、弱口令、目录遍历、其他、反序列化漏洞、OGNL表达式注入、SSRF、后门、任意文件下载、鉴权绕过、暴力破解、命令注入、路径泄露、XSS、远程文件包含、CSRF、任意文件包含、代码注入、任意文件写入、密码硬编码、文件包含、任意用户注册、缓冲区溢出、用户枚举漏洞、任意文件删除、任意页面上传、管理权限等
        'vuln_solution':'''修复建议。''',
        'FofaQuery_type':'socket', #socket、http
        'FofaQuery_link':'/', #此处的路径会加在url拼接访问，进行FofaQuery的条件匹配 此处为all为全部页面都检测
        'FofaQuery_rule':'title="百度"',#header="JSESSIONID" || body="Struts Problem Report" || body="There is no Action mapped for namespace" || body="No result defined for action and result input" || header="Servlet" || header="JBoss",port="60001"
        #header', 'body', 'title', 'banner','port','banner','service','protocol','server'
        'ispoc':1, #是否有poc  1为有 0为无
        'isexp':1  #是否有exp   1为有 0为无
    }
    return info
# url：url  hostname：主机地址  port：端口  scheme：服务  heads：http自定义头信息
def do_poc(url,hostname,port,scheme,heads={}):
    try:
    # 返回参数
    #Result返回是否存在，
    #Result_Info为返回的信息，可以为Paylaod 
    #Debug debug信息 默认不会显示，勾选显示调试信息会输出此结果
    #Error_Info无论何时都会输出
        result = {"Result":True,"Result_Info":"payload","Debug_Info":"","Error_Info":""}
        result['Result_Info']= 'payload'
        result['Debug_Info']  = 'ddd'
        result['Error_Info'] = "dsaaaaaaaa"
    except Exception as e:
        result['Error_Info'] = str(e)+str(e.__traceback__.tb_lineno)+'行'
    return result
    
    # {
    #     "type":"cmd",  #cmd,shell,uploadfile
    #     "command":"whoami",  #cmd命令
    #     "reverse_ip":"127.0.0.1", #反弹shell的ip
    #     "reverse_port":"8888", #反弹shell的端口
    #     "filename":"conf.php", #写入文件的名字
    #     "filename_contents":"shell内容", #shell文件内容
    # }
# url:url   hostname：主机地址  port：端口  scheme：服务  heads:自定义请求头 
def do_exp(url,hostname,port,scheme,heads={},exp_data={}):
    try:
    # 返回参数
    #Result返回是否成功，
    #Result_Info为返回的信息，可以为Paylaod 
    #Debug debug信息 默认不会显示，勾选显示调试信息会输出此结果
    #Error_Info无论何时都会输出
        result = {"Result":False,"Result_Info":"payload","Debug_Info":"","Error_Info":""}
        #命令执行
        if exp_data['type']=='cmd':
            result['Result'] = True
            result['Result_Info'] = "root"
        #反弹shell    
        if exp_data['type']=='shell':
            result['Result'] = True
            result['Result_Info'] = "反弹成功"
        #上传文件    
        if exp_data['type']=='uploadfile':
            result['Result'] = True
            result['Result_Info'] = "上传成功"

        # 
        result['Debug_Info'] = "1"
    except Exception as e:
        result['Error_Info'] = str(e)+str(e.__traceback__.tb_lineno)+'行'
    return result




if __name__== '__main__':
    url='http://127.0.0.1/'
    # aa= do_exp(url,'','','','',exp_data)
    # print(aa)
    aa = do_poc(args.url,'','','',heads={})
    print(aa)

```

### Yaml插件

请参考[FrameScan-Yaml插件文档](https://github.com/qianxiao996/FrameScan-Yaml/)

## 警告！
**请勿用于非法用途！否则自行承担一切后果**

