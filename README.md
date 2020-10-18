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
        -a          Specify CMS              指定webapp or CMS类型

    EXP Mode:
        -v          Use exp name             指定漏洞EXP名称
        -c          RCE Command(whoami)      执行cmd命令(whoami)
        -shell      Write webshell           写入Webshell

    Search:
        -s          Search poc keywords      查找关键词漏洞
        -la         List CMS POC             列出指定CMS漏洞
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
        python3 FrameScan.py -u http://example.com -a thinkphp
        python3 FrameScan.py -u http://example.com:7001 -m exp -v CVE-2019-2729
        python3 FrameScan.py -f list.txt -txt results.txt
    --------------------------------------------------------------
    FrameScan  V1.5 20201018         Blog:blog.qianxiao996.cn
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
python3 FrameScan.py -u URL -a POC_METHOS
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
python3 FrameScan.py -f 文件名  -a  CMS类型
```

输出到TXT或者HTML文件

```
python3 FrameScan.py -u URL -txt   文件名
python3 FrameScan.py -u URL -html  文件名
```

单URL漏洞利用

```
python3 FrameScan.py -u URL -v exp_name 
python3 FrameScan.py -u URL -v exp_name -c whoami
python3 FrameScan.py -u URL -v exp_name -shell
```

多URL漏洞利用

```
python3 FrameScan.py -f 文件 -v exp_name 
python3 FrameScan.py -f 文件 -v exp_name -c whoami
python3 FrameScan.py -f 文件 -v exp_name -shell
```

## 插件POC模板

代码中采用自定义彩色输出，请尽量规范编写。脚本中为示例代码。

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
from urllib.parse import urlparse

def vuln_info():
    info={
        'name': 'POC测试漏洞',
        'referer':'http://baidu.com',
        'author':'qianxiao996',
        'description':'''百度测试。'''

    }
    return info
def run(url,timeout):
    try:
        return_list = ['不存在','Payload']
        return_list[0] = '存在'
        padload= 'payload'
        return return_list
    except Exception as e :
        return ['错误',str(e)]
```

## Exp模板

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import json
import requests
import warnings

def vuln_info():
    info={
        'name': 'POC测试漏洞',
        'referer':'http://baidu.com',
        'author':'qianxiao996',
        'description':'''expddddd'''

    }
    return info

def run(url,type="cmd",cmd='whoami',timeout=10):
    # print(type)
    #命令执行
    if type=='cmd':
        return "root"

    #写入shell
    if type=='shell':
        return "shheee"
```

欢迎投递POC

邮箱地址：qianxiao996@126.com

## 警告！
**请勿用于非法用途！否则自行承担一切后果**
