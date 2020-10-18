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
 