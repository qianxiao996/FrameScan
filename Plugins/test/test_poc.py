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
    

