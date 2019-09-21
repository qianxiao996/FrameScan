#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: phpstudy探针
referer: unknown
author: Lucifer
description: phpstudy默认存在探针l.php,泄露敏感信息。
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *

class phpstudy_probe:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/l.php"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"phpStudy" in req.text and r"php_version" in req.text:
                printGreen("[+]Success:存在phpstudy探针...(信息)\tpayload: "+vulnurl)
            else:
                printBlue("[-]Info:不存在phpstudy_probe漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = phpstudy_probe(sys.argv[1])
    testVuln.run()