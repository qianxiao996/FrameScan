#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: discuz X3 focus.swf flashxss漏洞
referer: unknown
author: Lucifer
description: 文件中focus.swf存在flashxss。
'''
import sys
import urllib
import hashlib
import requests
import warnings
sys.path.append('../../')
from color import *

class discuz_focus_flashxss:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        flash_md5 = "c16a7c6143f098472e52dd13de85527f"
        payload = "/static/image/common/focus.swf"
        vulnurl = self.url + payload
        try:
            req = urllib.request.urlopen(vulnurl)
            data = req.read()
            md5_value = hashlib.md5(data).hexdigest()
            if md5_value in flash_md5:
                printGreen("[+]Success:存在discuz X3 focus.swf flashxss漏洞...(高危)\tpayload: "+vulnurl)
            else:
                printBlue("[-]Info:不存在discuz_focus_flashxss漏洞")

        except:
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = discuz_focus_flashxss(sys.argv[1])
    testVuln.run()