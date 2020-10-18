#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Author: qianxiao996
#Blog:blog.qianxiao996.cn
#date:  2019-9-21
#别问我为什么不用命令行解释模块，因为丑。
import importlib
import sys,os,re
from prettytable import PrettyTable
from color import *
import sqlite3,requests,threading
import queue,frozen_dir
SETUP_DIR = frozen_dir.app_path()
sys.path.append(SETUP_DIR)
vuln_data=[]
# 禁用安全警告
requests.packages.urllib3.disable_warnings()
DB_NAME = "FrameScan_DB.db"  #存储的数据库名
VERSION = "V1.5 20201018"
FLAGLET = ("""
        _____                         ____                  
        |  ___| __ __ _ _ __ ___   ___/ ___|  ___ __ _ _ __  
        | |_ | '__/ _` | '_ ` _ \ / _ \___ \ / __/ _` | '_ \ 
        |  _|| | | (_| | | | | | |  __/___) | (_| (_| | | | |
        |_|  |_|  \__,_|_| |_| |_|\___|____/ \___\__,_|_| |_|
""")
usage = FLAGLET + '''
    Options:                          Code by qianxiao996 
    --------------------------------------------------------------
    All:
        -u          Target URL               目标URL
        -f          Load urls file           文件路径
        -m          mode:poc or exp          选择运行模式(默认POC)
        
    POC Mode:
        -n          Use poc name             使用单个漏洞检测POC
        -a          Specify CMS              指定webapp or CMS类型

    EXP Mode:
        -v          Use exp name             指定漏洞EXP名称
        -c          RCE Command(whoami)      执行cmd命令(whoami)
        -shell      Write webshell           写入Webshell

    Search:
        -s          Search poc keywords      查找关键词漏洞
        -la         List CMS POC             列出指定CMS漏洞
        -l          List avalible pocs       列出所有POC

    Output:
        -txt        Save Result(txt)         输出扫描结果（txt）
        -html       Save Result(html)        输出扫描结果（html）
        
    Other: 
        -r          Reload POC               重新加载POC
        -t          Threads                  指定线程数量，默认10
        -h          Get help                 帮助信息
        --timeout   Scan timeout time(10s)   请求超时时间(10s)

    Example:
        python3 FrameScan.py -u http://example.com -a thinkphp
        python3 FrameScan.py -u http://example.com:7001 -m exp -v CVE-2019-2729
        python3 FrameScan.py -f list.txt -txt results.txt
    --------------------------------------------------------------
    FrameScan  %s         Blog:blog.qianxiao996.cn
    ''' % VERSION

color = Colored()
#得到输入的参数
def getparameter():
    # 获取命令行所有参数
    Command = sys.argv
    # print(Command)
    Command_dict = {}
    #判断互斥参数:
    if "-u" in Command and  "-f" in Command :
        print(color.blue(usage))
        sys.exit(1)
    elif "-n" in Command and  "-a" in Command :
        print(color.blue(usage))
        sys.exit(1)
    elif "-n" in Command and  "-a" in Command :
        print(color.blue(usage))
        sys.exit(1)
    elif "-c" in Command and  "-shell" in Command :
        print(color.blue(usage))
        sys.exit(1)
    elif "-txt" in Command and  "-html" in Command :
        print(color.blue(usage))
        sys.exit(1)
    #帮助信息
    if  len(sys.argv) ==1 or "-h" in Command:
        # 输出帮助信息
        print(color.blue(usage))
        sys.exit(1)
    elif  len(sys.argv) ==1 or "-l" in Command:
        # 列出所有漏洞
        list_all_vuln()
        sys.exit(1)
    try:
        #列表每次取两个元素
        # print(len(Command))
        if "-shell" in Command:
            Command_dict['-shell'] = ""
            Command.remove("-shell")
        for i in range(1, len(Command), 2):
            # print(Command[i])
            Command_dict[Command[i]] = Command[i + 1]
            #转化为字典
        return(Command_dict)
    except:
        print(color.blue(FLAGLET))
        print(color.red("[E]Error:参数值设置错误！"))
        sys.exit(1)
    #如果参数字典为空  输出帮助
    if not Command_dict:
        print(color.blue(usage))
        sys.exit(1)
    #否则返回参数
    else:
        return Command_dict
#重新加载POC
def Reload_POC():
    print(color.blue(FLAGLET))
    #删除数据库，重新建立
    print(color.blue("[*]Info:正在删除数据库..."))
    try:
        if os.path.exists(DB_NAME):
            os.remove(DB_NAME)
            print(color.green("[+]Success:删除数据库完成！"))
        else:
            print(color.blue("[*]Info:文件不存在，无需删除！"))
    except:
        print(color.red("[E]Error:数据库文件删除失败，请手动删除！"))
        sys.exit(1)
    print(color.blue("[*]Info:正在创建数据库..."))
    try:
        # 连接数据库。如果数据库不存在的话，将会自动创建一个 数据库
        conn = sqlite3.connect(DB_NAME)
        # 创建一个游标 curson
        cursor = conn.cursor()
        # 执行一条语句,创建 user表 如不存在创建
        sql = "create table IF NOT EXISTS POC (id integer primary key autoincrement , cmsname varchar(30),vulnname  varchar(30),pocfilename varchar(50),expfilename varchar(50),pocreferer varchar(50),expreferer varchar(50),pocdescription varchar(200),expdescription varchar(9000))"
        cursor.execute(sql)
        print(color.green("[+]Success:创建数据库完成!"))
    except:
        print(color.red("[E]Error:数据框创建失败！"))
        sys.exit(1)
    print(color.blue("[*]Info:正在写入数据..."))
    # cms_path='Plugins/'
    try:
        plugins_path = "Plugins/"
        plugins_path = plugins_path.replace("\\", "/")
        for cms_name in os.listdir(plugins_path):  # 遍历目录名
            cms_path = os.path.join(plugins_path, cms_name).replace("\\", "/")
            for poc_file_dir, poc_dirs_list, poc_file_name_list in os.walk(cms_path):  # 遍历poc文件，得到方法名称
                # print(path,dirs,poc_methos_list)
                # print(poc_file_name_list)
                for poc_file_name in poc_file_name_list:
                    poc_name_path = poc_file_dir+ "\\" + poc_file_name
                    poc_name_path = poc_name_path.replace("\\", "/")
                    # 判断是py文件在打开  文件存在
                    if os.path.isfile(poc_name_path) and poc_file_name.endswith('.py') and poc_file_name[-7:]=='_poc.py':
                        # print(poc_name_path)
                        try:
                            nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(poc_name_path[:-3], poc_name_path).load_module()
                            vuln_info = nnnnnnnnnnnn1.vuln_info()
                            # 将数据插入到表中
                            cursor.execute(
                                'insert into POC (cmsname, vulnname,pocfilename,expfilename,pocreferer,expreferer,pocdescription,expdescription) values ("%s","%s","%s","%s","%s","%s","%s","%s")' % (
                                    cms_name, vuln_info['name'], poc_file_name, 'None', vuln_info['referer'],'None',
                                    vuln_info['description'],''))
                        except Exception as  e:
                            print(color.red(
                                "Error:%s脚本执行错误！<br>[Exception]:<br>%s</p>\n" % (
                                    poc_file_name, e)))
                            continue
                conn.commit()  # 提交
                for poc_file_name in poc_file_name_list:
                    poc_name_path = poc_file_dir + "\\" + poc_file_name
                    poc_name_path = poc_name_path.replace("\\", "/")
                    if os.path.isfile(poc_name_path) and poc_file_name.endswith(
                            '.py') and poc_file_name[-7:] == '_exp.py':
                        try:
                            nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(poc_name_path[:-3],poc_name_path).load_module()
                            exp_info = nnnnnnnnnnnn1.vuln_info()
                            # print(exp_info)
                            # 将数据插入到表中
                            sql = "select *  from  POC where vulnname='%s'"%(exp_info['name'])
                            # print(sql)
                            # 判断是否已有poc 有则修改 无则添加
                            exp_result = sql_search(sql)
                            if exp_result:
                                cursor.execute("UPDATE POC SET expfilename='%s' ,expreferer='%s',expdescription='%s' where vulnname='%s'"%(poc_file_name,exp_info['referer'],exp_info['description'],exp_info['name']))

                            else:
                                cursor.execute(
                                    'insert into POC (cmsname, vulnname,pocfilename,expfilename,pocreferer,expreferer,pocdescription,expdescription) values ("%s","%s","%s","%s","%s","%s","%s","%s")' % (
                                        cms_name, exp_info['name'], 'None',poc_file_name, 'None',exp_info['referer'],
                                        '',exp_info['description']))
                        except Exception as  e:
                            print(color.red(
                                "Error:%s脚本执行错误！<br>[Exception]:<br>%s</p>" % (
                                    poc_file_name, e)))
                            continue

                    else:
                        pass
                conn.commit()  # 提交

        # print(result)
        cursor.execute("select count(*) from POC where pocfilename !=''")
        poc_num = cursor.fetchall()
        cursor.execute("select count(expfilename) from POC where expfilename !=''")
        exp_num = cursor.fetchall()
        conn.close()
        print(color.green("[+]Success:数据库更新完成！"))
        print(color.yellow( "[+]数据更新完成！\n   POC数量：%s\n   EXP数量：%s" % (poc_num[0][0],exp_num[0][0])))
        sys.exit(1)
        # reboot = sys.executable
        # os.execl(reboot, reboot, *sys.argv)
    except Exception as e:
        print(color.red(
            "Error:数据写入失败！\n[Exception]:\n%s</p>" % (e)))
        sys.exit(1)

#列出所有的漏洞
def list_all_vuln():
    conn2 = sqlite3.connect(DB_NAME)
    # 创建一个游标 curson
    cursor = conn2.cursor()
    #查询所有数据
    sql = "SELECT cmsname,vulnname,pocfilename,expfilename,pocdescription from POC"
    print(color.green(("[*]Info:正在查询数据...")))
    cursor.execute(sql)
    values = cursor.fetchall()
    # print(values)
    if values == []:
        print(color.yellow("[-]Success:查询完成，数据查询为空。"))
    else:
        print(color.yellow("[-]Success:数据查询成功！"))
        table = PrettyTable([color.ccyan('CMS_NAME'),color.ccyan('VULN_NAME'),color.ccyan('POC_FILE'),color.ccyan('EXP_FILE'),color.ccyan("Vuln_Descriptio")])

        for single in values:
            table.add_row(list(single))
        print(table)
        conn2.close()

#列出指定cms的数据
def list_cms_vuln():
    if sys.argv[1] == "-la" or sys.argv[1] == "-s":
        try:
            # -la 通过cms名称来查询POC
            if sys.argv[1] == "-la":
                sql = "select cmsname,vulnname,pocfilename,expfilename,pocdescription  from POC where cmsname like '%%%s%%'"%sys.argv[2]
            # -s 通过POC名称来查询poc
            elif sys.argv[1] == "-s":
                sql = "SELECT cmsname,vulnname,pocfilename,expfilename,pocdescription  from POC where vulnname like '%%%s%%'" % sys.argv[2]
            # print(color.red(sql)
        except:
            sys.exit(1)
        conn2 = sqlite3.connect(DB_NAME)
        # 创建一个游标 curson
        cursor = conn2.cursor()
        print(color.green(("[*]Info:正在查询数据...")))
        cursor.execute(sql)
        values = cursor.fetchall()
        # print(values)
        if values == []:
            print(color.yellow("[-]Success:查询完成，数据查询为空。"))
        else:
            print(color.yellow("[-]Success:数据查询成功！"))
            table = PrettyTable([color.ccyan('CMS_NAME'),color.ccyan('VULN_NAME'),color.ccyan('POC_FILE'),color.ccyan('EXP_FILE'),color.ccyan("Vuln_Descriptio")])
            for single in values:
                table.add_row(list(single))
            print(table)
            conn2.close()

    else:
        print(color.blue(FLAGLET))
def sql_search(sql,type='list'):
    if type=='dict':
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = dict_factory
    else:
        conn = sqlite3.connect(DB_NAME)
    # 创建一个游标 curson
    cursor = conn.cursor()
    # self.Ui.textEdit_log.append("[%s]Info:正在查询数据..."%(time.strftime('%H:%M:%S', time.localtime(time.time()))))
    # 列出所有数据
    cursor.execute(sql)
    values = cursor.fetchall()
    return  values
#sql查询返回字典

#sql查询通用函数
def check_sql(sql):
    conn = sqlite3.connect(DB_NAME)
    # 创建一个游标 curson
    cursor = conn.cursor()
    # 执行一条语句,创建 user表 如不存在创建
    cursor.execute(sql)
    values = cursor.fetchall()
    return values

def check_vuln(url_list,poc_list,threadnum):

    # print(save_file,threadnum)
    # print(save_file)
    threads = []
    portQueue = queue.Queue()  # 待检测端口队列，会在《Python常用操作》一文中更新用法

    if savefiletype == 'html':
        save = open(savefilename, 'w', encoding='gbk')
        save.write('''
<html>
<head>
    <title>FrameScan Sacn Result</title>
    <style type="text/css">
        /*表格样式*/			
        table {
            table-layout: fixed;
            word-break:break-all;
            width: 100%;
            background: #ccc;
            margin: 10px auto;
            border-collapse: collapse;
        }				
        th,td {
            text-align: center;
            border: 1px solid #ccc;
        }		
        th {
            background: #eee;
            font-weight: normal;
        }		
        tr {
            background: #fff;
        }		
        tr:hover {
            background: #cc0;
        }		
        td a {
            color: #06f;
            text-decoration: none;
        }		
        td a:hover {
            color: #06f;
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <h2 align="center">FrameScan Sacn Result</h2>
    <table align="center">
    <thead>
        <tr>
            <th>URL地址</th>
            <th>漏洞名称</th>
            <th>漏洞描述</th>
            <th>漏洞链接</th>
            <th>POC脚本位置</th>
            <th width=20%>Payload</th>
            <th>扫描结果</th>
        </tr>
    </thead>
    <tbody>''')
        save.close()
  
    print(color.blue(FLAGLET))
    print(color.blue("[-]Start:开始执行"))
    # print(savefiletype)
    print(color.blue("[*]Info:共加载%s个URL,%s个POC,线程%s,超时:%ss"%(len(url_list),len(poc_list),str(threadnum),timeout)))
    print(color.yellow("[*]Info:正在创建队列..."))
    for url in url_list:
        for all in poc_list:
            # print(all)
            poc_filename = 'Plugins/' + all[1] + '/' + all[3]
            # print(filename)
            poc_methods = 'Plugins.' + all[1]+ '.' + all[3][:-3]
            portQueue.put(url+ '$$$' + poc_filename + '$$$' + poc_methods+'$$$'+all[2]+'$$$'+all[5]+'$$$'+all[7])
            # print(url,methods[0])
    if threadnum>portQueue.qsize():
        threadnum = portQueue.qsize()
    print(color.yellow("[-]Start:开始扫描..."))
    print(color.green((
            "-"*80)))
    for i in range(threadnum):
        thread = threading.Thread(target=vuln_start, args=(portQueue,))
        # thread.setDaemon(True)  # 设置为后台线程，这里默认是False，设置为True之后则主线程不用等待子线程
        threads.append(thread)
        thread.start()
    for t in threads:
        t.join()
    print(color.green((
            "-"*80)))
    print(color.yellow("[-]End:扫描结束！"))
    if len(vuln_data) != 0:
        print(color.yellow('[-]Success:共扫描到%s个漏洞！'%len(vuln_data)))
        print(color.green('\n[-]漏洞详情'))
        print(color.green(
                "-"*50))
        for i in vuln_data:
            print(color.green(i.strip()+'\n'))

    else:
        print(color.yellow('[-]End:未发现漏洞！'))
    sys.exit(1)

def exp_start(url_list,poc,timeout,type,cmd):
    print(color.blue(FLAGLET))
    print(color.yellow("POC_Name:%s\nType:%s\nData:%s\nTimeout:%s"%(poc[2],type,cmd,timeout)))
    for url in url_list:
        print(color.cyan("URL:%s"%url))
        poc_filename = "Plugins/"+poc[1]+"/"+poc[4]
        poc_methods = "Plugins."+poc[1]+"."+poc[4][:-3]
        # print(poc_filename,poc_methods)
        nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(poc_methods, poc_filename).load_module()
        # result = nnnnnnnnnnnn1.run(url)
        return_data = nnnnnnnnnnnn1.run(url,type,cmd,timeout)
        print(color.green("EXP_Result:\n%s\n"%(return_data)))
    return
def vuln_start(portQueue):
    while 1:
        if portQueue.empty():  # 队列空就结束
            break
        all = portQueue.get()  # 从队列中取出
        # print(all)
        url = all.split('$$$')[0]
        poc_filename= all.split('$$$')[1]
        poc_methods = all.split('$$$')[2]
        poc_name = all.split('$$$')[3]
        poc_referer = all.split('$$$')[4]
        poc_description = all.split('$$$')[5]
        
        try:
            nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(poc_methods, poc_filename).load_module()
            # result = nnnnnnnnnnnn1.run(url)
            return_data = nnnnnnnnnnnn1.run(url,timeout)
            # print (return_data)
            if return_data[0] == '存在' and return_data[0] != '':
                # return_data.append(url)
                vuln_info = "[*]URL:%s\n[*]漏洞名称:%s\n[*]测试结果:%s\n[*]漏洞描述:%s\n[*]漏洞来源:%s\n[*]插件路径:%s\n[*]Payload:\n%s" % (
                url.strip(),poc_name, return_data[0],poc_description.strip(),poc_referer.strip(),poc_filename,return_data[1])
                vuln_data.append(vuln_info)
                output([url.strip(),poc_name, return_data[0],poc_description.strip(),poc_referer.strip(),poc_filename,return_data[1]])
                print(color.green("[*]Info:%s----%s----%s----%s。" % (url, poc_name, return_data[0],return_data[1])))
            elif return_data[0] == '错误' and return_data[0] != '':
                info_error =  "[*]Error:%s----%s----%s扫描出现错误。" % (url, poc_name,poc_filename)
                print(color.red(info_error
                   ))
                print(color.red("[*]详细信息:\n"+return_data[1]+"\n"
                   ))
            elif return_data[0] == '不存在' and return_data[0] != '':
                print(color.blue("[*]Info:%s----%s----%s。" % (url, poc_name, return_data[0])))
            else:
                print(color.cyan("[*]Info:%s----%s----%s。" % (url, poc_name, return_data[0])))
        except Exception as e:
            # print(str(e))
            print(color.red("[E]Error:%s脚本执行错误!"%(poc_filename)))
            print(color.red("[E]Error:%s"%e))
def get_url_list(path):
    all_list =[]
    if os.path.exists(path):
        try:
            file = open(path,'r',encoding= 'utf-8')
            for line in file:
                if 'http://' in line or 'https://' in line:
                    all_list.append(line)
            file.close()
            all_list2 = []
            for i in all_list:
                if i not in all_list2:
                    all_list2.append(i.replace('\n','').strip())
            return list(filter(None, all_list2))  # 去除 none 和 空字符
        except:
            print(color.red('Error:文件读取错误！'))
    else:
        all_list = path.split()
        return list(filter(None, all_list))  # 去除 none 和 空字符
def Judgement_parameter(Command_dict):
    # print(222)
    if "-la" in Command_dict or "-s" in Command_dict  :
        #-s 查询关键词的漏洞 -la # 列出某个cms的漏洞
        if len(sys.argv) <=2:
            print(color.blue(usage))
            sys.exit(1)
        else:
            list_cms_vuln()
            sys.exit(1)
    if "-u" in Command_dict or '-f' in Command_dict:
        if "-u" in Command_dict:
            url_list = get_url_list(Command_dict['-u'])
        elif '-f' in Command_dict:
            if not os.path.isfile(Command_dict['-f']):
                print(color.blue(FLAGLET))
                print(color.red("[E]Error:文件%s不存在！" % Command_dict['-f']))
                sys.exit(1)
            url_list = get_url_list(Command_dict['-f'])
        if len(url_list)==0:
            print(color.blue(FLAGLET))
            print(color.red('未获取到URL地址!'))
            sys.exit()

        global savefiletype
        global savefilename          
        global timeout
        if '-html' in Command_dict  :
            savefiletype = 'html'
            savefilename = Command_dict['-html']
        elif '-txt' in Command_dict:
            savefiletype= 'txt'
            savefilename = Command_dict['-txt']
        else:
            savefiletype= ''
            savefilename=''
        if '-timeout' in Command_dict:
            timeout = int(Command_dict['-timeout'])
        else:
            timeout=10

        #漏洞利用 
        if "-m" in Command_dict and Command_dict['-m'] == "exp":
            if "-v" in Command_dict:
                sql_data = "select * from POC where vulnname='%s' and expfilename!='None'" % Command_dict['-v']
            else:
                print(color.red('请指定一个EXP!'))
                sys.exit()
            if sql_data != "":
                exp_list = check_sql(sql_data)
                if len(exp_list)==0:
                    print(color.blue(FLAGLET))
                    print(color.red("[E]Error:未查询到EXP！"))
                    sys.exit(1)
            if "-c" in Command_dict:
                cmd =  Command_dict['-c']
                exp_start(url_list,exp_list[0],timeout,"cmd",cmd)
            elif "-shell" in Command_dict:
                cmd =["confog.php","996"]
                exp_start(url_list,exp_list[0],timeout,"shell",cmd)
            else:
                cmd="whoami"
                exp_start(url_list,exp_list[0],timeout,"cmd",cmd)
        
        #漏洞扫描
        else:
            sql_data = ""
            if '-t' in Command_dict:
                threadnum = int(Command_dict['-t'])
            else:
                threadnum = 10
            if "-n" in Command_dict:
                sql_data = "select * from POC where vulnname='%s'" % Command_dict['-n']
            elif "-a" in Command_dict:
                sql_data = "select * from POC where cmsname='%s'" % Command_dict['-a']
            else:
                # -u参数
                sql_data = "select * from POC"
            if sql_data != "":
                poc_list = check_sql(sql_data)
                if len(poc_list)==0:
                    print(color.blue(FLAGLET))
                    print(color.red("[E]Error:未查询到POC！"))
                    sys.exit(1)
                check_vuln(url_list, poc_list,threadnum)
            else:
                print(color.blue(FLAGLET))
                sys.exit(1)
    else:
        print(color.blue(FLAGLET))
        print(color.red("Error:请指定URL地址!"))

def output(vuln_info):
    #保存到文件
    if savefiletype == 'txt':
        vuln_info="\nURL:"+vuln_info[0]+"\n漏洞名称:"+vuln_info[1]+"\n测试结果:"+vuln_info[2]+"\n漏洞描述:"+vuln_info[3]+"\n漏洞来源:"+vuln_info[4]+"\n插件路径:"+vuln_info[5]+"\nPayload:"+vuln_info[6]
        print(vuln_info)
        save = open(savefilename, 'a', encoding='utf-8')
        save.write(vuln_info)
        save.close()
    if savefiletype == 'html':
        save = open(savefilename, 'a', encoding='gbk')
        save.write('''  
        <tr>
        <td>%s</td>
        <td>%s</td>
        <td>%s</td>
        <td>%s</td>
        <td>%s</td>
        <td>%s</td>
        <td>%s</td>
        </tr>\n''' % (vuln_info[0], vuln_info[1],vuln_info[3],vuln_info[4],vuln_info[5],vuln_info[6],vuln_info[2]))
        save.close()
if __name__ == '__main__':
    # 需要python3 版本
    if sys.version_info < (3, 0):
        sys.stdout.write("Sorry, FrameScan requires Python 3.x\n")
        sys.exit(1)
    #获取返回的参数和值
    if len(sys.argv)==2 and sys.argv[1]=="-r":
        Reload_POC()
        sys.exit(1)
    if not os.path.isfile(DB_NAME):
        print(color.blue(FLAGLET))
        print(color.red("[E]Error:数据库文件不存在，请执行-r重新加载数据文件！"))
        sys.exit(1)
    Command_dict=getparameter()
    #测试输出
    # for key in Command_dict:
    #     print(key + ':' + Command_dict[key])
    Judgement_parameter(Command_dict)

