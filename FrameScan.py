#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Author: qianxiao996
#Blog:blog.qianxiao996.cn
#date:  2019-9-21
#别问我为什么不用命令行解释模块，因为丑。
import sys,os,re
from color import *
import sqlite3,requests

# 禁用安全警告
requests.packages.urllib3.disable_warnings()
DB_NAME = "POC_DB.db"  #存储的数据库名
VERSION = "V1.0"
FLAGLET = ("""
     _____                         ____                  
    |  ___| __ __ _ _ __ ___   ___/ ___|  ___ __ _ _ __  
    | |_ | '__/ _` | '_ ` _ \ / _ \___ \ / __/ _` | '_ \ 
    |  _|| | | (_| | | | | | |  __/___) | (_| (_| | | | |
    |_|  |_|  \__,_|_| |_| |_|\___|____/ \___\__,_|_| |_|
""")
usage = FLAGLET + '''
    Options:                          Code by qianxiao996 
    -----------------------------------------------------
    -u          Url                      URL地址
    -f          Load urls file           文件路径
    -m          Use poc module           使用单个POC
    -c          Specify CMS              指定CMS类型
    -s          Search poc keywords      查找关键词漏洞
    -lc         List CMS POC             列出指定CMS漏洞
    -l          List avalible pocs       列出所有POC
    -r          Reload POC               重新加载POC
    -h          Get help                 帮助信息
    -----------------------------------------------------
    FrameScan  %s              Blog:blog.qianxiao996.cn
    ''' % VERSION
#得到输入的参数
def getparameter():
    # 获取命令行所有参数
    Command = sys.argv
    Command_dict = {}
    for i in range(1, len(Command)):
        # 指定爆破的URL
        try:
            if Command[i] == "-u":
                if Command[i + 1][0:7] != 'http://' and Command[i + 1][0:8] != "https://":
                    printBlue(FLAGLET)
                    printRed("[E]Error:URL格式错误！\n[E]请添加http://或者https://")
                    os._exit()
                else:
                    Command_dict['URL'] = Command[i + 1]
            # 指定爆破的文件名
            if Command[i] == "-f":
                Command_dict['file'] = Command[i + 1]
            #print(Command[i])
            if  len(sys.argv) >=3:
                # 指定模块名爆破
                if Command[i] == "-m" :
                    Command_dict['module'] = Command[i + 1]
                # 指定CMS信息
                if Command[i] == "-c"  :
                    Command_dict['CMS'] = Command[i + 1]
        except:
            printBlue(FLAGLET)
            printRed("[E]Error:参数值设置错误！")
            sys.exit(1)
        if  len(sys.argv) <=3:
            #  -s 查询关键词的漏洞 -lc # 列出某个cms的漏洞
            if Command[i] == "-s" or Command[i] == "-lc":
                if len(sys.argv)==2:
                    printBlue(usage)
                else:
                    list_cms_poc()
                    sys.exit(1)
            #列出所有的漏洞
            if Command[i] == "-l":
                list_cms_poc()
                sys.exit(1)
        if  len(sys.argv) ==2 and Command[i] == "-h":
            # 输出帮助信息
            printBlue(usage)
            sys.exit(1)
    # 如果参数字典为空  输出帮助
    if not Command_dict:
        printBlue(usage)
        sys.exit(1)
    # 否则返回参数
    else:
        return Command_dict
#重新加载POC
def Reload_POC():
    printBlue(FLAGLET)
    #删除数据库，重新建立
    printBlue("[*]Info:正在删除数据库...")
    try:
        os.remove(DB_NAME)
    except:
        printRed("[E]Error:数据库文件删除失败，请手动删除！")
        sys.exit(1)
    printGreen("[+]Success:删除数据库完成！")
    printBlue("[*]Info:正在创建数据库...")
    try:
        # 连接数据库。如果数据库不存在的话，将会自动创建一个 数据库
        conn = sqlite3.connect(DB_NAME)
        # 创建一个游标 curson
        cursor = conn.cursor()
        # 执行一条语句,创建 user表 如不存在创建
        sql = "create table IF NOT EXISTS POC (id integer primary key autoincrement , cmsname varchar(30),pocmethods varchar(40),pocname  varchar(30),pocreferer varchar(50),pocdescription varchar(200))"
        cursor.execute(sql)
        printGreen("[+]Success:创建数据库完成!")
    except:
        printRed("[E]Error:数据框创建失败！")
        sys.exit(1)
    printBlue("[*]Info:正在写入数据...")
    try:
        cms_path=sys.path[0]+ "\cms"
        cms_path = cms_path.replace("\\","/")

        #创建一个文件来存储引入的模块
        cmsmain_file = open(cms_path+"/cmsmain.py","w",encoding="utf-8")
    except:
        printRed("[E]Error:打开cmsmain.py文件失败！")
        sys.exit(1)
    try:
        cmsmain_file.write(r"#!/usr/bin/env python"+'\n'
                r"# -*- coding: utf-8 -*-"+'\n'
                r"'''"+'\n'
                r"name: cms漏洞库"+'\n'
                r"referer: unknow"+'\n'
                r"author: qianxiao996"+'\n'
                r"description: 包含所有cms漏洞类型，封装成一个模块"+'\n'
                r"此文件禁止修改"+'\n'
                r"'''"+'\n')
        for cms_name in os.listdir(cms_path): #遍历目录名
            cmsmain_file.write("#" + cms_name + "\n")
            poc_path = os.path.join(cms_path,cms_name)
            for path, dirs, poc_methos_list in os.walk(poc_path):#遍历poc文件，得到方法名称
                for poc_file_name in poc_methos_list:
                    # printRed(poc_file_name[-3:])
                    # printBlue(poc_file_name)
                    poc_name_path = cms_path+"\\"+cms_name+"\\"+poc_file_name
                    poc_name_path = poc_name_path.replace("\\", "/")
                    #print(poc_name_path)
                    #判断是py文件在打开  文件存在
                    if os.path.isfile(poc_name_path) and poc_file_name.endswith('.py') :
                        #判断py文件不包含.
                        if '.' not in poc_file_name.replace(".py",""):
                            # print(poc_name_path)
                            f= open(poc_name_path,"r",encoding="utf-8")
                            #获取poc的中文名称
                            # printSkyBlue(cms_name)
                            poc_methos = ""  # 定义局部变量 存放poc方法
                            poc_name = ""  # 定义局部变量 存放poc名称
                            poc_referer=""
                            if cms_name[0:2]!="__":#判断文件夹的前两位不是下划线
                                for name in f.readlines():
                                    # print(name)
                                    #得到中文poc_name
                                    if "name:"in name:
                                        poc_name = name.split(":")[1].replace(" ","")
                                        poc_name=poc_name.replace("\n","").replace("\r","").replace("\r\n","")
                                        # print(poc_name)
                                    #得到调用的poc_methos
                                    if "class " in name:
                                        # print(name)
                                        poc_methos = name.replace(":","").split(" ")[1].replace("\n","").replace("\r","").replace("\r\n","").replace("()","")
                                        # printBlue(poc_methos)
                                    #得到调用的poc_referer
                                    if "referer" in  name:
                                        poc_referer= name.replace(":","").split(" ")[1].replace("\n","").replace("\r","").replace("\r\n","")
                                        # printBlue(poc_referer)
                                #读取文件光标恢复到初始位置
                                f.seek(0)
                                condata = f.read() ##所有数据
                                # print(condata)
                                #匹配描述
                                comment= re.compile(r"description:(.*?)'''",re.DOTALL)
                                poc_description= str(comment.findall(condata)[0]).replace("\"","").replace(" ","").replace("\n","\n\t")
                                # print(poc_description)
                                # print(poc_name)
                                if poc_name !="" and poc_methos!="":
                                #将数据插入到表中
                                    cursor.execute('insert into POC (cmsname, pocname,pocmethods,pocreferer,pocdescription) values ("%s","%s","%s","%s","%s")'%(cms_name,poc_name,poc_methos,poc_referer,poc_description))
                                    data = "from cms." +cms_name+"."+ poc_file_name.replace(".py","")+ " import " + poc_methos+"\n"
                                    cmsmain_file.write(data)
                            f.close()
                        else:
                            printRed("[E]Error:%s文件加载失败，文件名中不允许包含英文符号点！"%(cms_name+"/"+poc_file_name))
                    else:
                        pass
            cmsmain_file.write("\n")
        conn.commit()#提交
        result = cursor.fetchall()
        if not len(result):
            cursor.execute("select count(*) from POC")
            values = cursor.fetchall()
            printGreen("[+]Success:数据库更新完成！")
            printYellow("[-]End:漏洞总数：%s条。"%values[0][0])

        else:
            printRed("[E]Error:数据库更新失败，原因:"+str(result))
        conn.close()
        cmsmain_file.close()
    except Exception as e:
        printRed("[E]Error:数据写入失败！\n Exception:%s"%e)
        sys.exit(1)
#列出指定cms的数据
def list_cms_poc():
    conn2 = sqlite3.connect(DB_NAME)
    # 创建一个游标 curson
    cursor = conn2.cursor()
    # print(sys.argv)
    if (len(sys.argv) <=3 )and (sys.argv[1] == "-lc" or sys.argv[1] == "-s"or sys.argv[1] == "-l"):
        try:
            # -lc 通过cms名称来查询POC
            # print(len(sys.argv))
            if sys.argv[1] == "-lc" and sys.argv[1] != "-s"and sys.argv[1] != "-l" :
                if len(sys.argv)<=2:
                    printRed("[E]Error 参数值不能为空")
                    sys.exit(1)
                else:
                    sql = "select * from POC where cmsname like '%%%s%%'"%sys.argv[2]
            # -s 通过POC名称来查询poc
            if sys.argv[1] == "-s" and sys.argv[1] != "-lc"and sys.argv[1] != "-l" :
                if len(sys.argv)<=2:
                    printRed("[E]Error 参数值不能为空")
                    sys.exit(1)
                if len(sys.argv) == 3:
                    sql = "SELECT * from POC where pocname like '%%%s%%'" % sys.argv[2]

                # printRed(sql)
            if sys.argv[1] == "-l" and sys.argv[1] != "-lc"and sys.argv[1] != "-s" :
                #根据iD查数据
                # print(int(sys.argv[2]))  isdigit()用于判断字符串是不是数字
                if len(sys.argv)==3 and sys.argv[2].isdigit():
                    search_id()
                    sys.exit(1)
                #列出所有数据
                if len(sys.argv)==2:
                    #查询所有数据
                    sql = "SELECT * from POC"
                else:
                    printBlue(FLAGLET)
                    printRed("[E]Error:请输入正确的ID!")
                    sys.exit(1)
        except:
            sys.exit(1)
        printGreen("[*]Info:正在查询数据...")
        cursor.execute(sql)
        values = cursor.fetchall()
        # print(values)
        if values == []:
            printYellow("[-]Success:查询完成，数据查询为空。")
        else:
            printYellow("[-]Success:数据查询成功！")
            printGreen("----------------------------------------------------------------------------------------------------------------------------------")
            print(" I D ".center(5), "|", "CMS_NAME".center(20), "|", "POC_METHOS".center(40), "|",   #居中显示
                  "POC_NAME".center(40))
            for single in values:
                print(""+str(single[0]).center(5),"|",str(single[1]).center(20),"|",str(single[2]).center(40),"|",str(single[3]).center(40))
           # printGreen_no(, str(single[1]),str(single[2]),str(single[3]))
            #printGreen_no("\n")
            printGreen("-----------------------------------------------------------------------------------------------------------------------------------")
            conn2.close()
        # except:
        #     printRed("[E]Error:数据查询错误，请重新加载数据库！")
    else:
        printBlue(FLAGLET)
        printRed("[E]Error：用户数据的参数数据为空,请输入CMS名称。")
#-l id调用的查询函数
def search_id():
    printGreen("[*]Info:正在查询数据...")
    conn2 = sqlite3.connect(DB_NAME)
    # 创建一个游标 curson
    cursor = conn2.cursor()
    sql = "SELECT * from POC where id ='%s'" % sys.argv[2]
    cursor.execute(sql)
    values = cursor.fetchall()
    if values == []:
        printYellow("[-]Success:查询完成，数据查询为空。")
        sys.exit(1)
    else:
        printYellow("[-]Success:数据查询成功！")
        printGreen("------------------------------------------------------------------------------------")
        print("ID".ljust(15)+"| " + str(values[0][0]).ljust(20), "\n"+"CMS_NAME ".ljust(15)+"|" , values[0][1].ljust(20), "\n"+"POC_METHOS".ljust(15)+"|", values[0][2].ljust(20), "\n"+"POC_NAME".ljust(15)+"|",
              values[0][3].ljust(20),"\n"+"POC_RRFERER".ljust(15)+"|", values[0][4].ljust(20))
        printGreen("------------------------------------------------------------------------------------")
        print("POC_POCDESCRIPTION\n\n",values[0][5])

       # print("ID: %s\nCMS_NAME: %s\nPOC_METHOS: %s\nPOC_NAME: %s\nPOC_RRFERER: %s\nPOC_POCDESCRIPTION: %s"%(,,values[0][2],values[0][3],values[0][4],values[0][5]))
        printRed("注意:命令行输出的数据有可能不完整！")
        printGreen("------------------------------------------------------------------------------------")
        sys.exit(1)
#sql查询通用函数
def check_sql(sql):
    conn = sqlite3.connect(DB_NAME)
    # 创建一个游标 curson
    cursor = conn.cursor()
    # 执行一条语句,创建 user表 如不存在创建
    cursor.execute(sql)
    values = cursor.fetchall()
    return values
def check_url_go(url,data):
    printBlue(FLAGLET)
    printBlue("[-]Start:开始执行")
    printBlue("[*]Info:共加载%s个漏洞" % len(data))
    printBlue("[*]Info:开始扫描...")
    for methods in data:
        #使用eval方法将字符串转换为可以执行的函数
        try:
            printBlue("[*]Info:扫描%s"%methods[1]+"...")
            eval(methods[0])(url).run()
        except:
            printRed("[E]Error:%s脚本执行错误！"%methods[0])
    #     # methods(url)
    printBlue("[-]End:扫描结束！")
def check_file_go(url_list,data):
    printBlue(FLAGLET)
    printBlue("[-]Start:开始执行")
    printBlue("[*]Info:共加载%s个URL"%len(url_list))
    printBlue("[*]Info:共加载%s种漏洞" % len(data))
    for url in url_list:
        url = url.replace("\n","").replace("\r\n","").replace("\r","")
        printSkyBlue("[*]Info:开始扫描%s"%url)
        for methods in data:
            #使用eval方法将字符串转换为可以执行的函数
            try:
                printBlue("[*]Info:扫描%s"%methods[1]+"...")
                eval(methods[0])(url).run()
            except:
                printRed("[E]Error:%s脚本执行错误！"%methods[0])
        # printBlue("\n")
    #     # methods(url)
    printBlue("[-]End:扫描结束！")
def Judgement_parameter(Command_dict):
    sql_data=""
    if "URL" in Command_dict and 'file' not in Command_dict:
        if "CMS" in Command_dict and "module" in Command_dict:
            printBlue(FLAGLET)
            printRed("[E]Error:-m参数和c参数不能同时使用！")
            sys.exit(1)
        if "module" in Command_dict and "CMS" not in Command_dict:
            # -m -u
            sql_data = "select pocmethods,pocname from POC where pocmethods='%s'" % Command_dict['module']
        if "CMS" in Command_dict and "module" not in Command_dict:
            # -c  -u
            sql_data = "select pocmethods,pocname from POC where cmsname='%s'" % Command_dict['CMS']
        if len(sys.argv) == 3:
            # -u参数
            sql_data = "select pocmethods,pocname from POC"
        if sql_data!="":
            data = check_sql(sql_data)
            # print(data)
            # print(type(data))
            check_url_go(Command_dict['URL'], data)
            sys.exit(1)
        else:
            printBlue(FLAGLET)
            printRed("[E]Error:参数设置错误！")
            sys.exit(1)
        # file module  cms
    if 'file' in Command_dict and "URL" not in Command_dict:
        if not os.path.isfile(Command_dict['file']):
            printBlue(FLAGLET)
            printRed("[E]Error:文件%s不存在！" % Command_dict['file'])
            sys.exit(1)
        else:
            if "module" in Command_dict:
                sql_data = "select pocmethods,pocname from POC where pocmethods='%s'" % Command_dict['module']
            if "CMS" in Command_dict:
                sql_data = "select pocmethods,pocname from POC where cmsname='%s'" % Command_dict['CMS']
            if "CMS" in Command_dict and "module" in Command_dict:
                printBlue(FLAGLET)
                printRed("[E]Error:-m参数和c参数不能同时使用！")
                sys.exit(1)
            if len(sys.argv) == 3:
                sql_data = "select pocmethods,pocname from POC"
            if sql_data != "":
                data = check_sql(sql_data)
                # 读取url到列表中
                file_url = []
                f = open(Command_dict['file'], 'r', encoding='utf-8')
                for url in f.readlines():
                    if url[0:7] == 'http://' or url[0:8] == "https://":
                        file_url.append(url)
                check_file_go(file_url, data)
            else:
                printBlue(FLAGLET)
                printRed("[E]Error:参数设置错误！")
                sys.exit(1)
    else:
        printBlue(usage)

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
        printBlue(FLAGLET)
        printRed("[E]Error:数据库文件不存在，请执行-r重新加载数据文件！")
        sys.exit(1)
    try:
        from cms.cmsmain import *
    except:
        printBlue(FLAGLET)
        printRed("[E]Error:CMS数据库文件引入错误，请执行-r重新加载数据文件！")
        sys.exit(1)
    Command_dict=getparameter()
    Judgement_parameter(Command_dict)

    # #测试输出
    # for key in Command_dict:
    #     print(key + ':' + Command_dict[key])