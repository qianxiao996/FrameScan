#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Author: qianxiao996
#Blog:blog.qianxiao996.cn
#date:  2019-9-21
#别问我为什么不用命令行解释模块，因为丑。
import importlib
import sys,os
from urllib.parse import urlparse
from colorama import init, Fore

import eventlet
from prettytable import PrettyTable
import sqlite3,requests,threading
import queue,frozen_dir
SETUP_DIR = frozen_dir.app_path()
sys.path.append(SETUP_DIR)
vuln_data=[]
# 禁用安全警告
requests.packages.urllib3.disable_warnings()
DB_NAME = "VULN_DB.db"  #存储的数据库名
VERSION = "V1.6.1 20210523"
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
        -cms        Specify CMS              指定webapp or CMS类型

    EXP Mode:
        -v          Use exp name             指定漏洞EXP名称
        -cmd        RCE Command(whoami)      执行cmd命令(默认:whoami)
        -shell      Return webshell          反弹Webshell(127.0.0.1:8080)

    Search:
        -ls         List Specify CMS poc     查找关键词漏洞(匹配漏洞名称)
        -la         List CMS POC             列出指定CMS漏洞(匹配CMS)
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
        python3 FrameScan.py -u http://example.com -cms thinkphp
        python3 FrameScan.py -f url.txt -m exp -v CVE-2019-2729
        python3 FrameScan.py -u http://example.com:7001 -m exp -v CVE-2019-2729
        python3 FrameScan.py -f list.txt -txt results.txt
    --------------------------------------------------------------
    FrameScan  %s         Blog:blog.qianxiao996.cn
    ''' % VERSION

#得到输入的参数
def getparameter():
    # 获取命令行所有参数
    Command = sys.argv
    # print(Command)
    Command_dict = {}
    #判断互斥参数:
    if "-u" in Command and  "-f" in Command :
        print(Fore.BLUE+(usage))
        sys.exit(1)
    elif "-n" in Command and  "-cms" in Command :
        print(Fore.BLUE+(usage))
        sys.exit(1)
    elif "-n" in Command and  "-cms" in Command :
        print(Fore.BLUE+(usage))
        sys.exit(1)
    elif "-c" in Command and  "-shell" in Command :
        print(Fore.BLUE+(usage))
        sys.exit(1)
    elif "-txt" in Command and  "-html" in Command :
        print(Fore.BLUE+(usage))
        sys.exit(1)
    #帮助信息
    if  len(sys.argv) ==1 or "-h" in Command:
        # 输出帮助信息
        print(Fore.BLUE+(usage))
        sys.exit(1)
    elif  len(sys.argv) ==1 or "-l" in Command:
        # 列出所有漏洞
        list_all_vuln()
        sys.exit(1)
    try:
        #列表每次取两个元素
        # print(len(Command))
        # if "-shell" in Command:
            # Command_dict['-shell'] = ""
            # Command.remove("-shell")
        for i in range(1, len(Command), 2):
            # print(Command[i])
            Command_dict[Command[i]] = Command[i + 1]
            #转化为字典
        return(Command_dict)
    except:
        print(Fore.BLUE+(FLAGLET))
        print(Fore.RED+("[E]Error:参数值设置错误！"))
        sys.exit(1)
    #如果参数字典为空  输出帮助
    if not Command_dict:
        print(Fore.BLUE+(usage))
        sys.exit(1)
    #否则返回参数
    else:
        return Command_dict
#重新加载POC
def Reload_POC():
    print(Fore.BLUE+(FLAGLET))
    #删除数据库，重新建立
    print(Fore.BLUE+("[*]Info:正在删除数据库..."))
    try:
        if os.path.exists(DB_NAME):
            os.remove(DB_NAME)
            print(Fore.GREEN+("[+]Success:删除数据库完成！"))
        else:
            print(Fore.BLUE+("[*]Info:文件不存在，无需删除！"))
    except:
        print(Fore.RED+("[E]Error:数据库文件删除失败，请手动删除！"))
        sys.exit(1)
    print(Fore.BLUE+("[*]Info:正在创建数据库..."))
    try:
        # 连接数据库。如果数据库不存在的话，将会自动创建一个 数据库
        conn = sqlite3.connect(DB_NAME)
        # 创建一个游标 curson
        cursor = conn.cursor()
        # 执行一条语句,创建 user表 如不存在创建
        sql ='CREATE TABLE `vuln_poc`  (`id` int(255) NULL DEFAULT NULL,`cms_name` varchar(255),`vuln_file` varchar(255),`vuln_name` varchar(255),`vuln_author` varchar(255),`vuln_referer` varchar(255),`vuln_description` varchar(255),`vuln_identifier` varchar(255),`vuln_solution` varchar(255),`ispoc` int(255) NULL DEFAULT NULL,`isexp` int(255) NULL DEFAULT NULL,`vuln_class` varchar(255),`FofaQuery_link` varchar(255),`target` varchar(1000),`FofaQuery` varchar(255))'        
        cursor.execute(sql)
        print(Fore.GREEN+("[+]Success:创建数据库完成!"))
    except:
        print(Fore.RED+("[E]Error:数据框创建失败！"))
        sys.exit(1)
    print(Fore.BLUE+("[*]Info:正在写入数据..."))
    # cms_path='Plugins/'
    try:
        id=1
        plugins_path = "Plugins/"
        plugins_path = plugins_path.replace("\\", "/")
        for cms_name in os.listdir(plugins_path):  # 遍历目录名
            cms_path = os.path.join(plugins_path, cms_name).replace("\\", "/")
            for poc_file_dir, poc_dirs_list, poc_file_name_list in os.walk(cms_path):
                # print(path,dirs,poc_methos_list)
                # print(poc_file_name_list)
                for poc_file_name in poc_file_name_list:
                    poc_name_path = poc_file_dir+ "\\" + poc_file_name
                    poc_name_path = poc_name_path.replace("\\", "/")
                    # 判断是py文件在打开  文件存在
                    if os.path.isfile(poc_name_path) and poc_file_name.endswith('.py') and len(
                            poc_file_name) >= 8 and poc_file_name[:8] == "Plugins_":
                        # print(poc_name_path)
                        try:
                            nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(poc_name_path[:-3],
                                                                                 poc_name_path).load_module()
                            vuln_info = nnnnnnnnnnnn1.vuln_info()
                            if vuln_info.get('vuln_class'):
                                vuln_class =vuln_info.get('vuln_class')
                            else:
                                vuln_class='未分类'
                            if vuln_info.get('FofaQuery_link'):
                                FofaQuery_link =(vuln_info.get('FofaQuery_link'))
                            else:
                                FofaQuery_link=''
                            if vuln_info.get('FofaQuery'):
                                FofaQuery =vuln_info.get('FofaQuery')
                            else:
                                FofaQuery=''
                            # 将数据插入到表中
                            insert_sql = 'insert into vuln_poc  (id,cms_name,vuln_file,vuln_name,vuln_author,vuln_referer,vuln_description,vuln_identifier,vuln_solution,ispoc,isexp,vuln_class,FofaQuery_link,FofaQuery,target) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
                            cursor.execute(insert_sql, (
                                        id,cms_name, poc_file_name,vuln_info['vuln_name'],vuln_info['vuln_author'] , vuln_info['vuln_referer'], vuln_info['vuln_description'],
                                        vuln_info['vuln_identifier'],vuln_info['vuln_solution'],vuln_info['ispoc'],vuln_info['isexp'],vuln_class,FofaQuery_link,FofaQuery,'[]'))
                            id=id+1
                        except Exception as  e:
                            print(Fore.RED+(
                                "Error:%s脚本执行错误！<br>[Exception]:<br>%s</p>\n" % (
                                    poc_file_name, e)))
                            continue
            conn.commit()  # 提交

        cursor.execute("select count(ispoc) from vuln_poc where ispoc =1")
        poc_num = cursor.fetchall()
        cursor.execute("select count(isexp) from vuln_poc where isexp =1")
        exp_num = cursor.fetchall()
        conn.close()
        print(Fore.GREEN+("[+]Success:数据库更新完成！"))
        print(Fore.YELLOW+( "[+]数据更新完成！\n   POC数量：%s\n   EXP数量：%s" % (poc_num[0][0],exp_num[0][0])))
        sys.exit(1)
        # reboot = sys.executable
        # os.execl(reboot, reboot, *sys.argv)
    except Exception as e:
        print(Fore.RED+(
            "Error:数据写入失败！\n[Exception]:\n%s</p>" % (e)))
        sys.exit(1)

#列出所有的漏洞
def list_all_vuln():
    conn2 = sqlite3.connect(DB_NAME)
    # 创建一个游标 curson
    cursor = conn2.cursor()
    #查询所有数据
    sql = "SELECT cms_name,vuln_name,vuln_author,vuln_identifier,vuln_file,ispoc,isexp from vuln_poc"
    print(Fore.GREEN+(("[*]Info:正在查询数据...")))
    cursor.execute(sql)
    values = cursor.fetchall()
    # print(values)
    if values == []:
        print(Fore.YELLOW+("[-]Success:查询完成，数据查询为空。"))
    else:
        print(Fore.YELLOW+("[-]Success:数据查询成功！"))
        table = PrettyTable([Fore.CYAN+('CMS_NAME'),Fore.CYAN+('VULN_NAME'),Fore.CYAN+('VULN_Author'),Fore.CYAN+("vuln_identifier"),Fore.CYAN+("Vuln_File"),Fore.CYAN+("Is_Poc"),Fore.CYAN+("Is_Exp")])

        for single in values:
            table.add_row(list(single))
        print(table)
        conn2.close()

#列出指定cms的数据
def list_cms_vuln():
    if sys.argv[1] == "-la" or sys.argv[1] == "-ls":
        try:
            # -la 通过cms名称来查询POC
            if sys.argv[1] == "-la":
                sql = "select cms_name,vuln_name,vuln_author,vuln_identifier,vuln_file,ispoc,isexp   from vuln_poc where cms_name like '%%%s%%'"%sys.argv[2]
            # -s 通过POC名称来查询poc
            elif sys.argv[1] == "-ls":
                sql = "SELECT cms_name,vuln_name,vuln_author,vuln_identifier,vuln_file,ispoc,isexp   from vuln_poc where vuln_name like '%%%s%%'" % sys.argv[2]
            # print(Fore.RED+(sql)
        except:
            sys.exit(1)
        conn2 = sqlite3.connect(DB_NAME)
        # 创建一个游标 curson
        cursor = conn2.cursor()
        print(Fore.GREEN+(("[*]Info:正在查询数据...")))
        cursor.execute(sql)
        values = cursor.fetchall()
        # print(values)
        if values == []:
            print(Fore.YELLOW+("[-]Success:查询完成，数据查询为空。"))
        else:
            print(Fore.YELLOW+("[-]Success:数据查询成功！"))
            table = PrettyTable([Fore.CYAN+('CMS_NAME'), Fore.CYAN+('VULN_NAME'), Fore.CYAN+('VULN_Author'),
                                 Fore.CYAN+("vuln_identifier"), Fore.CYAN+("Vuln_File"), Fore.CYAN+("Is_Poc"),
                                 Fore.CYAN+("Is_Exp")])
            for single in values:
                table.add_row(list(single))
            print(table)
            conn2.close()

    else:
        print(Fore.BLUE+(FLAGLET))
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
    <link rel="stylesheet" href="http://cdn.datatables.net/1.10.21/css/jquery.dataTables.min.css">
    <script src="http://libs.baidu.com/jquery/2.0.0/jquery.min.js"></script>
    <script src="http://cdn.datatables.net/1.10.21/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.jsdelivr.net/gh/rainabba/jquery-table2excel@master/src/jquery.table2excel.js"></script>
    


    <style type="text/css">
        /*表格样式*/			
        table {
            /*table-layout: fixed;*/
            /* word-break:break-all; */
            width: 80%;
            margin: 10px auto;
            border-collapse: collapse;
        }				
        th,td {
            text-align: center;
            border: 1px solid #ccc;
        }		
        th {
            min-width:50px;
            font-weight: normal;
            color:white;
            background-color: rgb(8, 103, 193);
            padding: 0.5em;
        }	
        td{
            min-width:50px;
            font-weight: normal;
            /* text-align: left; */
            padding: 0.5em;
        }	
        table tbody tr td a {
            color: #06f;
            text-decoration: none;
        }	
        	
        table tbody tr td a:visited
        {
            color:	green;
            text-decoration: none;

        }
        table tbody tr:nth-child(odd) {
             /* 匹配奇数行 */
            background-color: #F1F1F1  ;
            color: black;
        }

        table tbody tr:nth-child(even) {
            /* 匹配偶数行 */
            background-color:white ;
            color: black;
        }
        
    </style>
</head>
<body style="margin:0px;background-color:#F0F2F5">
    <div style="position: fixed;background: rgb(8, 103, 193);width:100%; z-index:9999">
        <p  style="color:white;width: 100%;height: 20px;display: block;line-height: 20px;text-align: center;">Super-PortScan Sacn Result</p>
    </div>
    <div style="padding-top:70px;padding-bottom:0px;padding-left:80px;padding-right:80px">
        <table id="table" align="center">
        </table>
    </div>
</body>
</html>
<script>

    $("#table").dataTable({
         //lengthMenu: [5, 10, 20, 30],//这里也可以设置分页，但是不能设置具体内容，只能是一维或二维数组的方式，所以推荐下面language里面的写法。
        destroy:true,
        "autoWidth": false,
        paging: true,//分页
        ordering: true,//是否启用排序
        searching: true,//搜索
        language: {
            lengthMenu: '<select class="form-control input-xsmall">' + '<option value="1">1</option>' + '<option value="10">10</option>' + '<option value="20">20</option>' + '<option value="50">50</option>' + '<option value="100">100</option>' + '<option value="200">200</option>'  + '<option value="500">500</option>'  + '<option value="1000">1000</option>' + '</select>条记录',//左上角的分页大小显示。
            search: '<button onclick="exportCsv()" style="margin:2px 30px">导出CSV</button><span class="label label-success" style="">搜索:</span>',//右上角的搜索文本，可以写html标签
            
            paginate: {//分页的样式内容。
                previous: "上一页",
                next: "下一页",
                first: "第一页",
                last: "最后"
            },

            zeroRecords: "无扫描结果",//table tbody内容为空时，tbody的内容。
            //下面三者构成了总体的左下角的内容。
            info: "总共_PAGES_ 页，显示第_START_ 到第 _END_ ，筛选之后得到 _TOTAL_ 条，初始_MAX_ 条 ",//左下角的信息显示，大写的词为关键字。
            infoEmpty: "0条记录",//筛选为空时左下角的显示。
            infoFiltered: ""//筛选之后的左下角筛选提示，
        },
        paging: true,
        pagingType: "full_numbers",//分页样式的类型


        columns: [
        { title: "URL地址", sortable: true, render: function(data, type, row) { return '<a  href="'+data+'" target="_blank">' + data + '</a>'; }},
        { title: "漏洞名称", sortable: true },
        { title: "漏洞编号", sortable: true },
        { title: "漏洞描述", sortable: true },
        { title: "漏洞链接", sortable: true, render: function(data, type, row) { return '<a  href="'+data+'" target="_blank">' + data + '</a>'; }},
        { title: "插件位置", sortable: true },
        { title: "Payload", sortable: true },
        { title: "扫描结果", sortable: true }
         ]       

    });
    $("#table_local_filter input[type=search]").css({ width: "auto" });//右上角的默认搜索文本框，不写这个就超出去了。
    $('#table').on( 'click', 'tr', function () {
        var table = $('#table').DataTable();
        // var id = table.row(this).row();
        var background = $(this).css('backgroundColor');
        // console.log(background);
        
        if(background=="rgb(216, 191, 216)")
        {
            $(this).css("background","white");
        }
        else
        {
            $(this).css("background","rgb(216, 191, 216)");
        }

        // alert( '被点击行的id是 '+id );
    } );

    function add_table(url,vuln_name,vuln_bianhao,vuln_miaoshu,vuln_refefer,vuln_file,vuln_payload,result){
        var t = $('#table').DataTable();
        t.row.add( [url,vuln_name,vuln_bianhao,vuln_miaoshu,vuln_refefer,vuln_file,vuln_payload,result] ).draw( false );
    }


    
    function exportCsv() {
            $("#table").table2excel({
                exclude: ".noExl",
                name: "Excel Document Name",
                // Excel文件的名称
                filename: "FrameScan Sacn Result",
                exclude_img: true,
                exclude_links: true,
                exclude_inputs: true
            });
        }

        
</script>
        ''')
        save.close()
  
    print(Fore.BLUE+(FLAGLET))
    print(Fore.BLUE+("[-]Start:开始执行"))
    # print(savefiletype)
    print(Fore.BLUE+("[*]Info:共加载%s个URL,%s个POC,线程%s,超时:%ss"%(len(url_list),len(poc_list),str(threadnum),timeout)))
    print(Fore.YELLOW+("[*]Info:正在创建队列..."))
    for url in url_list:
        for all in poc_list:
            # print(all)
            poc_filename = 'Plugins/' + all[1] + '/' + all[2]
            # print(filename)
            poc_methods = 'Plugins.' + all[1]+ '.' + all[2][:-3]
            portQueue.put(url+ '$$$' + poc_filename + '$$$' + poc_methods+'$$$'+all[1]+'$$$'+all[5]+'$$$'+all[6]+'$$$'+all[7])
            # print(url,methods[0])
    if threadnum>portQueue.qsize():
        threadnum = portQueue.qsize()
    print(Fore.YELLOW+("[-]Start:开始扫描..."))
    print(Fore.GREEN+((
            "-"*80)))
    for i in range(threadnum):
        thread = threading.Thread(target=vuln_start, args=(portQueue,))
        # thread.setDaemon(True)  # 设置为后台线程，这里默认是False，设置为True之后则主线程不用等待子线程
        threads.append(thread)
        thread.start()
    for t in threads:
        t.join()
    print(Fore.GREEN+((
            "-"*80)))
    print(Fore.YELLOW+("[-]End:扫描结束！"))
    if len(vuln_data) != 0:
        print(Fore.YELLOW+('[-]Success:共扫描到%s个漏洞！'%len(vuln_data)))
        print(Fore.CYAN+('\n[-]漏洞详情'))
        print(Fore.GREEN+(
                "-"*50))
        for i in vuln_data:
            print(Fore.GREEN+(i.strip()+'\n'))

    else:
        print(Fore.YELLOW+('[-]End:未发现漏洞！'))
    sys.exit(1)

def exp_start(url_list,poc,timeout,exp_type,cmd):
    print(Fore.BLUE+(FLAGLET))
    print(Fore.YELLOW+("[*]EXP_Name:%s\n[*]EXP_Identifier:%s\n[*]EXP_File:%s\n[*]EXP_Type:%s\n[*]EXP_Data:%s\n[*]Timeout:%s"%(poc[3],poc[7],poc[2],exp_type,cmd,timeout)))
    for url in url_list:
        _url = urlparse(url)
        hostname = _url.hostname
        port = _url.port
        scheme = _url.scheme
        if port is None and scheme == 'https':
            port = 443
        elif port is None:
            port = 80
        url = scheme + '://' + hostname + ':' + str(port) + '/'
        # print(url)
        print(Fore.CYAN+("[*]URL:%s"%url))
        poc_filename = "Plugins/"+poc[1]+"/"+poc[2]
        poc_methods = "Plugins."+poc[1]+"."+poc[2][:-3]
        return_data =  {"type":'Result', "value":"root", "color":"black"}
        eventlet.monkey_patch(time=True)
        try:
            with eventlet.Timeout(timeout, False):
                if exp_type=="shell":
                    try:
                        ip_port = cmd.split(":")
                    except:
                        print(Fore.RED+("[E]Error:请输入正确的反弹IP和端口,示例：127.0.0.1:8888"))
                        continue
                    if len(ip_port)==2:
                        ip = ip_port[0]
                        port = int(ip_port[1])
                    else:
                        print(Fore.RED+("[E]Error:请输入正确的反弹IP和端口,示例：127.0.0.1:8888"))
                        continue
                    nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(poc_methods, poc_filename).load_module()
                    return_data = nnnnnnnnnnnn1.do_exp(url, "",  exp_type, cmd, ip,port)
                else:
                    nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(poc_methods, poc_filename).load_module()
                    return_data = nnnnnnnnnnnn1.do_exp(url, "", exp_type, cmd)
                if return_data['type'] == 'Result':
                    print(Fore.GREEN+("[*]EXP_Result:\n%s\n"%(return_data['value'])))
                else:
                    print(Fore.GREEN+("[*]EXP_Result:\n%s\n"%(return_data['value'])))
                continue
            print(Fore.RED+("[E]Error:%s运行超时！" % (poc_filename)))
        except Exception as  e:
            print(Fore.RED+("[E]Error:%s"%(str(e))))
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
        poc_bianhao = all.split('$$$')[6]
        eventlet.monkey_patch(time=True)
        with eventlet.Timeout(int(timeout), False):
            try:
                _url = urlparse(url)
                hostname = _url.hostname
                port = _url.port
                scheme = _url.scheme
                if port is None and scheme == 'https':
                    port = 443
                elif port is None:
                    port = 80
                url = scheme + '://' + hostname + ':' + str(port) + '/'
                nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(poc_methods, poc_filename).load_module()
                return_data = nnnnnnnnnnnn1.do_poc(url,"",hostname,port,scheme)
                if return_data['type'] == 'Result' and return_data['value'] == '存在':
                    # return_data.append(url)
                    vuln_info = "[*]URL:%s\n[*]漏洞名称:%s\n[*]测试结果:%s\n[*]漏洞编号:%s\n[*]漏洞描述:%s\n[*]漏洞来源:%s\n[*]插件路径:%s\n[*]Payload:\n%s" % (
                    url.strip(),poc_name,poc_bianhao, return_data['value'],poc_description.strip(),poc_referer.strip(),poc_filename,return_data['payload'])
                    vuln_data.append(vuln_info)
                    output([url.strip(),poc_name,return_data['value'],poc_description.strip(),poc_referer.strip(),poc_filename,return_data['payload'],poc_bianhao.strip()])
                    if poc_bianhao:
                        print(Fore.GREEN+("[*]Info:%s----%s(%s)----%s----%s。" % (url, poc_name,poc_bianhao, return_data['value'],return_data['payload'])))
                    else:
                        print(Fore.GREEN+("[*]Info:%s----%s----%s----%s。" % (url, poc_name, return_data['value'],return_data['payload'])))

                elif return_data['type'] == '不存在' and return_data['value'] == '不存在':
                    print(Fore.BLUE+(
                            "[*]Info:%s----%s----%s。" % (url, poc_name, return_data['value'])))
                else:
                    print(Fore.CYAN+("[*]Info:%s----%s----%s。" % (url, poc_name, return_data['value'])))
                continue
            except Exception as e:
                # print(str(e))
                print(Fore.RED+("[E]Error:%s脚本执行错误!"%(poc_filename)))
                print(Fore.RED+("[E]Error:%s"%e))
                continue
        print(Fore.RED+("[E]Error:%s脚本运行超时!"%(poc_filename)))

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
            print(Fore.RED+('Error:文件读取错误！'))
    else:

        url = path.split()[0]
        # print(url)
        if 'http://' in url or 'https://' in url:
            all_list.append(url)
        # print(all_list)
        return list(filter(None, all_list))  # 去除 none 和 空字符
def Judgement_parameter(Command_dict):
    # print(222)
    if "-la" in Command_dict or "-ls" in Command_dict  :
        #-s 查询关键词的漏洞 -la # 列出某个cms的漏洞
        if len(sys.argv) <=2:
            print(Fore.BLUE+(usage))
            sys.exit(1)
        else:
            list_cms_vuln()
            sys.exit(1)
    if "-u" in Command_dict or '-f' in Command_dict:
        if "-u" in Command_dict:
            url_list = get_url_list(Command_dict['-u'])
        elif '-f' in Command_dict:
            if not os.path.isfile(Command_dict['-f']):
                print(Fore.BLUE+(FLAGLET))
                print(Fore.RED+("[E]Error:文件%s不存在！" % Command_dict['-f']))
                sys.exit(1)
            url_list = get_url_list(Command_dict['-f'])
        # print(url_list)
        if len(url_list)==0:
            print(Fore.BLUE+(FLAGLET))
            print(Fore.RED+('未获取到URL地址!'))
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
                sql_data = "select * from vuln_poc where vuln_name like'%"+Command_dict['-v']+"%' and isexp =1"
                # print(sql_data)
            else:
                print(Fore.RED+('请指定一个EXP!'))
                sys.exit()
            if sql_data != "":
                exp_list = check_sql(sql_data)
                if len(exp_list)==0:
                    print(Fore.BLUE+(FLAGLET))
                    print(Fore.RED+("[E]Error:未查询到EXP！"))
                    sys.exit(1)
            if "-cmd" in Command_dict:
                cmd =  Command_dict['-cmd']
                exp_start(url_list,exp_list[0],timeout,"cmd",cmd)
            elif "-shell" in Command_dict:
                shell = Command_dict['-shell']
                exp_start(url_list,exp_list[0],timeout,"shell",shell)
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
                sql_data = "select * from vuln_poc where vuln_name like '%"+Command_dict['-n']+"%'"
            elif "-cms" in Command_dict:
                sql_data = "select * from vuln_poc where cms_name like '%"+Command_dict['-cms']+"%'"
            else:
                # -u参数
                sql_data = "select * from vuln_poc"
            if sql_data != "":
                poc_list = check_sql(sql_data)
                if len(poc_list)==0:
                    print(Fore.BLUE+(FLAGLET))
                    print(Fore.RED+("[E]Error:未查询到POC！"))
                    sys.exit(1)
                check_vuln(url_list, poc_list,threadnum)
            else:
                print(Fore.BLUE+(FLAGLET))
                sys.exit(1)
    else:
        print(Fore.BLUE+(FLAGLET))
        print(Fore.RED+("Error:请指定URL地址!"))

def output(vuln_info):
    #保存到文件
    if savefiletype == 'txt':
        vuln_info="\nURL:"+vuln_info[0]+"\n漏洞名称:"+vuln_info[1]+"\n漏洞编号:"+vuln_info[7]+"\n测试结果:"+vuln_info[2]+"\n漏洞描述:"+vuln_info[3]+"\n漏洞来源:"+vuln_info[4]+"\n插件路径:"+vuln_info[5]+"\nPayload:"+vuln_info[6]
        print(vuln_info)
        save = open(savefilename, 'a', encoding='utf-8')
        save.write(vuln_info)
        save.close()
    if savefiletype == 'html':
        save = open(savefilename, 'a', encoding='gbk')
        save.write('''  
        <script>add_table("%s","%s","%s","%s","%s","%s","%s","%s");</script>
        ''' % (vuln_info[0], vuln_info[1], vuln_info[7],vuln_info[3],vuln_info[4],vuln_info[5],vuln_info[6],vuln_info[2]))
        save.close()
if __name__ == '__main__':
    init(autoreset=False)
    # 需要python3 版本
    if sys.version_info < (3, 0):
        sys.stdout.write("Sorry, FrameScan requires Python 3.x\n")
        sys.exit(1)
    #获取返回的参数和值
    if len(sys.argv)==2 and sys.argv[1]=="-r":
        Reload_POC()
        sys.exit(1)
    if not os.path.isfile(DB_NAME):
        print(Fore.BLUE+(FLAGLET))
        print(Fore.RED+("[E]Error:数据库文件不存在，请执行-r重新加载数据文件！"))
        sys.exit(1)
    Command_dict=getparameter()
    #测试输出
    # for key in Command_dict:
    #     print(key + ':' + Command_dict[key])
    Judgement_parameter(Command_dict)

