#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: qianxiao996
# Blog:blog.qianxiao996.cn
# date:  2019-9-21
# 别问我为什么不用命令行解释模块，因为丑。
import contextlib
import datetime
import importlib
import platform
import sys, os
sys.path.append('./Modules')
sys.path.append('./Plugins/Modules')
vuln_plugins_dir = './Plugins/Vuln_Plugins/'
import time
from urllib.parse import urlparse
from colorama import init, Fore
from io import StringIO
import eventlet
from prettytable import PrettyTable
import sqlite3, requests, threading
import queue, frozen_dir

all_vuln_out_table = PrettyTable([Fore.CYAN + ('URL'),Fore.CYAN + ('漏洞名称'), Fore.CYAN + ('n漏洞编号'), Fore.CYAN + ('测试结果'),
                     Fore.CYAN + ("漏洞描述"), Fore.CYAN + ("漏洞来源"), Fore.CYAN + ("插件路径"),
                     Fore.CYAN + ("Payload")])
_print = print
mutex = threading.Lock()
#使输出有序进行，不出现多线程同一时间输出导致错乱的问题
def print(text, *args, **kw):
    with mutex:
        _print(text, *args, **kw)
sysstr = platform.system()
if (sysstr == "Windows"):
    houzhui = '.pyd'
elif (sysstr == "Linux"):
    houzhui = '.so'
plugins_ext = ['.py', '.pyc']
plugins_ext.append(houzhui)
SETUP_DIR = frozen_dir.app_path()
sys.path.append(SETUP_DIR)
vuln_data = []

# 禁用安全警告
requests.packages.urllib3.disable_warnings()
DB_NAME = "./VULN_DB.db"  # 存储的数据库名
VERSION = "V1.6.7 20230412"
FLAGLET = ("""
        _____                         ____                  
        |  ___| __ __ _ _ __ ___   ___/ ___|  ___ __ _ _ __  
        | |_ | '__/ _` | '_ ` _ \ / _ \___ \ / __/ _` | '_ \ 
        |  _|| | | (_| | | | | | |  __/___) | (_| (_| | | | |
        |_|  |_|  \__,_|_| |_| |_|\___|____/ \___\__,_|_| |_|
""")
usage = FLAGLET + '''
    Options:                                 Code by qianxiao996 
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
        -shell      Return Shell             反弹Shell(127.0.0.1:8080)

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
        python3 FrameScan.py -f url.txt -txt results.txt
    --------------------------------------------------------------
    FrameScan  %s                      by qianxiao996
    ''' % VERSION


# 得到输入的参数
def getparameter():
    # 获取命令行所有参数
    Command = sys.argv
    # print(Command)
    Command_dict = {}
    # 判断互斥参数:
    if "-u" in Command and "-f" in Command:
        print(Fore.CYAN + (usage))
        sys.exit(1)
    elif "-n" in Command and "-cms" in Command:
        print(Fore.CYAN + (usage))
        sys.exit(1)
    elif "-n" in Command and "-cms" in Command:
        print(Fore.CYAN + (usage))
        sys.exit(1)
    elif "-c" in Command and "-shell" in Command:
        print(Fore.CYAN + (usage))
        sys.exit(1)
    elif "-txt" in Command and "-html" in Command:
        print(Fore.CYAN + (usage))
        sys.exit(1)
    # 帮助信息
    if len(sys.argv) == 1 or "-h" in Command:
        # 输出帮助信息
        print(Fore.CYAN + (usage))
        sys.exit(1)
    elif len(sys.argv) == 1 or "-l" in Command:
        # 列出所有漏洞
        list_all_vuln()
        sys.exit(1)
    try:
        # 列表每次取两个元素
        # print(len(Command))
        # if "-shell" in Command:
        # Command_dict['-shell'] = ""
        # Command.remove("-shell")
        for i in range(1, len(Command), 2):
            # print(Command[i])
            Command_dict[Command[i]] = Command[i + 1]
            # 转化为字典
        return (Command_dict)
    except:
        print(Fore.CYAN + (FLAGLET))
        print(Fore.RED + ("参数值设置错误！"))
        sys.exit(1)
    # 如果参数字典为空  输出帮助
    if not Command_dict:
        print(Fore.CYAN + (usage))
        sys.exit(1)
    # 否则返回参数
    else:
        return Command_dict


# 重新加载POC
def Reload_POC():
    print(Fore.CYAN + (FLAGLET))
    # 删除数据库，重新建立
    (out_info("正在删除数据库..."))
    try:
        if os.path.exists(DB_NAME):
            os.remove(DB_NAME)
            (out_success("删除数据库完成！"))
        else:
            (out_error("文件不存在，无需删除！"))
    except:
        (out_error("数据库文件删除失败，请手动删除！"))
        sys.exit(1)
    (out_info("正在创建数据库..."))
    try:
        # 连接数据库。如果数据库不存在的话，将会自动创建一个 数据库
        conn = sqlite3.connect(DB_NAME)
        # 创建一个游标 curson
        cursor = conn.cursor()
        # 执行一条语句,创建 user表 如不存在创建
        sql = 'CREATE TABLE `vuln_poc`  (`id` int(255) NULL DEFAULT NULL,`cms_name` varchar(255),`vuln_file` varchar(255),`vuln_name` varchar(255),`vuln_author` varchar(255),`vuln_referer` varchar(255),`vuln_description` varchar(255),`vuln_identifier` varchar(255),`vuln_solution` varchar(255),`ispoc` int(255) NULL DEFAULT NULL,`isexp` int(255) NULL DEFAULT NULL,`vuln_class` varchar(255),`FofaQuery_type` varchar(255),`FofaQuery_link` varchar(255),`FofaQuery_rule` varchar(255))'
        cursor.execute(sql)
        out_success("创建数据库完成!")
    except:
        out_error("数据框创建失败！")
        sys.exit(1)
    (out_info("正在写入数据..."))
    # cms_path='Plugins/'
    try:
        id = 1
        all_plugins = get_dir_file(vuln_plugins_dir)

        go_load_plugins = []  # 存放已经加载的模块
        for poc in all_plugins:
            try:
                if os.path.splitext(poc['poc_file_name'])[-1] in plugins_ext:
                    if os.path.splitext(poc['poc_file_name'])[-1] == '.py':
                        nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(os.path.splitext(poc['poc_file_name'])[0],
                                                                             poc['poc_file_path']).load_module()
                    elif os.path.splitext(poc['poc_file_name'])[-1] in ['.pyc', '.pyd', '.so']:
                        if os.path.splitext(poc['poc_file_name'])[0] in go_load_plugins:
                            continue
                        module_spec = importlib.util.spec_from_file_location(os.path.splitext(poc['poc_file_name'])[0],
                                                                             poc['poc_file_path'])
                        nnnnnnnnnnnn1 = importlib.util.module_from_spec(module_spec)
                        module_spec.loader.exec_module(nnnnnnnnnnnn1)
                    vuln_info = nnnnnnnnnnnn1.vuln_info()
                    if vuln_info.get('vuln_class'):
                        vuln_class = vuln_info.get('vuln_class')
                    else:
                        vuln_class = '未分类'
                    if vuln_info.get('FofaQuery_type'):
                        FofaQuery_type = vuln_info.get('FofaQuery_type')
                    else:
                        FofaQuery_type = 'http'
                    if vuln_info.get('FofaQuery_link'):
                        FofaQuery_link = (vuln_info.get('FofaQuery_link'))
                    else:
                        FofaQuery_link = '/'

                    if vuln_info.get('FofaQuery_rule'):
                        FofaQuery_rule = vuln_info.get('FofaQuery_rule')
                    else:
                        FofaQuery_rule = ''
                    insert_sql = 'insert into vuln_poc  (id,cms_name,vuln_file,vuln_name,vuln_author,vuln_referer,vuln_description,vuln_identifier,vuln_solution,ispoc,isexp,vuln_class,FofaQuery_type,FofaQuery_link,FofaQuery_rule) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'

                    # 将数据插入到表中
                    cursor.execute(insert_sql, (
                        id, poc['cms_name'], os.path.splitext(poc['poc_file_name'])[0], vuln_info['vuln_name'],
                        vuln_info['vuln_author'],
                        vuln_info['vuln_referer'], vuln_info['vuln_description'],
                        vuln_info['vuln_identifier'], vuln_info['vuln_solution'], vuln_info['ispoc'],
                        vuln_info['isexp'], vuln_class, FofaQuery_type, FofaQuery_link, FofaQuery_rule))
                    id = id + 1
                    go_load_plugins.append(os.path.splitext(poc['poc_file_name'])[0])
            except Exception as  e:
                print(Fore.RED + "%s脚本执行错误！\n[Exception]:\n%s</a>" % (poc['poc_file_name'], str(e)))
                continue
            conn.commit()  # 提交

        # print(result)
        cursor.execute("select count(ispoc) from vuln_poc where ispoc =1")
        poc_num = cursor.fetchall()
        cursor.execute("select count(isexp) from vuln_poc where isexp =1")
        exp_num = cursor.fetchall()
        conn.close()
        out_success("数据更新完成！\n"+Fore.YELLOW +"  POC数量：%s\tEXP数量：%s" % (poc_num[0][0], exp_num[0][0]))
        sys.exit(1)
        # reboot = sys.executable
        # os.execl(reboot, reboot, *sys.argv)
    except Exception as e:
        print(Fore.RED + ("Error:数据写入失败！\n[Exception]:\n%s</p>" % (e)))
        sys.exit(1)


def get_dir_file(dir):
    all_plugins = []
    plugins_path = dir
    plugins_path = plugins_path.replace("\\", "/")
    for cms_name in os.listdir(plugins_path):  # 遍历目录名
        cms_path = os.path.join(plugins_path, cms_name).replace("\\", "/")
        for poc_file_dir, poc_dirs_list, poc_file_name_list in os.walk(cms_path):  # 遍历poc文件，得到方法名称
            # print(path,dirs,poc_methos_list)
            # print(poc_file_name_list)
            for poc_file_name in poc_file_name_list:
                if '__pycache__' in poc_file_dir:
                    continue
                # print(poc_file_name)
                poc_name_path = poc_file_dir + "\\" + poc_file_name
                poc_name_path = poc_name_path.replace("\\", "/")
                # 判断是py文件在打开  文件存在
                # print(poc_file_name[:8])
                if os.path.isfile(poc_name_path) and (
                        os.path.splitext(poc_name_path)[1] in ['.pyd', '.pyc', '.so', '.py']) and len(
                    poc_file_name) >= 8 and poc_file_name[:8] == "Plugins_":
                    single_plugins = {}
                    single_plugins['cms_name'] = cms_name
                    single_plugins['poc_file_name'] = poc_file_name
                    single_plugins['poc_file_path'] = poc_name_path
                    all_plugins.append(single_plugins)
    return all_plugins


# 列出所有的漏洞
def list_all_vuln():
    conn2 = sqlite3.connect(DB_NAME)
    # 创建一个游标 curson
    cursor = conn2.cursor()
    # 查询所有数据
    sql = "SELECT cms_name,vuln_name,vuln_author,vuln_identifier,vuln_file,ispoc,isexp from vuln_poc"
    out_info("正在查询数据...")
    cursor.execute(sql)
    values = cursor.fetchall()
    # print(values)
    if values == []:
        out_success("查询完成，数据查询为空。")
    else:
        out_success("数据查询成功！")
        table = PrettyTable([Fore.CYAN + ('CMS_NAME'), Fore.CYAN + ('VULN_NAME'), Fore.CYAN + ('VULN_Author'),
                             Fore.CYAN + ("vuln_identifier"), Fore.CYAN + ("Vuln_File"), Fore.CYAN + ("Is_Poc"),
                             Fore.CYAN + ("Is_Exp")])

        for single in values:
            table.add_row(list(single))
        print(table)
        conn2.close()


# 列出指定cms的数据
def list_cms_vuln():
    if sys.argv[1] == "-la" or sys.argv[1] == "-ls":
        try:
            # -la 通过cms名称来查询POC
            if sys.argv[1] == "-la":
                sql = "select cms_name,vuln_name,vuln_author,vuln_identifier,vuln_file,ispoc,isexp   from vuln_poc where cms_name like '%%%s%%'" % \
                      sys.argv[2]
            # -s 通过POC名称来查询poc
            elif sys.argv[1] == "-ls":
                sql = "SELECT cms_name,vuln_name,vuln_author,vuln_identifier,vuln_file,ispoc,isexp   from vuln_poc where vuln_name like '%%%s%%'" % \
                      sys.argv[2]
            # print(Fore.RED+(sql)
        except:
            sys.exit(1)
        conn2 = sqlite3.connect(DB_NAME)
        # 创建一个游标 curson
        cursor = conn2.cursor()
        out_info("正在查询数据...")
        cursor.execute(sql)
        values = cursor.fetchall()
        # print(values)
        if values == []:
            out_success("查询完成，数据查询为空。")
        else:
            out_success("数据查询成功！")
            table = PrettyTable([Fore.CYAN + ('CMS_NAME'), Fore.CYAN + ('VULN_NAME'), Fore.CYAN + ('VULN_Author'),
                                 Fore.CYAN + ("vuln_identifier"), Fore.CYAN + ("Vuln_File"), Fore.CYAN + ("Is_Poc"),
                                 Fore.CYAN + ("Is_Exp")])
            for single in values:
                table.add_row(list(single))
            print(table)
            conn2.close()

    else:
        print(Fore.CYAN + (FLAGLET))


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


# sql查询返回字典
def sql_search(sql, type='list'):
    if type == 'dict':
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
    return values


# sql查询返回字典

# # sql查询通用函数
# def check_sql(sql):
#     conn = sqlite3.connect(DB_NAME)
#     # 创建一个游标 curson
#     cursor = conn.cursor()
#     # 执行一条语句,创建 user表 如不存在创建
#     cursor.execute(sql)
#     values = cursor.fetchall()
#
#     return values


def check_vuln(url_list, poc_list, threadnum):
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

    print(Fore.CYAN + (FLAGLET))
    (out_info("开始执行"))
    # print(savefiletype)
    (out_prompt("共加载%s个URL,%s个POC,线程%s,超时:%ss" % (len(url_list), len(poc_list), str(threadnum), timeout)))
    (out_info("正在创建队列..."))
    for url in url_list:
        for all in poc_list:
            poc_filename = vuln_plugins_dir + all['cms_name'] + '/' +all['vuln_file']
            # print(filename)
            portQueue.put(
                url + '$$$' + poc_filename + '$$$' + all['vuln_file'] + '$$$' + all['vuln_name'] + '$$$' + all['vuln_referer'] + '$$$' + all['vuln_description']+ '$$$' + all['vuln_identifier'])
    if threadnum > portQueue.qsize():
        threadnum = portQueue.qsize()
    (out_info("开始扫描..."))
    print(Fore.GREEN + ((
            "-" * 80)))
    for i in range(threadnum):
        thread = threading.Thread(target=vuln_start, args=(portQueue,))
        # thread.setDaemon(True)  # 设置为后台线程，这里默认是False，设置为True之后则主线程不用等待子线程
        threads.append(thread)
        thread.start()
    for t in threads:
        t.join()
    print(Fore.GREEN + ((
            "-" * 80)))
    out_info(("扫描结束！"))
    if len(vuln_data) != 0:
        out_success(('共扫描到%s个漏洞！' % len(vuln_data))+Fore.CYAN)
        # print(Fore.GREEN + (
        #         "-" * 50))
        all_vuln_out_table = PrettyTable(
            [Fore.CYAN + ('URL'), Fore.CYAN + ('漏洞名称'), Fore.CYAN + ('漏洞编号'), Fore.CYAN + ('测试结果'),
             Fore.CYAN + ("漏洞描述"), Fore.CYAN + ("漏洞来源"), Fore.CYAN + ("插件路径"),
             Fore.CYAN + ("Payload")])
        for i in vuln_data:
            all_vuln_out_table.add_row(i)
        print(all_vuln_out_table)

        # for i in vuln_data:
        #     print(Fore.GREEN + (i.strip() + '\n'))
    else:
        out_success(('恭喜您,未发现漏洞！'))
    sys.exit(1)


def exp_start(url_list, poc, timeout, exp_type, cmd):
    print(Fore.CYAN + (FLAGLET))
    out_success((
            "EXP_Name:%s\nEXP_Identifier:%s\nEXP_File:%s\nEXP_Type:%s\nEXP_Data:%s\nTimeout:%s" % (
        poc[3], poc[7], poc[2], exp_type, cmd, timeout)))
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
        print(Fore.CYAN + ("URL:%s" % url))
        poc_filename = vuln_plugins_dir + poc[1] + "/" + poc[2]
        poc_methods = poc[2]
        return_data = {"type": 'Result', "value": "root", "color": "black"}
        eventlet.monkey_patch(time=True)
        try:
            with eventlet.Timeout(timeout, False):
                data = {}
                if exp_type == "shell":
                    try:
                        ip_port = cmd.split(":")
                    except:
                        out_error(("请输入正确的反弹IP和端口,示例：127.0.0.1:8888"))
                        continue
                    if len(ip_port) == 2:
                        ip = ip_port[0]
                        port = int(ip_port[1])
                    else:
                        out_error(("请输入正确的反弹IP和端口,示例：127.0.0.1:8888"))
                        continue
                    data['type'] = 'shell'
                    data['reverse_ip'] = ip
                    data['reverse_port'] = port

                    if os.path.isfile(poc_filename + '.py'):
                        poc_filename = poc_filename + '.py'
                        nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(poc_methods, poc_filename).load_module()
                    elif os.path.isfile(poc_filename + '.pyc'):
                        poc_filename = poc_filename + '.pyc'
                        module_spec = importlib.util.spec_from_file_location(poc_methods,
                                                                             poc_filename)
                        nnnnnnnnnnnn1 = importlib.util.module_from_spec(module_spec)
                        module_spec.loader.exec_module(nnnnnnnnnnnn1)
                    else:
                        sysstr = platform.system()
                        if (sysstr == "Windows"):
                            poc_filename = poc_filename + '.pyd'
                        elif (sysstr == "Linux"):
                            poc_filename = poc_filename + '.so'
                        loader_details = (
                            importlib.machinery.ExtensionFileLoader,
                            importlib.machinery.EXTENSION_SUFFIXES
                        )
                        tools_finder = importlib.machinery.FileFinder(
                            os.path.dirname(poc_filename), loader_details)
                        # print("FileFinder: ", tools_finder)
                        toolbox_specs = tools_finder.find_spec(poc_methods)
                        # print("find_spec: ", toolbox_specs)
                        nnnnnnnnnnnn1 = importlib.util.module_from_spec(toolbox_specs)
                        # print("module: ", nnnnnnnnnnnn1)
                        toolbox_specs.loader.exec_module(nnnnnnnnnnnn1)
                        # print("导入成功 path_import(): ", nnnnnnnnnnnn1)

                    # nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(poc_methods, poc_filename).load_module()
                    result = nnnnnnnnnnnn1.do_exp(url, "", '', '', {}, data)
                else:
                    data['type'] = 'cmd'
                    data['command'] = cmd
                    if os.path.isfile(poc_filename + '.py'):
                        poc_filename = poc_filename + '.py'
                        nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(poc_methods, poc_filename).load_module()
                    elif os.path.isfile(poc_filename + '.pyc'):
                        poc_filename = poc_filename + '.pyc'
                        module_spec = importlib.util.spec_from_file_location(poc_methods,
                                                                             poc_filename)
                        nnnnnnnnnnnn1 = importlib.util.module_from_spec(module_spec)
                        module_spec.loader.exec_module(nnnnnnnnnnnn1)
                    else:
                        sysstr = platform.system()
                        if (sysstr == "Windows"):
                            poc_filename = poc_filename + '.pyd'
                        elif (sysstr == "Linux"):
                            poc_filename = poc_filename + '.so'
                        loader_details = (
                            importlib.machinery.ExtensionFileLoader,
                            importlib.machinery.EXTENSION_SUFFIXES
                        )
                        tools_finder = importlib.machinery.FileFinder(
                            os.path.dirname(poc_filename), loader_details)
                        # print("FileFinder: ", tools_finder)
                        toolbox_specs = tools_finder.find_spec(poc_methods)
                        # print("find_spec: ", toolbox_specs)
                        nnnnnnnnnnnn1 = importlib.util.module_from_spec(toolbox_specs)
                        # print("module: ", nnnnnnnnnnnn1)
                        toolbox_specs.loader.exec_module(nnnnnnnnnnnn1)
                        # print("导入成功 path_import(): ", nnnnnnnnnnnn1)

                    result = nnnnnnnnnnnn1.do_exp(url, "", '', '', {}, data)

                if result.get('Result'):
                    print(Fore.GREEN + ("EXP_Result:\n%s\n" % (result.get('Result_Info'))))
                # 不存在
                else:
                    (out_info(
                        "%s\t%s\t%s。" % (url, poc[3], "漏洞不存在")))
                if result.get('Error_Info'):
                    out_error((
                            "%s\t%s\t%s。" % (url, poc[3], result.get("Error_Info"))))
                continue
            out_error(("%s运行超时！" % (poc_filename)))
        except Exception as  e:
            out_error(("%s" % (str(e))))
    return


def vuln_start(portQueue):
    while 1:
        if portQueue.empty():  # 队列空就结束
            break
        all = portQueue.get()  # 从队列中取出
        # print(all)
        url = all.split('$$$')[0]
        poc_filename = all.split('$$$')[1]
        poc_methods = all.split('$$$')[2]
        # print(poc_methods)
        poc_name = all.split('$$$')[3]
        # print(poc_name)
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
                # nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(poc_methods, poc_filename).load_module()
                nnnnnnnnnnnn1 = get_obj_by_path(poc_filename)
                if not nnnnnnnnnnnn1:
                    out_error(("%s文件导入失败!" % (poc_filename)))
                    continue
                result = nnnnnnnnnnnn1.do_poc(url, hostname, port, scheme, '')
                if result:
                    if result.get('Result'):
                        # return_data.append(url)
                        vuln_info = [url.strip(), poc_name, poc_bianhao, "存在", poc_description.strip(), poc_referer.strip(),poc_filename, result.get("Result_Info")]
                        vuln_data.append(vuln_info)
                        output([url.strip(), poc_name, "存在", poc_description.strip(), poc_referer.strip(), poc_filename,
                                result.get("Result_Info"), poc_bianhao.strip()])
                        if poc_bianhao:
                            out_success("%s\t%s(%s)\t%s\t%s。" % (
                                url, poc_name, poc_bianhao, "存在", result.get("Result_Info")))
                        else:
                            out_success(
                                "%s\t%s\t%s\t%s。" % (url, poc_name, "存在", result.get("Result_Info")))
                        # 不存在
                    elif result.get('Error_Info'):
                        out_error((
                            "%s\t%s\t%s。" % (url, poc_name, result.get("Error_Info"))))
                    else:
                        (out_info(
                                "%s\t%s\t%s。" % (url, poc_name, "不存在")))

                else:
                    out_error((
                            "%s\t%s\t%s。" % (url, poc_name, "脚本返回结果信息为空！")))
                continue
            except Exception as e:
                # print(str(e))
                out_error(("%s脚本执行错误!" % (poc_filename)))
                out_error(("%s %s行" % (e, str(e.__traceback__.tb_lineno))))
                continue
        out_error(("%s脚本运行超时!" % (poc_filename)))

def get_obj_by_path(filename):
    if os.path.isfile(filename + '.py'):
        filename = filename + '.py'
        nnnnnnnnnnnn1 = importlib.machinery.SourceFileLoader(
            os.path.splitext(filename)[0], filename).load_module()
    elif os.path.isfile(filename + '.pyc'):
        filename = filename + '.pyc'
        module_spec = importlib.util.spec_from_file_location(filename[:-4],
                                                             filename)
        nnnnnnnnnnnn1 = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(nnnnnnnnnnnn1)
    else:
        sysstr = platform.system()
        if (sysstr == "Windows"):
            new_filename =  filename + '.pyd'
            # filename = filename + '.pyd'
        elif (sysstr == "Linux"):
            new_filename = filename + '.so'
        else:
            new_filename = filename + '.py'
        if os.path.isfile(new_filename):

            loader_details = (
                importlib.machinery.ExtensionFileLoader,
                importlib.machinery.EXTENSION_SUFFIXES
            )
            tools_finder = importlib.machinery.FileFinder(
                os.path.dirname(new_filename), loader_details)
            # print("FileFinder: ", tools_finder)
            toolbox_specs = tools_finder.find_spec(
                os.path.basename(os.path.splitext(new_filename)[0]))
            # print("find_spec: ", toolbox_specs)
            nnnnnnnnnnnn1 = importlib.util.module_from_spec(toolbox_specs)
            # print("module: ", nnnnnnnnnnnn1)
            toolbox_specs.loader.exec_module(nnnnnnnnnnnn1)
            # print("导入成功 path_import(): ", nnnnnnnnnnnn1)
        else:
            nnnnnnnnnnnn1 =None
    return nnnnnnnnnnnn1
def get_url_list(path):
    all_list = []
    if os.path.exists(path):
        try:
            file = open(path, 'r', encoding='utf-8')
            for line in file:
                if 'http://' in line or 'https://' in line:
                    all_list.append(line)
            file.close()
            all_list2 = []
            for i in all_list:
                if i not in all_list2:
                    all_list2.append(i.replace('\n', '').strip())
            return list(filter(None, all_list2))  # 去除 none 和 空字符
        except:
            out_error(('Error:文件读取错误！'))
    else:

        url = path.split()[0]
        # print(url)
        if 'http://' in url or 'https://' in url:
            all_list.append(url)
        # print(all_list)
        return list(filter(None, all_list))  # 去除 none 和 空字符


def Judgement_parameter(Command_dict):
    # print(222)
    if "-la" in Command_dict or "-ls" in Command_dict:
        # -s 查询关键词的漏洞 -la # 列出某个cms的漏洞
        if len(sys.argv) <= 2:
            print(Fore.CYAN + (usage))
            sys.exit(1)
        else:
            list_cms_vuln()
            sys.exit(1)
    if "-u" in Command_dict or '-f' in Command_dict:
        if "-u" in Command_dict:
            url_list = get_url_list(Command_dict['-u'])
        elif '-f' in Command_dict:
            if not os.path.isfile(Command_dict['-f']):
                print(Fore.CYAN + (FLAGLET))
                out_error(("文件%s不存在！" % Command_dict['-f']))
                sys.exit(1)
            url_list = get_url_list(Command_dict['-f'])
        # print(url_list)
        if len(url_list) == 0:
            print(Fore.CYAN + (FLAGLET))
            out_error(('未获取到URL地址!'))
            sys.exit()

        global savefiletype
        global savefilename
        global timeout
        if '-html' in Command_dict:
            savefiletype = 'html'
            savefilename = Command_dict['-html']
        elif '-txt' in Command_dict:
            savefiletype = 'txt'
            savefilename = Command_dict['-txt']
        else:
            savefiletype = ''
            savefilename = ''
        if '-timeout' in Command_dict:
            timeout = int(Command_dict['-timeout'])
        else:
            timeout = 10

        # 漏洞利用
        if "-m" in Command_dict and Command_dict['-m'] == "exp":
            if "-v" in Command_dict:
                sql_data = "select * from vuln_poc where vuln_name like'%" + Command_dict['-v'] + "%' and isexp =1"
                # print(sql_data)
            else:
                out_error(('请指定一个EXP!'))
                sys.exit()
            if sql_data != "":
                exp_list = sql_search(sql_data,'dict')
                if len(exp_list) == 0:
                    print(Fore.CYAN + (FLAGLET))
                    out_error(("未查询到EXP！"))
                    sys.exit(1)
            if "-cmd" in Command_dict:
                cmd = Command_dict['-cmd']
                exp_start(url_list, exp_list[0], timeout, "cmd", cmd)
            elif "-shell" in Command_dict:
                shell = Command_dict['-shell']
                exp_start(url_list, exp_list[0], timeout, "shell", shell)
            else:
                cmd = "whoami"
                exp_start(url_list, exp_list[0], timeout, "cmd", cmd)

        # 漏洞扫描
        else:
            sql_data = ""
            if '-t' in Command_dict:
                threadnum = int(Command_dict['-t'])
            else:
                threadnum = 10
            if "-n" in Command_dict:
                sql_data = "select * from vuln_poc where vuln_name like '%" + Command_dict['-n'] + "%'"
            elif "-cms" in Command_dict:
                sql_data = "select * from vuln_poc where cms_name like '%" + Command_dict['-cms'] + "%'"
            else:
                # -u参数
                sql_data = "select * from vuln_poc"
            if sql_data != "":
                poc_list = sql_search(sql_data,'dict')
                if len(poc_list) == 0:
                    print(Fore.CYAN + (FLAGLET))
                    out_error(("未查询到POC！"))
                    sys.exit(1)
                check_vuln(url_list, poc_list, threadnum)
            else:
                print(Fore.CYAN + (FLAGLET))
                sys.exit(1)
    else:
        print(Fore.CYAN + (FLAGLET))
        out_error(("Error:请指定URL地址!"))


def output(vuln_info):
    # 保存到文件
    if savefiletype == 'txt':
        vuln_info = "\nURL:" + vuln_info[0] + "\n漏洞名称:" + vuln_info[1] + "\n漏洞编号:" + vuln_info[7] + "\n测试结果:" + \
                    vuln_info[2] + "\n漏洞描述:" + vuln_info[3] + "\n漏洞来源:" + vuln_info[4] + "\n插件路径:" + vuln_info[
                        5] + "\nPayload:" + vuln_info[6]
        print(vuln_info)
        save = open(savefilename, 'a', encoding='utf-8')
        save.write(vuln_info)
        save.close()
    if savefiletype == 'html':
        save = open(savefilename, 'a', encoding='gbk')
        save.write('''  
        <script>add_table("%s","%s","%s","%s","%s","%s","%s","%s");</script>
        ''' % (
            vuln_info[0], vuln_info[1], vuln_info[7], vuln_info[3], vuln_info[4], vuln_info[5], vuln_info[6],
            vuln_info[2]))
        save.close()


def out_info(text):
    now_time = time.strftime("%H:%M:%S", time.localtime())
    print(Fore.MAGENTA + "[" + now_time + "]" + Fore.CYAN + " [INFO] " + Fore.WHITE + text)


def out_success(text):
    now_time = time.strftime("%H:%M:%S", time.localtime())
    print(Fore.MAGENTA + "[" + now_time + "]" + Fore.GREEN + " [Success] " + Fore.GREEN + text)

def out_prompt(text):
    now_time = time.strftime("%H:%M:%S", time.localtime())
    print(Fore.MAGENTA + "[" + now_time + "]" + Fore.LIGHTYELLOW_EX + " [INFO] " + Fore.WHITE + text)


def out_error(text):
    now_time = time.strftime("%H:%M:%S", time.localtime())
    print(Fore.MAGENTA + "[" + now_time + "]" + Fore.RED + " [Error] " + Fore.WHITE + text)




if __name__ == '__main__':
    init(autoreset=False)
    # 需要python3 版本
    if sys.version_info < (3, 0):
        sys.stdout.write("Sorry, FrameScan requires Python 3.x\n")
        sys.exit(1)
    # 获取返回的参数和值
    if len(sys.argv) == 2 and sys.argv[1] == "-r":
        Reload_POC()
        sys.exit(1)
    if not os.path.isfile(DB_NAME):
        print(Fore.CYAN + (FLAGLET))
        out_error(("数据库文件不存在，请执行-r重新加载数据文件！"))
        sys.exit(1)
    Command_dict = getparameter()
    # 测试输出
    # for key in Command_dict:
    #     print(key + ':' + Command_dict[key])
    Judgement_parameter(Command_dict)
