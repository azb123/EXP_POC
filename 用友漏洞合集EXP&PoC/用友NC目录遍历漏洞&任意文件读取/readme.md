## 用友NC目录遍历漏洞&任意文件读取



### POC使用&效果图

```
usage: yonyouERP_NC_RAF.py [-h] [-f FILE] [-t THREAD] [-T TIMEOUT] [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  The url file, default is ./url.txt
  -t THREAD, --thread THREAD
                        Number of thread, default is 32
  -T TIMEOUT, --timeout TIMEOUT
                        request timeout(default 3)
  -o OUTPUT, --output OUTPUT
                        Vuln url output file, default is 2022-01-12, 20:00:13.txt
```

![image-20220112195939851](.\img\image-20220112195939851.png)



### EXP使用&效果图

```
usage: yonyouEDR_NC_RAF_EXP.py [-h] [-u URL] [-t TIMEOUT]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     The target address,(ip:port) or url
  -t TIMEOUT, --timeout TIMEOUT
                        request timeout(default 3)
```

![image-20220112204650178](.\img\image-20220112204650178.png)