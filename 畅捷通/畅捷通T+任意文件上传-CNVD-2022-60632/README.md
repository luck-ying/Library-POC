# 使用说明

由于畅捷通整套程序用了预编译，所以需要将shell进行预编译处理

CMD 命令执行
`C:\WINDOWS\Microsoft.NET\Framework\v2.0.50727\aspnet_compiler.exe -v / -p (木马文件目录) (生成预编译文件目录) -fixednames`

<image src="images/1.png">

将bin文件中的两个文件移动到poc目录下的bin文件中
<image src="images/2.png">

也可以使用bin中自带的哥斯拉shell
<image src="images/3.png">

然后运行poc即可

