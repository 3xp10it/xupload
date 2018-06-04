## About

xupload是一个用于自动测试上传功能是否可上传webshell的工具

## Disclaimer

[!] legal disclaimer: Usage of xupload.py for attacking targets without prior mutual consent is illegal.It is the end user's responsibility to obey all applicable local, state and federal laws.Developers assume no liability and are not responsible for any misuse or damage caused by this program.

## Usage

```
python3 xupload.py -h

usage: xupload.py [-h] [-u URL] [--cookie COOKIE] --suffix SUFFIX [--batch]
                  [--delay DELAY] [--force-ssl] [-r R]

xupload.py is a program that automates the testing of uploading functionality.
If xupload.py does not successfully upload webshell, try more tips at:
1.http://3xp10it.cc/web/2016/08/12/fckeditor各版本绕过/
2.https://paper.seebug.org/219/
3.http://www.owasp.org.cn/OWASP_Training/Upload_Attack_Framework.pdf
4.https://thief.one/2016/09/22/上传木马姿势汇总-欢迎补充/

optional arguments:
  -h, --help         show this help message and exit
  -u URL, --url URL  The target url which has upload function
  --cookie COOKIE    HTTP Cookie header value
  --suffix SUFFIX    The web server's script type: 'php','asp','aspx','jsp'
  --batch            Never ask for user input, use the default behavior
  --delay DELAY      Delay in seconds between each HTTP request
  --force-ssl        Force usage of SSL/HTTPS
  -r R               Load HTTP request from a file
```

eg.

`python3 xupload.py -u http://192.168.8.190/vulnerabilities/upload/ --cookie "PHPSESSID=v7rebkn2dn8ln1ebuqfhjf00s4;security=low" --batch`


## Attention

`-r`参数是在xupload.py无法自动识别url对应的html中上传表单时要用到的参数(一般通过插件实现上传功能的url无法通过xupload.py自动获取上传表单),用于指定一个http上传文件时拦截到的请求包,如果url是https开头则需要指定`--force-ssl`.

<a target="_blank" href="http://oiqwnrsx4.bkt.clouddn.com/xupload.mov">视频示例</a>
