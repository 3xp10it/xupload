## About

xupload是一个用于自动测试上传功能是否可上传webshell的工具

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

## eg


<iframe 
    width="800" 
    height="450" 
    src="http://oiqwnrsx4.bkt.clouddn.com/xupload.mov"
    frameborder="0" 
    allowfullscreen>
</iframe>

