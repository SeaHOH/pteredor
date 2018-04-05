#!/usr/bin/env python
# coding:utf-8

# A tool to help evaluate the teredo servers.
# Thanks XndroidDev
# Author: SeaHOH <seahoh@gmail.com>
# Version: 0.0.1
# Compatible: Python 2.7 & 3.4 & 3.5 & 3.6
# References:
#   https://tools.ietf.org/html/rfc4380 5.1 5.2
#   https://tools.ietf.org/html/rfc4861 4.1 4.2
#   https://tools.ietf.org/html/rfc2460 8.1
#   https://github.com/XndroidDev/Xndroid/blob/master/fqrouter/manager/teredo.py

import sys

if sys.version_info[0] < 3:
    import win_inet_pton

import os
import socket
import random
import struct
import collections
import time
import logging
import select
import errno

try:
    import queue
except:
    import Queue as queue

try:
    import thread
except:
    import _thread as thread

try:
    raw_input
except:
    raw_input = input

logger = logging.getLogger('pteredor')


teredo_timeout = 4
teredo_port = 3544
link_local_addr = 'fe80::ffff:ffff:ffff'
all_router_multicast = 'ff02::2'
teredo_server_list = [
    'teredo.remlab.net',
    'teredo2.remlab.net',
    'teredo-debian.remlab.net',
    'teredo.ngix.ne.kr',
    'teredo.trex.fi',
    'teredo.iks-jena.de',
    'teredo.autotrans.consulintel.com',
    'teredo.managemydedi.com',
    'teredo.ipv6.microsoft.com',
    'win10.ipv6.microsoft.com',
    'win1710.ipv6.microsoft.com',
    'win1711.ipv6.microsoft.com'
    ]

def creat_rs_nonce():
    return struct.pack('d', random.randint(0, 1<<62))

def creat_ipv6_rs_msg(checksum=None):
    return struct.pack('!2BH4x', 133, 0, checksum or 0)

def in_checksum(data):
    n = len(data)
    f = '%dH' % (n // 2)
    if n % 2:
        f += 'B'
    s = sum(struct.unpack(f, data))
    while (s >> 16):
        s = (s & 0xffff) + (s >> 16)
    s = ~s & 0xffff
    return socket.ntohs(s)

class teredo_rs_packet(object):

    rs_src = socket.inet_pton(socket.AF_INET6, link_local_addr)
    rs_dst = socket.inet_pton(socket.AF_INET6, all_router_multicast)
    _icmpv6_rs_msg = creat_ipv6_rs_msg()

    def __init__(self, nonce=None):
        self.nonce = nonce or creat_rs_nonce()
        self.rs_src = bytearray(self.rs_src)
        self.teredo_header = self.creat_teredo_header()

    def creat_teredo_header(self):
        return struct.pack('!H2x8sx', 1, self.nonce)

    def creat_ipv6_pseudo_header(self):
        return struct.pack('!16s16sI3xB',
                           bytes(self.rs_src),
                           self.rs_dst,
                           58,
                           len(self._icmpv6_rs_msg)
                           )

    def creat_rs_packet(self, cone=None):
        self.rs_src[8] = 0x80 if cone else 0
        pseudo_header = self.creat_ipv6_pseudo_header()
        checksum = in_checksum(self._icmpv6_rs_msg + pseudo_header)
        rs_msg = creat_ipv6_rs_msg(checksum)
        return self.teredo_header + struct.pack('!B4x3B16s16s',
                                                0x60,
                                                len(rs_msg),
                                                58,
                                                255,
                                                bytes(self.rs_src),
                                                self.rs_dst
                                                ) + rs_msg

    @property
    def type_cone(self):
        if not hasattr(self, '_type_cone'):
            self._type_cone = self.creat_rs_packet(True)
        return self._type_cone

    @property
    def type_restricted(self):
        if not hasattr(self, '_type_restricted'):
            self._type_restricted = self.creat_rs_packet()
        return self._type_restricted

def get_sock():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            port = random.randint(1025, 5000)
            print('try bind local port:', port)
            sock.bind(('0.0.0.0', port))
            return sock
        except socket.error as e:
            if e.args[0] == errno.EADDRINUSE:
                pass

def is_ipv4(ip):
    try:
        socket.inet_aton(ip)
    except:
        return False
    else:
        return True

def resolve(host):
   try:
       return socket.gethostbyname_ex(host)[-1]
   except:
       return []

def ip2int(ip):
    return struct.unpack('>I', socket.inet_aton(ip))[0]

def remove_same_server(server_ip_list):
    logger.debug('input ip: %%' % server_ip_list)
    cleared_list = set()
    while server_ip_list:
        ip1 = server_ip_list.pop()
        _ip1 = ip2int(ip1)
        for ip2 in server_ip_list:
            if ip1 == ip2:
                continue
            _ip2 = ip2int(ip2)
            if _ip1 ^ _ip2 == 1:
                if _ip1 > _ip2:
                    ip1 = ip2
                else:
                    continue
        cleared_list.add(ip1)
    logger.debug('cleared ip: %s' % cleared_list)
    return cleared_list

def str2hex(str):
    str = bytearray(str)
    h = ['']
    for c in str:
        if c > 0xf:
            h.append(hex(c)[2:])
        else:
            h.append('0' + hex(c)[2:])
    return '\\x'.join(h)

class deque(collections.deque):

    def put(self, v):
        self.append(v)

    def get(self):
        try:
            return self.popleft()
        except:
            return None

class default_prober_dict(dict):

    def __init__(self):
        self['nonce'] = None
        self['addr'] = None
        self['rs_packet'] = None
        self['ra_packets'] = deque()

class teredo_prober(object):

    _stoped = None
    nat_type = 'null'
    qualified = False
    rs_cone_flag = 1
    timeout = teredo_timeout
    teredo_port = teredo_port

    def __init__(self, server_list, probe_nat_type=True):
        self.teredo_sock = get_sock()
        self.prober_dict = collections.defaultdict(default_prober_dict)
        self.ip2server = collections.defaultdict(list)
        server_ip_list = []
        if isinstance(server_list, str):
            server_list = [server_list]
        for server in server_list:
            if is_ipv4(server):
                server_ip_list.append(server)
            else:
                ip_list = resolve(server)
                for ip in ip_list:
                    self.ip2server[ip].append(server)
                server_ip_list += ip_list
        self.server_ip_list = remove_same_server(server_ip_list)
        if len(self.server_ip_list) < 2:
            print('Need input more teredo servers, now is %d.' % len(self.server_ip_list))
        if len(self.server_ip_list) < 1:
            raise Exception('Servers could not be resolved, %r.' % server_list)
        thread.start_new_thread(self.receive_loop, ())
        if probe_nat_type:
            self.nat_type = self.nat_type_probe()

    def unpack_indication(self, data):
        return struct.unpack('!2s4s', data[2:8])

    def handle_ra_packet(self, ipv6_pkt):
        server_ip = socket.inet_ntoa(ipv6_pkt[76:80])
        cone_flag = bytearray(ipv6_pkt)[32] >> 7 & 1
        logger.debug('ipv6_pkt ; RA_cone = %s\nsrc:%s\ndst:%s' % (
                cone_flag,
                str2hex(ipv6_pkt[8:24]),
                str2hex(ipv6_pkt[24:40])))
        return server_ip, cone_flag

    def receive_ra_packet(self):
        data, addr = self.teredo_sock.recvfrom(10240)
        ip, port = addr
        if port != self.teredo_port or len(data) < 40:
            logger.debug('ipv6_pkt ;1 drop:\n%s' % str2hex(data))
            return
        auth_pkt = indicate_pkt = ipv6_pkt = None
        if data[0:2] == b'\x00\x01':
            auth_len = 13 + sum(struct.unpack('2B', data[2:4]))
            auth_pkt = data[0:auth_len]
            if data[auth_len:auth_len + 2] == b'\x00\x00':
                indicate_pkt = data[auth_len:auth_len + 8]
                ipv6_pkt = data[auth_len + 8:]
        if (auth_pkt is None or
            indicate_pkt is None or
            ipv6_pkt is None or
            bytearray(ipv6_pkt)[0] & 0xf0 != 0x60 or
            bytearray(ipv6_pkt)[40] != 134 or
            struct.unpack('!H', ipv6_pkt[4:6])[0] + 40 != len(ipv6_pkt)
            ):
            logger.debug('ipv6_pkt ;2 drop:\n%s' % str2hex(data))
            return
        server_ip, ra_cone_flag = self.handle_ra_packet(ipv6_pkt)
        logger.debug('server ip: %s ; received ip: %s' % (server_ip, ip))
        if auth_pkt[4:12] != self.prober_dict[server_ip]['rs_packet'].nonce:
            logger.debug('ipv6_pkt ;3 drop:\n%s' % str2hex(data))
            return
        ra_packet = {'addr': (server_ip, port),
                     'nonce': auth_pkt[4:12],
                     'qualify': (ra_cone_flag, indicate_pkt)
                     }
        self.prober_dict[server_ip]['ra_packets'].put(ra_packet)

    def receive_loop(self):
        while not self._stoped:
            try:
                rd, _, _ = select.select([self.teredo_sock], [], [], 0.5)
                if rd and not self._stoped:
                    self.receive_ra_packet()
            except Exception as e:
                logger.exception('receive procedure fail once: %r', e)
                pass

    def send_rs_packet(self, rs_packet, dst_ip):
        rs_packet = rs_packet.type_cone if self.rs_cone_flag else rs_packet.type_restricted
        logger.debug('send ; RS_cone = %s\n%s' % (self.rs_cone_flag, str2hex(rs_packet)))
        self.teredo_sock.sendto(rs_packet, (dst_ip, self.teredo_port))

    def qualify(self, dst_ip):
        rs_packet = self.prober_dict[dst_ip]['rs_packet']
        if rs_packet is None:
            self.prober_dict[dst_ip]['rs_packet'] = rs_packet = teredo_rs_packet()
        self.send_rs_packet(rs_packet, dst_ip)

        begin_recv = time.time()
        while time.time() < self.timeout + begin_recv:
            ra_packet = self.prober_dict[dst_ip]['ra_packets'].get()
            if (ra_packet and
                ra_packet['nonce'] == rs_packet.nonce and
                ra_packet['addr'] == (dst_ip, self.teredo_port)
                ):
                return ra_packet['qualify']
            time.sleep(0.01)

    def qualify_loop(self, dst_ip):
        for i in range(3):
            try:
                return self.qualify(dst_ip)
            except Exception as e:
                logger.exception('qualify procedure fail once: %r', e)

    def nat_type_probe(self):
        print('Starting probe NAT type...')
        server_ip_list = self.server_ip_list.copy()
        self.rs_cone_flag = 1
        for server_ip in server_ip_list:
            ra_qualify = self.qualify_loop(server_ip)
            if ra_qualify:
                break
        if ra_qualify is None:
            self.rs_cone_flag = 0
            while server_ip_list:
                server_ip = server_ip_list.pop()
                ra_qualify = self.qualify_loop(server_ip)
                if ra_qualify:
                    break
        if ra_qualify is None:
            self.qualified = True
            return 'offline'
        ra_cone_flag, first_indicate = ra_qualify
        if ra_cone_flag:
            self.qualified = True
            return 'cone'
        ra_qualify = None
        for server_ip in  server_ip_list:
            ra_qualify = self.qualify_loop(server_ip)
            if ra_qualify:
                break
        self.qualified = True
        if ra_qualify is None:
            self.last_server_ip = server_ip
            return 'unknown'
        ra_cone_flag, second_indicate = ra_qualify
        if first_indicate == second_indicate:
            return 'restricted'
        else:
            return 'symmetric'

    def _eval_servers(self, server_ip, queue_obj):
        start = time.time()
        ra_qualify = self.qualify_loop(server_ip)
        cost = int((time.time() - start) * 1000)
        queue_obj.put((bool(ra_qualify), self.ip2server[server_ip], server_ip, cost))

    def eval_servers(self):
        eval_list = []
        if not self.qualified:
            self.nat_type = self.nat_type_probe()
        if self.nat_type in ('symmetric', 'offline'):
            print('This device can not use teredo tunnel, the NAT type is %s!' % prober.nat_type)
            return eval_list
        print('Starting evaluate servers...')
        self.clear()
        queue_obj = queue.Queue()
        for server_ip in self.server_ip_list:
            thread.start_new_thread(self._eval_servers, (server_ip, queue_obj))
        for _ in self.server_ip_list:
            eval_list.append(queue_obj.get())
        return eval_list

    def close(self):
        self._stoped = True
        self.clear()
        if self.teredo_sock:
            self.teredo_sock.close()
            self.teredo_sock = None

    def clear(self):
        for server_ip in self.server_ip_list:
            self.prober_dict.pop(server_ip, None)
        

def main(*args):
    server_list = [] + teredo_server_list
    for arg in args:
        if isinstance(arg, str):
            server_list.append(arg)
        elif isinstance(arg, list):
            server_list += arg
        elif isinstance(arg, tuple):
            server_list += list(arg)
    prober = teredo_prober(server_list)
    recommend = None
    if prober.nat_type == 'unknown':
        print('We can not judge the NAT type.')
        recommend = prober.last_server_ip
    elif prober.nat_type in ('symmetric', 'offline'):
        print('This device can not use teredo tunnel, the NAT type is %s!' % prober.nat_type)
    elif prober.nat_type in ('cone', 'restricted'):
        print('The NAT type is %s.' % prober.nat_type)
        qualified_list = prober.eval_servers()
        for qualified, server, server_ip, cost in qualified_list:
            print('%s %s %sms' % (server_ip, server, cost))
        for qualified, server, server_ip, cost in qualified_list:
            if qualified:
                recommend = server
                break
    prober.close()
    return recommend

def test():
    logging.basicConfig(level=logging.DEBUG)
    blank_rs_packet = bytearray(
        b'\x00\x01\x00\x00\x8a\xde\xb0\xd0\x2e\xea\x0b\xfc\x00'
        b'\x60\x00\x00\x00\x00\x08\x3a\xff\xfe\x80\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\xff\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x02\x85\x00\x7d\x37\x00\x00\x00\x00')
    nonce = creat_rs_nonce()
    blank_rs_packet[4:12] = nonce
    assert(teredo_rs_packet(nonce).type_restricted == bytes(blank_rs_packet))

    server_list = ['teredo.remlab.net','win1710.ipv6.microsoft.com']
    prober = teredo_prober(server_list, probe_nat_type=False)
    prober.timeout = 4
    server_ip_list = prober.server_ip_list.copy()
    server_ip = server_ip_list.pop()
    for _ in range(2):
        print(prober.qualify_loop(server_ip))
        prober.rs_cone_flag = prober.rs_cone_flag ^ 1
    server_ip = server_ip_list.pop()
    for _ in range(2):
        print(prober.qualify_loop(server_ip))
        prober.rs_cone_flag = prober.rs_cone_flag ^ 1
#    prober.close()

    print(main())
    raw_input('Press enter to over...')
    sys.exit(0)

runas_vbs = '''
If WScript.Arguments.length = 0 Then
  Dim objShell
  Set objShell = CreateObject("Shell.Application")
  objShell.ShellExecute "wscript.exe", Chr(34) & WScript.ScriptFullName & Chr(34) & " uac", "", "runas", 1
  Set objShell = NoThing
  WScript.quit
End If

Dim Wsr
Set Wsr = WScript.CreateObject("WScript.Shell")
Wsr.Run "%s", 0, True
Set Wsr = NoThing

Dim fso
Set fso = CreateObject("scripting.FileSystemObject")
fso.DeleteFile WScript.ScriptFullName
Set fso = NoThing

WScript.quit
'''

local_ip_startswith = tuple(
    ['127', '192.168', '10.'] +
    ['100.%d.' % (64 + n) for n in range(1 << 6)] +
    ['172.%d.' % (16 + n) for n in range(1 << 4)]
    )

if os.name == 'nt':
    try:
        socket.socket(socket.AF_INET, socket.SOCK_RAW)
        runas = os.system
    except:
        def runas(cmd):
            temp = str(int(random.random() * 10 ** 8)) + '.vbs'
            with open(temp, 'w') as f:
                f.write(runas_vbs % cmd)
            os.system(temp)

if '__main__' == __name__:    
#    test()
    if os.name == 'nt':
        if raw_input('Stop teredo tunnel for run prober, Y/N? ').lower() == 'y':
            runas('netsh interface teredo set state disable')
            time.sleep(1)
            print(os.system('netsh interface teredo show state'))
    args = sys.argv[1:]
    recommend = main(*args)
    if recommend:
        print('\nThe recommend server is %r.' % recommend)
        if os.name == 'nt':
            if raw_input('Do you want to set recommend teredo server, Y/N? ').lower() == 'y':
                ip = [a for a in os.popen('route print').readlines() if ' 0.0.0.0 ' in a][0].split()[-2]
                client = 'enterpriseclient' if ip.startswith(local_ip_startswith) else 'client'
                runas('netsh interface teredo set state %s %s.' % (client, recommend.pop()))
                time.sleep(1)
                print(os.system('netsh interface teredo show state'))
    raw_input('Press enter to over...')
