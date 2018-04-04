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

try:
    import queue
except:
    import Queue as queue

try:
    import thread
except:
    import _thread as thread
Lock = thread.allocate_lock

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

    def __init__(self):
        self.lock = Lock()

    def put(self, v):
        with self.lock:
            return self.append(v)

    def get(self):
        with self.lock:
            return self.popleft() if self else None

class default_prober_dict(dict):

    def __init__(self):
        self.lock = Lock()
        self['nonce'] = None
        self['pkt'] = None
        self['addr'] = None
        self['rs_packet'] = None
        self['ra_packets'] = deque()

    def __setitem__(self, k, v):
        with self.lock:
            dict.__setitem__(self, k, v)

teredo_prober_dict = collections.defaultdict(default_prober_dict)

class teredo_prober(object):

    _stoped = None
    nat_type = 'null'
    qualified = False
    rs_cone_flag = 1
    timeout = teredo_timeout
    teredo_port = teredo_port
    prober_dict = teredo_prober_dict

    def __init__(self, sock, server_list, probe_nat_type=True):
        self.teredo_sock = sock
        server_ip_list = []
        self.ip2server = {}
        if isinstance(server_list, str):
            server_list = [server_list]
        for server in server_list:
            if is_ipv4(server):
                server_ip_list.append(server)
            else:
                ip_list = resolve(server)
                for ip in ip_list:
                    self.ip2server[ip] = server
                server_ip_list += ip_list
        self.server_ip_list = set(server_ip_list)
        if len(self.server_ip_list) < 2:
            print('Need input more teredo servers, now is %d.' % len(self.server_ip_list))
        if len(self.server_ip_list) < 1:
            raise Exception('Servers could not be resolved, %r.' % server_list)
        thread.start_new_thread(self.receive_loop, ())
        if probe_nat_type:
            self.nat_type = self.nat_type_probe()

    def unpack_indication(self, data):
        return struct.unpack('!2s4s', data[2:8])

    def handle_ra_packet(self, indicate_pkt, ipv6_pkt):
        obfuscated_port, obfuscated_ip = self.unpack_indication(indicate_pkt)
        flag = bytearray(ipv6_pkt)[16] >> 7 & 1
        logger.debug('ipv6_pkt ; RA_cone = %s\nobfuscated: %s:%s\nsrc:%s\ndst:%s' % (
                flag,
                str2hex(obfuscated_ip),
                str2hex(obfuscated_port),
                str2hex(ipv6_pkt[8:24]),
                str2hex(ipv6_pkt[24:40])))
        return flag, (obfuscated_port, obfuscated_ip)

    def receive_ra_packet(self):
        data, addr = self.teredo_sock.recvfrom(10240)
        ip, port = addr
        if (ip not in self.server_ip_list or
            port != self.teredo_port or
            len(data) < 40
            ):
            logger.debug('ipv6_pkt ; drop:\n%s' % str2hex(data))
            return
        auth_pkt = indicate_pkt = ipv6_pkt = None
        if len(data) < 40:
            logger.debug('ipv6_pkt ; drop:\n%s' % str2hex(data))
            return
        if data[0:2] == b'\x00\x01':
            auth_len = 13 + sum(struct.unpack('2B', data[2:4]))
            auth_pkt = data[0:auth_len]
            if data[auth_len:auth_len + 2] == b'\x00\x00':
                indicate_pkt = data[auth_len:auth_len + 8]
                ipv6_pkt = data[auth_len + 8:]
        if (auth_pkt is None or
            indicate_pkt is None or
            auth_pkt[4:12] != self.prober_dict[ip]['rs_packet'].nonce or
            bytearray(ipv6_pkt)[0] & 0xf0 != 0x60 or
            struct.unpack('!H', ipv6_pkt[4:6])[0]+40 != len(ipv6_pkt)
            ):
            logger.debug('ipv6_pkt ; drop:\n%s' % str2hex(data))
            return
        ra_packet = {'addr': addr,
                     'nonce': auth_pkt[4:12],
                     'qualify': self.handle_ra_packet(indicate_pkt, ipv6_pkt)
                     }
        self.prober_dict[ip]['ra_packets'].put(ra_packet)

    def receive_loop(self):
        try:
            while not self._stoped:
                rd, _, _ = select.select([self.teredo_sock], [], [], 0.5)
                if rd and not self._stoped:
                    self.receive_ra_packet()
        except Exception as e:
            logger.exception(e)
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
        ra_cone_flag, first_addr = ra_qualify
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
        ra_cone_flag, second_addr = ra_qualify
        if first_addr == second_addr:
            return 'restricted'
        else:
            return 'symmetric'

    def _eval_servers(self, server_ip, queue_obj):
        start = time.time()
        ra_qualify = self.qualify_loop(server_ip)
        cost = int((time.time() - start) * 1000)
        queue_obj.put((bool(ra_qualify), self.ip2server[server_ip], server_ip, cost))

    def eval_servers(self):
        if not self.qualified:
            self.nat_type = self.nat_type_probe()
        if self.nat_type in ('symmetric', 'offline'):
            print('This device can not use teredo tunnel, the NAT type is %s!' % prober.nat_type)
            return
        print('Starting evaluate servers...')
        self.clear()
        queue_obj = queue.Queue()
        eval_list = []
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
    server_list = teredo_server_list + list(args)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 0))
    prober = teredo_prober(sock, server_list)
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
            print('%s %s %sms' % (server, server_ip, cost))
        for qualified, server, server_ip, cost in qualified_list:
            if qualified:
                recommend = server
                break
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
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 0))
    prober = teredo_prober(sock, server_list, probe_nat_type=False)
    prober.timeout = 4
    server_ip_list = prober.server_ip_list.copy()
    server_ip = server_ip_list.pop()
    for _ in range(2):
        print(prober.qualify_loop(server_ip))
        prober.rs_cone_flag = prober.rs_cone_flag ^ 1
    server_ip_list = prober.server_ip_list.copy()
    server_ip = server_ip_list.pop()
    for _ in range(2):
        print(prober.qualify_loop(server_ip))
        prober.rs_cone_flag = prober.rs_cone_flag ^ 1
    prober.close()

    print(main())
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

def runas(cmd):
    temp = os.path.join(os.path.dirname(__file__), str(int(random.random()*10**8))) + '.vbs'
    with open(temp, 'w') as f:
        f.write(runas_vbs % cmd)
    os.system(temp)

if '__main__' == __name__:    
#    test()
    try:
        raw_input
    except:
        raw_input = input
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
                runas('netsh interface teredo set state client %s.' % recommend)
                time.sleep(1)
                print(os.system('netsh interface teredo show state'))
