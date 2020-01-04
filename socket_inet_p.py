"""Implement inet_pton and inet_ntop in python."""

import socket
from socket import error, AF_INET, AF_INET6, inet_aton, inet_ntoa
from struct import pack, unpack


try:
    _compat_str_types = (str, unicode)
except NameError:
    _compat_str_types = (str, )

def inet_pton(family, ip_string):
    if family == AF_INET:
        # inet_aton() also accepts strings like '1', '127.1', some also trailing
        # data like '127.0.0.1 whatever', but inet_pton() does not.
        ip_packed = inet_aton(ip_string)
        if inet_ntoa(ip_packed) == ip_string:
            # Only accept injective ip strings
            return ip_packed
        raise error("illegal IP address string passed to inet_pton")

    if family == AF_INET6:
        if not isinstance(ip_string, _compat_str_types):
            raise TypeError("inet_pton() argument 2 must be string, not %s"
                            % type(ip_string).__name__)
        try:
            parts = _explode_ip_string(ip_string).split(":")
            if len(parts) == 7:
                return pack("!8H", *[int(i, 16) for i in parts])
            else:
                ip4 = inet_aton(parts.pop())
                ip6 = pack("!6H", *[int(i, 16) for i in parts])
                return ip6 + ip4
        except Exception:
            pass
        raise error("illegal IP address string passed to inet_pton")

    raise error("unknown address family %r" % family)

def inet_ntop(family, ip_packed):
    if family == AF_INET:
        return inet_ntoa(ip_packed)

    if family == AF_INET6:
        if not isinstance(ip_packed, (bytes, bytearray)):
            raise TypeError("inet_ntop() argument 2 must be %s, not %s"
                            % (bytes.__name__, type(ip_string).__name__))
        try:
            hextets = ["%x" % i for i in unpack("!8H", ip_packed)]
            return ":".join(_compress_hextets(hextets))
        except Exception:
            pass
        raise error("illegal IP address string passed to inet_ntop")

    raise error("unknown address family %r" % family)


def _explode_ip_string(ip_string):
    assert 1 < len(ip_string) < 40, 0
    if ip_string[:1] == ":":
        assert ip_string[:2] == "::", 0
        ip_string = "0" + ip_string
    if ip_string[-1:] == ":":
        assert ip_string[-2:] == "::", 0
        ip_string = ip_string + "0"

    d_clns = ip_string.count("::")
    assert d_clns == 0 or d_clns == 1 and ip_string.count(":::") == 0, 0

    clns = ip_string.count(":")
    m_clns = 6 if "." in ip_string[-4:] else 7
    if d_clns:
        assert 1 < clns <= m_clns, 0
        exploded = "0".join([":"] * (2 + m_clns - clns))
        ip_string = ip_string.replace("::", exploded, 1)
    else:
        assert clns == m_clns, 0

    return ip_string

# Copy from ipaddress module
def _compress_hextets(hextets):
    best_doublecolon_start = -1
    best_doublecolon_len = 0
    doublecolon_start = -1
    doublecolon_len = 0
    for index, hextet in enumerate(hextets):
        if hextet == "0":
            doublecolon_len += 1
            if doublecolon_start == -1:
                # Start of a sequence of zeros.
                doublecolon_start = index
            if doublecolon_len > best_doublecolon_len:
                # This is the longest sequence of zeros so far.
                best_doublecolon_len = doublecolon_len
                best_doublecolon_start = doublecolon_start
        else:
            doublecolon_len = 0
            doublecolon_start = -1

    if best_doublecolon_len > 1:
        best_doublecolon_end = (best_doublecolon_start + best_doublecolon_len)
        # For zeros at the end of the address.
        if best_doublecolon_end == len(hextets):
            hextets += [""]
        hextets[best_doublecolon_start:best_doublecolon_end] = [""]
        # For zeros at the beginning of the address.
        if best_doublecolon_start == 0:
            hextets = [""] + hextets

    return hextets

if not hasattr(socket, "inet_pton"):
    socket.inet_pton = inet_pton

if not hasattr(socket, "inet_ntop"):
    socket.inet_ntop = inet_ntop
