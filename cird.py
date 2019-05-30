import socket
import struct

def _ip_string_to_long(ip):
    return struct.unpack('!I', socket.inet_pton(socket.AF_INET, ip))[0]

class CIRD(object):

    def __init__(self, prefix, mask):
        self._raw_prefix = _ip_string_to_long(prefix)
        self._raw_mask = _ip_string_to_long('.'.join([str((0xffffffff << (32 - mask) >> i) & 0xff)
                                                     for i in [24, 16, 8, 0]]))

    def match(self, raw_ip):
        return self._raw_prefix == (raw_ip & self._raw_mask)

reversed_addresses = (
    CIRD('0.0.0.0', 8),
    CIRD('10.0.0.0', 8),
    CIRD('100.64.0.0', 10),
    CIRD('127.0.0.0', 8),
    CIRD('169.254.0.0', 16),
    CIRD('172.16.0.0', 12),
    CIRD('192.0.0.0', 24),
    CIRD('192.0.2.0', 24),
    CIRD('192.0.2.0', 24),
    CIRD('192.88.99.0', 24),
    CIRD('192.168.0.0', 16),
    CIRD('198.18.0.0', 15),
    CIRD('198.51.100.0', 24),
    CIRD('203.0.113.0', 24),
    CIRD('224.0.0.0', 4),
    CIRD('240.0.0.0', 4),
    CIRD('255.255.255.255', 32)
)

def is_reversed_address(ip):
    for address in reversed_addresses:
        if address.match(ip):
            return True
    return False
