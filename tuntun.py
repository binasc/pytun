import copy
import random
import re
import socket
import struct
import time
import uuid

from watchdog.events import PatternMatchingEventHandler
from watchdog.observers import Observer

import loglevel
from dns import DNSRecord
from dns import QTYPE
from packet import Packet

_logger = loglevel.get_logger('tuntun')
_logger.setLevel(loglevel.DEFAULT_LEVEL)


def ip_string_to_long(ip):
    return struct.unpack('!I', socket.inet_pton(socket.AF_INET, ip))[0]


FAST_DNS_SERVER = ip_string_to_long('119.29.29.29')
CLEAN_DNS_SERVER = ip_string_to_long('8.8.8.8')
TEST_DNS_SERVER = ip_string_to_long('35.201.154.22')


global_proxy = True
poisoned_domain = set()
blocked_domain = set()
blocked_address = set()
blocked_address_last_sync = current = time.time()
normal_address = set()
modified_query = {}


def restore_blocked_address():
    try:
        fp = open('blocked_ip.txt', 'rb')
        content = fp.read()
        for i in range(0, len(content), 4):
            blocked_address.add(struct.unpack('!I', content[i: i + 4])[0])
        _logger.info('Update %d blocked ips', len(content) / 4)
        fp.close()
    except IOError as e:
        _logger.warning("Failed to open blocked_ip.txt: %s", str(e))
        return False


restore_blocked_address()


def update_blocked_address(address):
    blocked_address.update(address)
    now = time.time()
    global blocked_address_last_sync
    if now - blocked_address_last_sync > 60:
        try:
            fp = open('blocked_ip.txt', 'wb')
        except IOError as e:
            _logger.warning("Failed to write blocked_ip.txt: %s", str(e))
            return
        for ip in blocked_address:
            fp.write(struct.pack('!I', ip))
        fp.close()
        _logger.debug("Synced %d blocked ip", len(blocked_address))
        blocked_address_last_sync = now


def update_blocked_domain():
    global blocked_domain
    try:
        fp = open('blocked.txt', 'r')
    except IOError as e:
        _logger.warning("Failed to open blocked.txt: %s", str(e))
        return False
    new_blocked_domain = set()
    for line in fp.readlines():
        line = line.strip()
        if len(line) == 0 or line.startswith('#'):
            continue
        new_blocked_domain.add(line)
    fp.close()
    blocked_domain = new_blocked_domain
    _logger.info('Updated %d blocked items', len(blocked_domain))


def update_poisoned_domain(domain):
    parts = domain.split('.')
    if len(parts) > 0 and len(parts[-1].strip()) == 0:
        parts = parts[: -1]
    if len(parts[-1]) == 2:
        name = '.'.join(parts[-3:]) + '.'
    else:
        name = '.'.join(parts[-2:]) + '.'
    old_len = len(poisoned_domain)
    poisoned_domain.add(name)
    if len(poisoned_domain) != old_len:
        try:
            fp = open('poisoned.txt', 'w')
            fp.write('\n'.join(poisoned_domain))
            fp.close()
        except IOError as e:
            _logger.warning("Failed to open poisoned.txt: %s", str(e))


def load_poisoned_domain():
    global poisoned_domain
    try:
        fp = open('poisoned.txt', 'r')
    except IOError as e:
        _logger.warning("Failed to open poisoned.txt: %s", str(e))
        return
    new_poisoned_domain = set()
    for line in fp.readlines():
        line = line.strip()
        if len(line) == 0 or line.startswith('#'):
            continue
        new_poisoned_domain.add(line)
    fp.close()
    poisoned_domain = new_poisoned_domain
    _logger.info('loaded %d poisoned items', len(poisoned_domain))


class MyHandler(PatternMatchingEventHandler):

    def __init__(self):
        super(MyHandler, self).__init__(patterns=['*blocked.txt'])

    def on_modified(self, event):
        update_blocked_domain()

    def on_created(self, event):
        update_blocked_domain()


update_blocked_domain()
load_poisoned_domain()
event_handler = MyHandler()
observer = Observer()
observer.schedule(event_handler, path='./', recursive=False)
observer.start()


class CIRD(object):

    def __init__(self, prefix, mask):
        self._raw_prefix = ip_string_to_long(prefix)
        self._raw_mask = ip_string_to_long('.'.join([str((0xffffffff << (32 - mask) >> i) & 0xff)
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


def is_domain_blocked(domain):
    global blocked_domain
    global poisoned_domain
    m = re.search('([^.]+\.){2}[^.]{2}\.$', domain)
    if m is not None and (m.group(0) in blocked_domain or m.group(0) in poisoned_domain):
        return True
    else:
        m = re.search('[^.]+\.[^.]+\.$', domain)
        if m is not None and (m.group(0) in blocked_domain or m.group(0) in poisoned_domain):
            return True
    return False


def change_src(packet):
    packet.set_raw_source_ip(packet.get_raw_source_ip() + 1)


def need_restore(original, packet):
    return packet.is_ipv4() and packet.get_raw_destination_ip() == original + 1


def restore_dst(packet):
    packet.set_raw_destination_ip(packet.get_raw_destination_ip() - 1)


def try_parse_dns_query(packet):
    if packet.is_udp() and packet.get_destination_port() == 53:
        try:
            ret = []
            query = DNSRecord.parse(packet.get_udp_load())
            for question in query.questions:
                name = str(question.get_qname())
                ret.append(name)
            return ret, query.header.id
        except object:
            _logger.warning("Failed to parse DNS query")
    return None, None


def try_parse_dns_result(packet):
    if packet.is_udp() and packet.get_source_port() == 53:
        try:
            ret = []
            result = DNSRecord.parse(packet.get_udp_load())
            for rr in result.rr:
                if rr.rtype == QTYPE.A:
                    addr, = struct.unpack('!I', struct.pack('!BBBB', *rr.rdata.data))
                    ret.append(addr)
            return ret, result.header.id, str(result.get_q().get_qname())
        except object:
            _logger.warning("Failed to parse DNS result")
    return None, None, None


def address2uuid(addr, port):
    packed = struct.pack('!QQ', 0, (addr + port) & 0xFFFFFFFFFFFFFFFF)
    return uuid.UUID(bytes=packed)


def pack_dns_key(addr, port, id_):
    return struct.pack('!IHH', addr, port, id_)


def change_to_dns_server(packet, id_, server):
    key = pack_dns_key(packet.get_raw_source_ip(), packet.get_source_port(), id_)
    modified_query[key] = {
        'original': packet.get_raw_destination_ip(),
        'replaced': server
    }
    packet.set_raw_destination_ip(server)


def try_restore_dns(packet, id_):
    key = pack_dns_key(packet.get_raw_destination_ip(), packet.get_destination_port(), id_)
    if key in modified_query:
        original = modified_query[key]['original']
        replaced = modified_query[key]['replaced']
        if packet.get_raw_source_ip() == replaced:
            packet.set_raw_source_ip(original)
        del modified_query[key]


def test_domain_poisoned(tun, packet):
    copied = copy.deepcopy(packet)
    copied.set_raw_destination_ip(TEST_DNS_SERVER)
    copied.set_udp_load(0, 2, struct.pack('!H', random.randint(0, 0xffff)))
    change_src(copied)
    tun.send(copied.get_packet())


def is_through_tunnel(packet, to_addr):
    if global_proxy:
        return True, False

    if packet.is_ipv6():
        return True, False

    dst_ip = packet.get_raw_destination_ip()
    if dst_ip == to_addr:
        return True, False

    for address in reversed_addresses:
        if address.match(dst_ip):
            _logger.info('destination ip is reversed one: %s:%d, from: %s:%d',
                         packet.get_destination_ip(), packet.get_destination_port(),
                         packet.get_source_ip(), packet.get_source_port())
            return False, False

    through_tunnel = False
    dns_query = False

    domain_list, id_ = try_parse_dns_query(packet)
    if domain_list is not None:
        dns_query = True
        for domain in domain_list:
            through_tunnel = is_domain_blocked(domain)
            if through_tunnel:
                break
        if through_tunnel:
            _logger.info("query: %s through tunnel", ', '.join(domain_list))
            change_to_dns_server(packet, id_, CLEAN_DNS_SERVER)
        else:
            _logger.info("query: %s directly", ', '.join(domain_list))
            change_to_dns_server(packet, id_, FAST_DNS_SERVER)

    if not through_tunnel:
        if dst_ip in blocked_address:
            _logger.debug('address: %s sent via tunnel', packet.get_destination_ip())
            through_tunnel = True

    if not through_tunnel and not dns_query and dst_ip not in normal_address:
        _logger.info('unknown address: %s %s:%d (from: %s:%d) sent directly', packet.get_protocol(),
                     packet.get_destination_ip(), packet.get_destination_port(),
                     packet.get_source_ip(), packet.get_source_port())
        through_tunnel = False

    return through_tunnel, dns_query


def gen_on_connect_side_raw_tun_received(tun):

    def on_received(_, ip_packet, __):
        packet = Packet(ip_packet)
        addr_list, id_, _ = try_parse_dns_result(packet)
        if addr_list is not None:
            update_blocked_address(addr_list)
            try_restore_dns(packet, id_)
        tun.send(packet.get_packet())
        return True

    return on_received


def gen_on_connect_side_tun_dev_received(addr, gateway, tunnel):

    from_addr = ip_string_to_long(addr)
    to_addr = ip_string_to_long(gateway)

    def connect_side_multiplex(self_, _, packet):
        if need_restore(from_addr, packet):
            restore_dst(packet)
            if packet.is_rst():
                _logger.info('%s has been reset', packet.get_source_ip())

            addr_list, id_, domain = try_parse_dns_result(packet)
            if addr_list is not None:
                if packet.get_raw_source_ip() == TEST_DNS_SERVER:
                    _logger.error('POISONED DOMAIN: %s', domain)
                    update_poisoned_domain(domain)
                    return True
                else:
                    normal_address.update(addr_list)
                    try_restore_dns(packet, id_)
            self_.send(packet.get_packet())
            return True

        through_tunnel, dns_query = is_through_tunnel(packet, to_addr)
        if not through_tunnel:
            if dns_query is True:
                test_domain_poisoned(self_, packet)
            change_src(packet)
            self_.send(packet.get_packet())
            return True

        tunnel.send(packet.get_packet())
        return True

    return connect_side_multiplex


def gen_on_accept_side_raw_tun_received(tun):

    remote_addr = [None]

    def on_received(tunnel, packet, addr):
        if remote_addr[0] is None or remote_addr[0] != addr[0]:
            remote_addr[0] = addr[0]
            tunnel.connect(remote_addr[0])
        tun.send(packet)
        return True

    return on_received


def gen_on_accept_side_tun_dev_received(raw):

    def on_received(_, packet, __):
        raw.send(packet)
        return True

    return on_received
