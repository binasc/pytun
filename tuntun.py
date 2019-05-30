import copy
import random
import socket
import struct
import time

import cird
import loglevel
from dns import DNSRecord
from dns import QTYPE
from domain import Domain
from packet import Packet

_logger = loglevel.get_logger('tunnel')
_logger.setLevel(loglevel.DEFAULT_LEVEL)


def ip_string_to_long(ip):
    return struct.unpack('!I', socket.inet_pton(socket.AF_INET, ip))[0]


FAST_DNS_SERVER = ip_string_to_long('119.29.29.29')
CLEAN_DNS_SERVER = ip_string_to_long('8.8.8.8')
TEST_DNS_SERVER = ip_string_to_long('35.201.154.22')


global_proxy = True
domain_service = Domain('blocked.txt', 'poisoned.txt')
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
        except Exception:
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
        except Exception:
            _logger.warning("Failed to parse DNS result")
    return None, None, None


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

    if cird.is_reversed_address(dst_ip):
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
            through_tunnel = domain_service.is_blocked(domain)
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
                    domain_service.update_poisoned_domain(domain)
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
