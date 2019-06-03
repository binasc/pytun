import copy
import random
import socket
import struct

import cird
import loglevel
from address import Address
from dns import DNSRecord
from dns import QTYPE
from domain import Domain
from packet import Packet
from rawsocket import RawSocket
from tundevice import TunDevice

_logger = loglevel.get_logger('tunnel')
_logger.setLevel(loglevel.DEFAULT_LEVEL)

def _ip_string_to_long(ip):
    return struct.unpack('!I', socket.inet_pton(socket.AF_INET, ip))[0]

class Tunnel(object):

    def __init__(self, vps_addr, if_name, ip_proto, mtu, local_addr, remote_addr):
        self._tun_device = TunDevice(if_name, mtu)
        self._raw_socket = RawSocket(ip_proto, mtu)
        if vps_addr is not None:
            self._global_proxy = False
            self._domain_service = Domain('blocked.txt', 'poisoned.txt')
            self._address_service = Address('blocked_ip.txt')
            self._normal_address = set()

            self._fast_dns_server = _ip_string_to_long('119.29.29.29')
            self._clean_dns_server = _ip_string_to_long('8.8.8.8')
            self._test_dns_server = _ip_string_to_long('35.201.154.22')

            self._local_addr = _ip_string_to_long(local_addr)
            self._remote_addr = _ip_string_to_long(remote_addr)
            self._raw_socket.connect(vps_addr)
            self._raw_socket.set_on_receive(self._on_connect_side_raw_socket_received)
            self._tun_device.set_on_receive(self._on_connect_side_tun_device_received)
        else:
            self._vps_addr = None
            self._raw_socket.set_on_receive(self._on_accept_side_raw_socket_received)
            self._tun_device.set_on_receive(self._on_accept_side_tun_device_received)

        self._raw_socket.begin_receiving()
        self._tun_device.begin_receiving()

    def _on_connect_side_raw_socket_received(self, _, payload, __):
        packet = Packet(payload)
        addr_list, id_, _ = try_parse_dns_result(packet)
        if addr_list is not None:
            self._address_service.update_blocked_address(addr_list)
            try_restore_dns(packet, id_)
        self._tun_device.send(packet.get_packet())

    def _on_connect_side_tun_device_received(self, _, __, packet):
        if self._need_restore(self._local_addr, packet):
            self._restore_dst(packet)
            if packet.is_rst():
                _logger.info('%s has been reset', packet.get_source_ip())

            addr_list, id_, domain = try_parse_dns_result(packet)
            if addr_list is not None:
                if packet.get_raw_source_ip() == self._test_dns_server:
                    _logger.error('POISONED DOMAIN: %s', domain)
                    self._domain_service.update_poisoned_domain(domain)
                    return
                else:
                    self._normal_address.update(addr_list)
                    try_restore_dns(packet, id_)
            self._tun_device.send(packet.get_packet())
            return

        through_tunnel = self._is_through_tunnel(packet)
        if through_tunnel:
            self._raw_socket.send(packet.get_packet())
        else:
            self._change_src(packet)
            self._tun_device.send(packet.get_packet())

    def _on_accept_side_raw_socket_received(self, _, packet, addr):
        if self._vps_addr is None or self._vps_addr != addr[0]:
            self._vps_addr = addr[0]
            self._raw_socket.connect(self._vps_addr)
        self._tun_device.send(packet)

    def _on_accept_side_tun_device_received(self, _, packet, __):
        self._raw_socket.send(packet)

    @staticmethod
    def _change_src(packet):
        packet.set_raw_source_ip(packet.get_raw_source_ip() + 1)

    @staticmethod
    def _need_restore(original, packet):
        return packet.is_ipv4() and packet.get_raw_destination_ip() == original + 1

    @staticmethod
    def _restore_dst(packet):
        packet.set_raw_destination_ip(packet.get_raw_destination_ip() - 1)

    def _test_domain_poisoned(self, packet):
        copied = copy.deepcopy(packet)
        copied.set_raw_destination_ip(self._test_dns_server)
        copied.set_udp_load(0, 2, struct.pack('!H', random.randint(0, 0xffff)))
        self._change_src(copied)
        self._tun_device.send(copied.get_packet())

    def _is_through_tunnel(self, packet):
        if packet.is_ipv6():
            return True

        dst_ip = packet.get_raw_destination_ip()
        if dst_ip == self._remote_addr:
            return True

        if cird.is_reversed_address(dst_ip):
            return False

        if self._global_proxy:
            return True

        domain_list, id_ = try_parse_dns_query(packet)
        if domain_list is not None:
            blocked = False
            for domain in domain_list:
                blocked = self._domain_service.is_blocked(domain)
                if blocked:
                    break
            if blocked:
                _logger.info("query: %s through tunnel", ', '.join(domain_list))
                change_to_dns_server(packet, id_, self._clean_dns_server)
                return True
            else:
                _logger.info("query: %s directly", ', '.join(domain_list))
                change_to_dns_server(packet, id_, self._fast_dns_server)
                self._test_domain_poisoned(packet)
                return False

        through_tunnel = False
        if self._address_service.is_blocked(dst_ip):
            _logger.debug('address: %s sent via tunnel', packet.get_destination_ip())
            through_tunnel = True

        if not through_tunnel and dst_ip not in self._normal_address:
            _logger.info('unknown address: %s %s:%d (from: %s:%d) sent directly', packet.get_protocol(),
                         packet.get_destination_ip(), packet.get_destination_port(),
                         packet.get_source_ip(), packet.get_source_port())
            through_tunnel = False

        return through_tunnel


modified_query = {}


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

