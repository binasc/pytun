import copy
import random
import socket
import struct

import cird
import loglevel
from address import Address
from dnspacket import DnsPacket
from domain import Domain
from name import Name
from packet import Packet
from rawsocket import RawSocket
from tundevice import TunDevice

_logger = loglevel.get_logger('tunnel')
_logger.setLevel(loglevel.DEFAULT_LEVEL)

def _ip_string_to_long(ip):
    return struct.unpack('!I', socket.inet_pton(socket.AF_INET, ip))[0]

class Tunnel(object):

    def __init__(self, config):
        if_name = config.get('common', 'tun_device')
        mtu = config.getint('common', 'mtu')
        ip_proto = config.getint('common', 'ip_proto')

        self._tun_device = TunDevice(if_name, mtu)
        self._raw_socket = RawSocket(ip_proto, mtu)
        if config.get('common', 'mode') == 'CONNECT':
            self._global_proxy = False
            self._domain_service = Domain('blocked.txt', 'poisoned.txt')
            self._address_service = Address('blocked_ip.txt')
            self._name_service = Name()

            self._fast_dns_server = _ip_string_to_long(config.get('client', 'fast_dns'))
            self._clean_dns_server = _ip_string_to_long(config.get('client', 'clean_dns'))
            self._test_dns_server = _ip_string_to_long(config.get('client', 'test_dns'))

            self._local_addr = _ip_string_to_long(config.get('client', 'local_addr'))
            self._remote_addr = _ip_string_to_long(config.get('client', 'remote_addr'))
            self._raw_socket.connect(config.get('client', 'vps_addr'))
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
        dns_packet = DnsPacket(packet)
        if dns_packet.is_dns_packet():
            self._address_service.update_blocked_address(dns_packet.get_answers())
            self._name_service.try_restore_dns(packet, dns_packet.get_id())
        self._tun_device.send(packet.get_packet())

    def _on_connect_side_tun_device_received(self, _, __, packet):
        if self._need_restore(self._local_addr, packet):
            self._restore_dst(packet)
            if packet.is_rst():
                name = self._address_service.ptr_resolve(packet.get_raw_source_ip())
                _logger.info('%s has been reset', packet.get_source_ip() if name is None else name)

            dns_packet = DnsPacket(packet)
            if dns_packet.is_dns_packet():
                if packet.get_raw_source_ip() == self._test_dns_server:
                    names = map(lambda a: a[0], dns_packet.get_answers())
                    _logger.error('POISONED DOMAIN: %s', names)
                    self._domain_service.update_poisoned_domain(names)
                    return
                self._address_service.update_normal_address(dns_packet.get_answers())
                self._name_service.try_restore_dns(packet, dns_packet.get_id())
            self._tun_device.send(packet.get_packet())
            return
        else :
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

        dns_packet = DnsPacket(packet)
        if dns_packet.is_dns_packet():
            blocked = False
            queries = dns_packet.get_queries()
            for name, r_type in queries:
                if r_type == 'AAAA':
                    blocked = True
                    break
                blocked = self._domain_service.is_blocked(name)
                if blocked:
                    break
            if blocked:
                _logger.info("query: %s through tunnel", ', '.join(map(lambda t: t[0] + '-' + t[1], queries)))
                self._name_service.change_to_dns_server(packet, dns_packet.get_id(), self._clean_dns_server)
                return True
            else:
                _logger.info("query: %s directly", ', '.join(map(lambda t: t[0] + '-' + t[1], queries)))
                self._name_service.change_to_dns_server(packet, dns_packet.get_id(), self._fast_dns_server)
                if len(list(filter(lambda a: not a[0].endswith('openvpn.'), queries))) > 0:
                    self._test_domain_poisoned(packet)
                return False

        if self._address_service.is_blocked(dst_ip):
            _logger.debug('address: %s sent via tunnel', packet.get_destination_ip())
            return True

        if not self._address_service.is_normal(dst_ip):
            _logger.debug('unknown address: %s %s:%d (from: %s:%d) sent directly', packet.get_protocol(),
                          packet.get_destination_ip(), packet.get_destination_port(),
                          packet.get_source_ip(), packet.get_source_port())
        return False

    def on_stopped(self):
        self._address_service.flush_blocked_address()
