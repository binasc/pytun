import errno
import random
import socket
import traceback
from math import ceil

from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Util.strxor import strxor

import loglevel
from event import Event

_logger = loglevel.get_logger('raw-socket')


random.seed()


def _xor(key, data):
    return strxor(data, bytes((ceil(len(data) / len(key)) * key))[:len(data)])


class RawSocket(object):

    def __hash__(self):
        return hash(self._fd.fileno())

    def __eq__(self, other):
        if not isinstance(other, RawSocket):
            return False
        return self._fd.fileno() == other._fd.fileno()

    def __str__(self):
        return "%s: %d" % (self._prefix, self._fd.fileno())

    def __init__(self, proto, mtu):
        self._fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        self._prefix = 'RAW-' + str(proto)
        self._fd.setblocking(False)
        self._mtu = mtu

        self._rev = Event()
        self._rev.set_write(False)
        self._rev.set_fd(self._fd.fileno())
        self._rev.set_handler(lambda ev: self._receive())

        self._errorType = socket.error

        self._on_received = None
        self._connected = False

    def bind(self, addr):
        self._fd.bind((addr, 0))
        _logger.info('bind to: %s', addr)

    def connect(self, addr):
        self._fd.connect((addr, 0))
        self._connected = True
        _logger.info('connect to: %s', addr)

    def begin_receiving(self):
        Event.addEvent(self._rev)

    def set_on_receive(self, handler):
        self._on_received = handler

    def _obscure(self, packet):
        remain_length = self._mtu - 20 - 8 - len(packet)
        do_padding = remain_length >= 256

        key = Random.new().read(4)
        first_bit = (key[0] >> 7) == 1
        second_bit = do_padding ^ first_bit
        if second_bit:
            val = key[0] | 0x40
        else:
            val = key[0] & 0xbf
        key = bytes([val]) + key[1:]

        payload = _xor(key, packet)
        sha = SHA256.new(payload + key).digest()[:4]
        if do_padding:
            length = random.randint(0, 255)
            pad = bytes([random.randint(0, 255)] * length)
            if first_bit:
                return key + sha + bytes([length]) + pad + payload
            else:
                return key + sha + payload + pad + bytes([length])
        else:
            return key + sha + payload

    def _restore(self, packet):
        packet_length = len(packet)
        if packet_length < 28:
            _logger.error('%s, too small packet(%d)', str(self), packet_length)
            return None

        key = packet[20: 24]

        high2 = key[0] >> 6
        has_padding = high2 == 1 or high2 == 2
        if has_padding:
            if packet_length < 29:
                _logger.error('%s, too small packet with no room for padding byte', str(self))
                return None
            if high2 == 2:
                pad_length = packet[28]
            else:
                pad_length = packet[-1]
            if packet_length < pad_length + 29:
                _logger.error('%s, too small packet with no room for padding', str(self))
                return None
            if high2 == 2:
                payload = packet[29 + pad_length:]
            else:
                payload = packet[28: -1 - pad_length]
        else:
            payload = packet[28:]

        sha = packet[24: 28]
        if sha != SHA256.new(payload + key).digest()[:4]:
            _logger.error('%s, bad signature of payload', str(self))
            return None
        return _xor(key, payload)

    def _receive(self):
        while True:
            try:
                packet, addr = self._fd.recvfrom(self._mtu + 8 + 20)
                if self._on_received is not None:
                    payload = self._restore(packet)
                    if payload is None:
                        continue
                    try:
                        self._on_received(self, payload, addr)
                    except Exception as ex:
                        _logger.error('%s receive callback failed: %s', str(self), str(ex))
                        traceback.print_exc()
                        break
            except self._errorType as msg:
                if msg.errno != errno.EAGAIN and msg.errno != errno.EINPROGRESS:
                    _logger.error('%s recv error: %s', str(self), str(msg))
                break

    def send(self, packet):
        if not self._connected:
            return
        try:
            payload = self._obscure(packet)
            sent = self._fd.send(payload)
            _logger.debug("%s sent %d bytes", str(self), sent)
            if sent != len(payload):
                _logger.error('%s short send %d(%d)', str(self), sent, len(payload))
        except self._errorType as msg:
            if msg.errno != errno.EAGAIN and msg.errno != errno.EINPROGRESS:
                _logger.error('%s send error: %s', str(self), str(msg))

