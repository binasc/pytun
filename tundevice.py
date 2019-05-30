import ctypes
import errno
import fcntl
import os
import socket
import struct
import sys
import traceback

import ioctl
import loglevel
from event import Event
from packet import Packet

_logger = loglevel.get_logger('tun-device')


class FileWrapper(object):
    def __init__(self, fd):
        self._fd = fd

    def fileno(self):
        return self._fd


MAX_KCTL_NAME = 96
class CtlInfo (ctypes.Structure):
    _fields_ = [
        ('ctl_id', ctypes.c_uint32),
        ('ctl_name', ctypes.c_char * MAX_KCTL_NAME),
    ]


class TunDevice(object):

    TUNSETIFF = ioctl.IOW(ord('T'), 202, ctypes.c_int)
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000

    CTLIOCGINFO = ioctl.IOWR(ord('N'), 3, CtlInfo)
    UTUN_CONTROL_NAME = bytes('com.apple.net.utun_control', 'utf-8')
    UTUN_OPT_IFNAME = 2

    def __hash__(self):
        return hash(self._fd.fileno())

    def __eq__(self, other):
        if not isinstance(other, TunDevice):
            return False
        return self._fd.fileno() == other._fd.fileno()

    def __str__(self):
        return "%s: %d" % (self._prefix, self._fd.fileno())

    def __init__(self, if_name, mtu):
        if sys.platform.startswith('linux'):
            fd = os.open('/dev/net/tun', os.O_RDWR)
            if if_name is None:
                if_name = 'tun%d'
            mode = self.IFF_TUN | self.IFF_NO_PI
            ctrl_str = struct.pack('16sH', if_name.encode('ascii'), mode)
            ifs = fcntl.ioctl(fd, self.TUNSETIFF, ctrl_str)
            self._if_name = ifs[:16].strip(bytes([0])).decode('ascii')
            self._fd = FileWrapper(fd)
        elif sys.platform.startswith('darwin'):
            sock = socket.socket(socket.PF_SYSTEM, socket.SOCK_DGRAM, socket.SYSPROTO_CONTROL)
            ctrl_info = bytearray(struct.pack('I' + str(MAX_KCTL_NAME) + 's', 0, self.UTUN_CONTROL_NAME))
            fcntl.ioctl(sock, self.CTLIOCGINFO, ctrl_info)
            ctl_id, = struct.unpack('I', ctrl_info[:4])
            sock.connect((ctl_id, 10))
            if_name = sock.getsockopt(socket.SYSPROTO_CONTROL, self.UTUN_OPT_IFNAME, 20)
            self._if_name = if_name.strip(bytes([0])).decode('ascii')
            self._fd = sock
        else:
            raise Exception('unsupported platform: ' + sys.platform)

        self._prefix = 'TUN-' + self._if_name
        flag = fcntl.fcntl(self._fd.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(self._fd.fileno(), fcntl.F_SETFL, flag | os.O_NONBLOCK)
        self._mtu = mtu

        self._rev = Event()
        self._rev.set_write(False)
        self._rev.set_fd(self._fd.fileno())
        self._rev.set_handler(lambda ev: self._receive())

        self._errorType = OSError

        self._on_received = None

    def begin_receiving(self):
        Event.addEvent(self._rev)

    def set_on_receive(self, handler):
        self._on_received = handler

    def _receive(self):
        while True:
            try:
                packet = os.read(self._fd.fileno(), self._mtu)
                if self._on_received is not None:
                    try:
                        if sys.platform.startswith('linux'):
                            self._on_received(self, packet, Packet(packet))
                        else:
                            self._on_received(self, packet[4:], Packet(packet[4:]))
                    except Exception as ex:
                        _logger.error('%s receive callback failed: %s', str(self), str(ex))
                        traceback.print_exc()
                        break
            except self._errorType as msg:
                if msg.errno != errno.EAGAIN and msg.errno != errno.EINPROGRESS:
                    _logger.error('%s recv error: %s', str(self), str(msg))
                break

    def send(self, packet):
        try:
            sent = os.write(self._fd.fileno(), packet)
            _logger.info("%s sent %d bytes", str(self), sent)
            if sent != len(packet):
                _logger.error('%s short send %d(%d)', str(self), sent, len(packet))
        except self._errorType as msg:
            if msg.errno != errno.EAGAIN and msg.errno != errno.EINPROGRESS:
                _logger.error('%s send error: %s', str(self), str(msg))
