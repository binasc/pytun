#!/usr/bin/env python
import getopt
import sys

import event
import loglevel
import tuntun
from rawsocket import RawSocket
from tundevice import TunDevice

_logger = loglevel.get_logger('main')


def acceptor_on_closed(_self):
    _logger.exception('Acceptor closed!')
    sys.exit(-1)


_helpText = '''Usage:
Connect Side: -c {server_ip} -t tun_if
Accept Side: -a {listen_on} -t tun_if
'''


if __name__ == '__main__':
    if sys.platform.startswith('linux'):
        import epoll
        epoll.Epoll.init()
        _logger.debug("epoll")
    elif sys.platform.startswith('darwin'):
        import kqueue
        kqueue.Kqueue.init()
        _logger.debug("kqueue")

    addr = None
    accept_mode = False
    connect_mode = False
    tun_if = None
    mtu = None

    optlist, args = getopt.getopt(sys.argv[1:], 'ac:t:m:h')
    for cmd, arg in optlist:
        if cmd == '-a':
            accept_mode = True
            if connect_mode is True:
                raise Exception('Already in Connect Mode')
        if cmd == '-c':
            connect_mode = True
            if accept_mode is True:
                raise Exception('Already in Accept Mode')
            addr = arg
        if cmd == '-t':
            tun_if = arg
        if cmd == '-m':
            mtu = int(arg)
        if cmd == '-h':
            print(_helpText)
            sys.exit(0)

    if not accept_mode and not connect_mode or mtu is None:
        print(_helpText)
        sys.exit(0)

    dev = TunDevice(tun_if, mtu)
    raw = RawSocket(mtu, 253)

    if accept_mode:
        raw.set_on_receive(tuntun.gen_on_accept_side_raw_tun_received(dev))
        dev.set_on_receive(tuntun.gen_on_accept_side_tun_dev_received(raw))
        raw.begin_receiving()
    else:
        raw.connect(addr)
        raw.set_on_receive(tuntun.gen_on_connect_side_raw_tun_received(dev))
        dev.set_on_receive(tuntun.gen_on_connect_side_tun_dev_received('10.14.0.2', '10.14.0.1', raw))
        raw.begin_receiving()

    dev.begin_receiving()

    event.Event.process_loop()
