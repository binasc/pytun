#!/usr/bin/env python
import getopt
import sys

import epoll
import event
import loglevel
from tunnel import Tunnel

_logger = loglevel.get_logger('main')


def acceptor_on_closed(_self):
    _logger.exception('Acceptor closed!')
    sys.exit(-1)


_helpText = '''Usage:
Connect Side: -c {server_ip} -t if_name -p ip_proto -m mtu
Accept Side: -a -t if_name -p ip_proto -m mtu
'''


if __name__ == '__main__':
    epoll.Epoll.init()

    addr = None
    accept_mode = False
    connect_mode = False
    if_name = None
    ip_proto = None
    mtu = None

    optlist, args = getopt.getopt(sys.argv[1:], 'ac:t:p:m:h')
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
            if_name = arg
        if cmd == '-p':
            ip_proto = int(arg)
        if cmd == '-m':
            mtu = int(arg)
        if cmd == '-h':
            print(_helpText)
            sys.exit(0)

    if not accept_mode and not connect_mode or mtu is None:
        print(_helpText)
        sys.exit(0)

    if accept_mode:
        tunnel = Tunnel(None, if_name, ip_proto, mtu, None, None)
    else:
        tunnel = Tunnel(addr, if_name, ip_proto, mtu, "10.14.0.2", "10.14.0.1")

    event.Event.process_loop()
