#!/usr/bin/env python
import getopt
import signal
import sys
from configparser import ConfigParser

import epoll
import event
import loglevel
from event import Event
from tunnel import Tunnel

_logger = loglevel.get_logger('main')
_tunnel = None


def acceptor_on_closed(_self):
    _logger.exception('Acceptor closed!')
    sys.exit(-1)


_helpText = '''Usage:
pytun.py -c|-a [-f {config-file}]
'''

def stop_signal_handler(_, __):
    Event.stop_loop()
    if _tunnel is not None:
        _tunnel.on_stopped()


if __name__ == '__main__':
    epoll.Epoll.init()

    accept_mode = False
    connect_mode = False
    config_file = 'default.conf'

    optlist, args = getopt.getopt(sys.argv[1:], 'acf:h')
    for cmd, arg in optlist:
        if cmd == '-a':
            accept_mode = True
            if connect_mode is True:
                raise Exception('Already in Connect Mode')
        if cmd == '-c':
            connect_mode = True
            if accept_mode is True:
                raise Exception('Already in Accept Mode')
        if cmd == '-f':
            config_file = arg
        if cmd == '-h':
            print(_helpText)
            sys.exit(0)

    if not accept_mode and not connect_mode:
        print(_helpText)
        sys.exit(0)

    config = ConfigParser()
    config.read(config_file)
    config.set('common', 'mode', 'ACCEPT' if accept_mode else 'CONNECT')
    _tunnel = Tunnel(config)

    signal.signal(signal.SIGINT, stop_signal_handler)

    event.Event.process_loop()
    _logger.info('bye')
