import struct
import time

import loglevel

_logger = loglevel.get_logger('address')
_logger.setLevel(loglevel.DEFAULT_LEVEL)

class Address(object):

    def __init__(self, blocked_file):
        self._blocked_file = blocked_file
        self._blocked_address = set()
        self._last_size = 0
        self._last_sync = time.time()
        self.load_blocked_address()

    def load_blocked_address(self):
        try:
            fp = open(self._blocked_file, 'rb')
            content = fp.read()
            for i in range(0, len(content), 4):
                self._blocked_address.add(struct.unpack('!I', content[i: i + 4])[0])
            self._last_size = len(self._blocked_address)
            _logger.info('Update %d blocked ips', self._last_size)
            fp.close()
        except IOError as e:
            _logger.warning("Failed to open %s: %s", self._blocked_file, str(e))
            return False

    def update_blocked_address(self, addresses):
        self._blocked_address.update(addresses)
        now = time.time()
        if now - self._last_sync > 60 and self._last_size != len(self._blocked_address):
            try:
                fp = open(self._blocked_file, 'wb')
            except IOError as e:
                _logger.warning("Failed to write %s: %s", self._blocked_file, str(e))
                return
            for ip in self._blocked_address:
                fp.write(struct.pack('!I', ip))
            fp.close()
            _logger.info("Synced %d blocked ip", len(self._blocked_address))
            self._last_size = len(self._blocked_address)
            self._last_sync = now

    def is_blocked(self, ip):
        return ip in self._blocked_address
