import heapq
import struct
import time

import loglevel

_logger = loglevel.get_logger('address')
_logger.setLevel(loglevel.DEFAULT_LEVEL)

class Address(object):

    class Record(object):

        def __init__(self, ip):
            self._ip = ip
            self._names = {}

        @property
        def ip(self):
            return self._ip

        def append(self, name):
            if name not in self._names:
                self._names[name] = 0
            self._names[name] = self._names[name] + 1

        def expire(self, name):
            if name in self._names:
                self._names[name] = self._names[name] - 1
                if self._names[name] == 0:
                    del self._names[name]
            else:
                _logger.warning('no record for name: %s', name)

        def is_empty(self):
            return len(self._names) == 0

        def names_str(self):
            return ', '.join(map(lambda n: n[0], self._names))

    def __init__(self, blocked_file):
        self._blocked_file = blocked_file
        self._blocked_address = set()
        self._last_size = 0
        self._last_sync = time.time()
        self._records_heap = []
        self._ip2record = {}
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

    def update_normal_address(self, answers):
        now = time.time()

        for name, _, addr, ttl in answers:
            heapq.heappush(self._records_heap, (now + ttl, (addr, name)))
            if addr not in self._ip2record:
                self._ip2record[addr] = self.Record(addr)
            self._ip2record[addr].append(name)

        while len(self._records_heap) > 0:
            expired_at, addr_name = self._records_heap[0]
            if expired_at > now:
                break
            else:
                heapq.heappop(self._records_heap)
                addr = addr_name[0]
                name = addr_name[1]
                if addr in self._ip2record:
                    record = self._ip2record[addr]
                    record.expire(name)
                    if record.is_empty():
                        del self._ip2record[addr]
                    _logger.debug('%s expired', name)
                else:
                    _logger.warning('no record for name: %s', name)

    def update_blocked_address(self, answers):
        addr_list = []
        now = time.time()
        for _, __, addr, ___ in answers:
            addr_list.append(addr)

        self._blocked_address.update(addr_list)

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

    def is_normal(self, ip):
        return ip in self._ip2record

    def ptr_resolve(self, ip):
        if ip in self._ip2record:
            return self._ip2record[ip].names_str()
        return None

    def is_blocked(self, ip):
        return ip in self._blocked_address
