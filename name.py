import struct

import loglevel

_logger = loglevel.get_logger('name')
_logger.setLevel(loglevel.DEFAULT_LEVEL)

class Name(object):

    def __init__(self):
        self._modified_query = {}

    @staticmethod
    def _pack_dns_key(addr, port, id_):
        return struct.pack('!IHH', addr, port, id_)

    def change_to_dns_server(self, packet, id_, server):
        key = self._pack_dns_key(packet.get_raw_source_ip(), packet.get_source_port(), id_)
        self._modified_query[key] = {
            'original': packet.get_raw_destination_ip(),
            'replaced': server
        }
        packet.set_raw_destination_ip(server)

    def try_restore_dns(self, packet, id_):
        key = self._pack_dns_key(packet.get_raw_destination_ip(), packet.get_destination_port(), id_)
        if key in self._modified_query:
            original = self._modified_query[key]['original']
            replaced = self._modified_query[key]['replaced']
            if packet.get_raw_source_ip() == replaced:
                packet.set_raw_source_ip(original)
            del self._modified_query[key]
