import struct

import loglevel
from dns import DNSRecord
from dns import QTYPE

_logger = loglevel.get_logger('dns-packet')

class DnsPacket(object):

    def __init__(self, packet):
        self._packet = packet
        self._id = None
        self._queries = []
        self._answers = []
        self._try_parse_dns_packet()

    def _try_parse_dns_packet(self):
        if not self._packet.is_udp():
            return

        if self._packet.get_source_port() != 53 and self._packet.get_destination_port() != 53:
            return

        try:
            record = DNSRecord.parse(self._packet.get_udp_load())

            self._id = record.header.id

            for question in record.questions:
                name = str(question.get_qname())
                q_type = QTYPE.get(question.qtype)
                self._queries.append((name, q_type))

            for rr in record.rr:
                name = str(rr.get_rname())
                r_type = QTYPE.get(rr.rtype)
                if rr.rtype == QTYPE.A:
                    addr, = struct.unpack('!I', struct.pack('!BBBB', *rr.rdata.data))
                    self._answers.append((name, r_type, addr))

        except Exception as ex:
            _logger.warning("Failed to parse DNS query: %s", str(ex))

    def is_dns_packet(self):
        return self._id is not None

    def get_id(self):
        return self._id

    def get_queries(self):
        return self._queries

    def get_answers(self):
        return self._answers
