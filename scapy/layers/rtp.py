## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
RTP (Real-time Transport Protocol).
"""

from scapy.packet import *
from scapy.fields import *

_rtp_payload_types = {
    # http://www.iana.org/assignments/rtp-parameters
    0:  'G.711 PCMU',    3:  'GSM',
    4:  'G723',          5:  'DVI4',
    6:  'DVI4',          7:  'LPC',
    8:  'PCMA',          9:  'G722',
    10: 'L16',           11: 'L16',
    12: 'QCELP',         13: 'CN',
    14: 'MPA',           15: 'G728',
    16: 'DVI4',          17: 'DVI4',
    18: 'G729',          25: 'CelB',
    26: 'JPEG',          28: 'nv',
    31: 'H261',          32: 'MPV',
    33: 'MP2T',          34: 'H263' }


class RTP(Packet):
    name = "RTP"
    extension_condition = lambda pkt: (pkt.extension == 1)
    fields_desc = [
                   BitField('version', 2, 2),
                   BitField('padding', 0, 1),
                   BitField('extension', 0, 1),
                   BitFieldLenField('numsync', None, 4, count_of='sync'),
                   BitField('marker', 0, 1),
                   BitEnumField('payload_type', 0, 7, _rtp_payload_types),
                   ShortField('sequence', 0),
                   IntField('timestamp', 0),
                   IntField('sourcesync', 0),
                   FieldListField('sync', [], IntField("id", 0), count_from=lambda pkt: pkt.numsync),
                   #ConditionalField(ShortField("extension_header_id", 0), extension_condition),
                   #ConditionalField(FieldLenField("extension_header_len", None, 0, count_of="extension_header", fmt="H", ),
                   #                 extension_condition),
                   #ConditionalField(
                   #    FieldListField('extension_header', [], IntField("hdr", 0), count_from=lambda pkt: pkt.extension_header),
                   #    extension_condition),
                   ConditionalField(ShortField("extension_header_id", 0), extension_condition),
                   ConditionalField(FieldLenField("extension_header_len", None, count_of="extension_header", fmt="H", ),
                                    extension_condition),
                   ConditionalField(FieldListField('extension_header', [], IntField("hdr", 0), 
                                    count_from=lambda pkt: pkt.extension_header_len), extension_condition),
                  ]

