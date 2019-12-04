# Copyright (C) 2019 Brandon Ewing <brandon.ewing@warningg.com>
#               2019 Guillaume Valadon <guillaume.valadon@netatmo.com>
##
# This program is published under a GPLv2 license

# scapy.contrib.description = Arista Metawatch
# scapy.contrib.status = loads

from types import MethodType

from scapy.layers.l2 import Ether
from scapy.fields import ByteField, ShortField, FlagsField, SecondsIntField, \
    UTCTimeField
from scapy.error import Scapy_Exception


class TrailerBytes(bytes):
    """
    Reverses slice operations to take from the back of the packet,
    not the front
    """
    def __getitem__(self, item):
        if isinstance(item, int):
            item = -item
        elif isinstance(item, slice):
            start, stop, step = item.start, item.stop, item.step
            new_start = -stop if stop else None
            new_stop = -start if start else None
            item = slice(new_start, new_stop, step)
        return super(self.__class__, self).__getitem__(item)


class TrailerField(object):
    __slots__ = ["_fld"]

    def __init__(self, fld):
        self._fld = fld

    def getfield(self, pkt, s):
        previous_post_dissect = pkt.post_dissect

        def _post_dissect(self, s):
            # Reset packet to allow post_build
            self.raw_packet_cache = None
            self.post_dissect = previous_post_dissect
            return previous_post_dissect(s)
        pkt.post_dissect = MethodType(_post_dissect, pkt)
        s = TrailerBytes(s)
        s, val = self._fld.getfield(pkt, s)
        return bytes(s), val

    def build(self, *args, **kwargs):
        raise Scapy_Exception("Trailer reconstruction not supported")

    def __getattr__(self, attr):
        return getattr(self._fld, attr)


class MetawatchEther(Ether):
    name = "Ethernet (with MetaWatch trailer)"
    match_subclass = True
    fields_desc = Ether.fields_desc + [
        TrailerField(ByteField("metamako_portid", None)),
        TrailerField(ShortField("metamako_devid", None)),
        TrailerField(FlagsField("metamako_flags", 0x0, 8, "VX______")),
        TrailerField(SecondsIntField("metamako_nanos", 0, use_nano=True)),
        TrailerField(UTCTimeField("metamako_seconds", 0)),
        # TODO: Add TLV support
    ]
