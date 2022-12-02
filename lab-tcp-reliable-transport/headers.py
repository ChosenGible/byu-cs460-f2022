from __future__ import annotations

import struct

from cougarnet.util import \
        ip_str_to_binary, ip_binary_to_str


IP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
TCP_HEADER_LEN = 20
TCPIP_HEADER_LEN = IP_HEADER_LEN + TCP_HEADER_LEN
UDPIP_HEADER_LEN = IP_HEADER_LEN + UDP_HEADER_LEN

TCP_RECEIVE_WINDOW = 64

class IPv4Header:
    def __init__(self, length: int, ttl: int, protocol: int, checksum: int,
            src: str, dst: str) -> IPv4Header:
        self.length = length
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.src = src
        self.dst = dst

    @classmethod
    def from_bytes(cls, hdr: bytes) -> IPv4Header:
        length, = struct.unpack('!H', hdr[2:4])
        ttl, = struct.unpack('!B', hdr[8:9])
        protocol, = struct.unpack('!B', hdr[9:10])
        checksum, = struct.unpack('!H', hdr[10:12])
        srcInt, = struct.unpack('!I', hdr[12:16])
        destInt, = struct.unpack('!I', hdr[16:20])

        srcB = srcInt.to_bytes(4, 'big')
        destB = destInt.to_bytes(4, 'big')

        src = ip_binary_to_str(srcB)
        dest = ip_binary_to_str(destB)

        return cls(length, ttl, protocol, checksum, src, dest)

    def to_bytes(self) -> bytes:
        hdr = b''
        hdr += struct.pack('!H', 17664)
        hdr += struct.pack('!H', self.length)
        hdr += struct.pack('!H', 0)
        hdr += struct.pack('!H', 0)
        hdr += struct.pack('!B', self.ttl)
        hdr += struct.pack('!B', self.protocol)
        hdr += struct.pack('!H', self.checksum)
        hdr += struct.pack('!I', int.from_bytes(ip_str_to_binary(self.src), 'big'))
        hdr += struct.pack('!I', int.from_bytes(ip_str_to_binary(self.dst), 'big'))
        return hdr


class UDPHeader:
    def __init__(self, sport: int, dport: int, length: int,
            checksum: int) -> UDPHeader:
        self.sport = sport
        self.dport = dport
        self.checksum = checksum
        self.length = length

    @classmethod
    def from_bytes(cls, hdr: bytes) -> UDPHeader:
        sport, = struct.unpack('!H', hdr[:2])
        dport, = struct.unpack('!H', hdr[2:4])
        length, = struct.unpack('!H', hdr[4:6])
        checksum, = struct.unpack('!H', hdr[6:8])
        return cls(sport, dport, length, checksum)

    def to_bytes(self) -> bytes:
        hdr = b''
        hdr += struct.pack('!H', self.sport)
        hdr += struct.pack('!H', self.dport)
        hdr += struct.pack('!H', self.length)
        hdr += struct.pack('!H', self.checksum)
        return hdr


class TCPHeader:
    def __init__(self, sport: int, dport: int, seq: int, ack: int,
            flags: int, checksum: int) -> TCPHeader:
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.checksum = checksum

    @classmethod
    def makeFlags(cls, isSyn, isAck):
        base = 20480
        if (isSyn):
            base += 2
        if (isAck):
            base += 16

        return base

    def isSynFlagSet(self):
        synMask = int('0000000000000010', base=2)
        value = self.flags & synMask
        return not(value == 0)

    def isAckFlagSet(self):
        ackMask = int('0000000000010000', base=2)
        value = self.flags & ackMask
        return not(value == 0)

    @classmethod
    def from_bytes(cls, hdr: bytes) -> TCPHeader:
        sport, = struct.unpack('!H',hdr[:2])
        dport, = struct.unpack('!H',hdr[2:4])
        seq, = struct.unpack('!I',hdr[4:8])
        ack, = struct.unpack('!I',hdr[8:12])
        flags, = struct.unpack('!H', hdr[12:14])
        window, = struct.unpack('!H',hdr[14:16])
        checksum, = struct.unpack('!H',hdr[16:18])
        uptr, = struct.unpack('!H',hdr[18:20])
        return cls(sport, dport, seq, ack, flags, checksum)

    def to_bytes(self) -> bytes:
        hdr = b''
        hdr += struct.pack('!H', self.sport)
        hdr += struct.pack('!H', self.dport)
        hdr += struct.pack('!I', self.seq)
        hdr += struct.pack('!I', self.ack)
        hdr += struct.pack('!H', self.flags)
        hdr += struct.pack('!H', 64)
        hdr += struct.pack('!H', self.checksum)
        hdr += struct.pack('!H', 0)
        return hdr
