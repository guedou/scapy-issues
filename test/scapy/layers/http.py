% HTTP regression tests for Scapy

############
############
+ HTTP 1.0
~ http

= HTTP decompression (gzip)

conf.debug_dissector = True
load_layer("http")

import os
import gzip

tmp = "/test/pcaps/http_compressed.pcap"
filename = os.path.abspath(os.path.join(os.path.dirname(__file__),"../")) + tmp
filename = os.getenv("SCAPY_ROOT_DIR")+tmp if not os.path.exists(filename) else filename

# First without auto decompression

conf.contribs["http"]["auto_compression"] = False
pkts = sniff(offline=filename, session=TCPSession)

data = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xffEQ]o\xdb0\x0c\xfc+\x9a\x1f\x92\xa7\x9a\x96?\xe4\xb8\x892`I\x81\r\xe8\xda\xa2p1\xec\xa9P-\xd5\x16*[\x86\xa5\xd8K\x7f\xfd\xa8\x14E\x1f\x8e:R\x07\xf2D\xed\xbe\x1d\xef\x0f\xf5\xdf\x87\x1b\xd2\xf9\xde\x90\x87\xa7\x1f\xb7\xbf\x0e$\xba\x02\xf8\x93\x1d\x00\x8e\xf5\x91\xfc\xac\x7f\xdf\x92<N(\xa9\'18\xed\xb5\x1d\x84\x01\xb8\xb9\x8bH\xd4y?^\x03,\xcb\x12/Yl\xa7\x16\xeaG\x08\xadr0\xd6:\x15K/\xa3\xfd.T0*!\xf7;\xaf\xbdQ\xfb\x1d|\x9e\x1f\xd5\x17+\xcf\xc4\xf9\xb3Q<z\x11\xcd[;\xd9\xd3 \xaf\x1ak\xectM|\x98<\x8aI\r\x1e\xbb\xe9\xbe%nj\xf8:Lw8~\xd4\xff\x94\x89{\xe1;/\xda\xb8\xb1=\xa8\x19\xa5\x80\xc2\xef\xbd\x7f\xd6\x92\xd3\x82\xe6\x8c\xad0\x112\xa4\t\xa3y\xbe\x9a)_\xcd)"\xe3+\x87\xdc!w\xc8\xed$y\x9a\xe4eZV%+\xd6d\xd1\xd2w|M\xd7\xa4S\xba\xed\xfc\x85\xc2\x97\x91\xe8\xd3\x88\x90NM\xb3nT\xdcZ\xdb\x1au\xf1"e\x0f\xaf\xc6\xc1;\x04m\xc6\n\xc6h\xb9\xf5\xe7Q\xf1n\x9c5nt\xdb\x08\xcf;\xdb\xab\x91V\x9b\xed)\xe5\xdb\x13C\x14\x88\x1c\x91!*\x04M0\x94\x81\x84\n\rW\x94\x86p\xa9m\xf8ix\x1b\xec2`\x03\x14\x867\xd0\ng%\xd9\x86\xb1\x94\x15qUd,B\xd7\x10v\x1d\x16\x1f>\xe5?9\x89QV\x01\x02\x00\x00'

pkts[2].show()
assert HTTPResponse in pkts[2]
assert pkts[2].Expires == b'Mon, 22 Apr 2019 15:23:19 GMT'
assert pkts[2].Content_Type == b'text/html; charset=UTF-8'
assert pkts[2].load == data

# Now with auto decompression

conf.contribs["http"]["auto_compression"] = True
pkts = sniff(offline=filename, session=TCPSession)

pkts[2].show()
assert HTTPResponse in pkts[2]
assert pkts[2].load == b'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd"><html><head><title></title></head><body style="background-color: transparent"><img src=\'https://pixel.mathtag.com/event/img?mt_id=151466&mt_adid=106144&v1=&v2=&v3=&s1=&s2=&s3=&ord=2047279765\' width=\'1\' height=\'1\' /><img src="https://adservice.google.com/ddm/fls/z/src=3656617;type=hpvisit;cat=homep198;u2=;u6=;u5=;u4=;u3=;u9=;u10=;u7=;u13=;u14=;u11=;u17=;u18=unknown;u20=;ord=1956603866265.9536"/></body></html>'

= HTTP decompression (brotli)
~ brotli

conf.debug_dissector = True
load_layer("http")

import os
import brotli

tmp = "/test/pcaps/http_compressed-brotli.pcap"
filename = os.path.abspath(os.path.join(os.path.dirname(__file__),"../")) + tmp
filename = os.getenv("SCAPY_ROOT_DIR")+tmp if not os.path.exists(filename) else filename

# First without auto decompression

conf.contribs["http"]["auto_compression"] = False
pkts = sniff(offline=filename, session=TCPSession)

data = b'\x1f\x41\x00\xe0\xc5\x6d\xec\x77\x56\xf7\xb5\x8b\x1c\x52\x10\x48\xe0\x90\x03\xf6\x6f\x97\x30\xd0\x40\x24\xb8\x01\x9b\xdb\xa0\xf4\x5c\x92\x4c\xc4\x6f\x89\x58\xf7\x4b\xf7\x4b\x6f\x8c\x2e\x2c\x28\x64\x06\x1d\x03'

pkts[0].show()
assert HTTPResponse in pkts[0]
assert pkts[0].Content_Encoding == b'br'
assert pkts[0].Content_Type == b'text/plain'
assert pkts[0].load == data

# Now with auto decompression

conf.contribs["http"]["auto_compression"] = True
pkts = sniff(offline=filename, session=TCPSession)

pkts[0].show()
assert HTTPResponse in pkts[0]
assert pkts[0].load == b'This is a test file for testing brotli decompression in Wireshark\n'

= HTTP decompression (zstd)
~ zstd

conf.debug_dissector = True
load_layer("http")

import os
import zstandard

# sample server: $ socat -v TCP-LISTEN:8080,fork,reuseaddr SYSTEM:'(echo -ne "HTTP/1.1 200 OK\r\nContent-Encoding: zstd\r\n\r\n") > tmp && dd bs=1G count=1 status=none | zstd --stdout >> tmp && cat tmp'
# sample client: $ curl -v localhost:8080/tmp_echo_zstd_request_for_testing -o a.html
tmp = "/test/pcaps/http_compressed-zstd.pcap"
filename = os.path.abspath(os.path.join(os.path.dirname(__file__),"../")) + tmp
filename = os.getenv("SCAPY_ROOT_DIR")+tmp if not os.path.exists(filename) else filename

# First without auto decompression

conf.contribs["http"]["auto_compression"] = False
pkts = sniff(offline=filename)

data = b'\x28\xb5\x2f\xfd\x04\x58\x45\x03\x00\xf2\x06\x19\x1c\x70\x89\x1b\xf6\x4f\x21\x1a\xbb\x28\xda\x9a\x1c\x34\xb8\x68\x1f\xd2\x82\xd7\x01\x8d\x36\xe5\x57\x1d\x0f\x38\x10\xa9\xa9\x86\x32\x96\x3d\xd4\xce\x2d\xa9\x2b\x01\x92\x94\xa8\x17\x23\xb7\xec\x9f\x6e\x96\x23\xb6\x13\x52\x97\xb2\x14\xf6\x0e\x9d\x57\x70\xf0\x2d\x7b\x87\x4c\x2a\x92\x10\x35\x68\x8d\xd9\xe6\x41\xbc\xf7\x73\x84\x07\x7e\xef\x48\xd1\x91\x0d\xef\x0b\x86\x8e\x6b\x86\x12\xaf\xb6\x05\x04\x01\x00\x29\x52\xd2\xfa'

pkts[0].show()
assert HTTPResponse in pkts[0]
assert pkts[0].Content_Encoding == b'zstd'
assert pkts[0].load == data

# Now with auto decompression

conf.contribs["http"]["auto_compression"] = True
pkts = sniff(offline=filename)

pkts[0].show()
assert HTTPResponse in pkts[0]
assert b'tmp_echo_zstd_request_for_testing' in pkts[0].load

= HTTP PSH bug fix

tmp = "/test/pcaps/http_tcp_psh.pcap.gz"
filename = os.path.abspath(os.path.join(os.path.dirname(__file__),"../")) + tmp
filename = os.getenv("SCAPY_ROOT_DIR")+tmp if not os.path.exists(filename) else filename

pkts = sniff(offline=filename, session=TCPSession)

assert len(pkts) == 15
# Verify a split header exists in the packet
assert pkts[5].User_Agent == b'example_user_agent'

# Verify all of the response data exists in the packet
assert int(pkts[7][HTTP].Content_Length.decode()) == len(pkts[7][Raw].load)

= HTTP build

pkt = TCP()/HTTP()/HTTPRequest(Method=b'GET', Path=b'/download', Http_Version=b'HTTP/1.1', Accept=b'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', Accept_Encoding=b'gzip, deflate', Accept_Language=b'en-US,en;q=0.5', Cache_Control=b'max-age=0', Connection=b'keep-alive', Host=b'scapy.net', User_Agent=b'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0')
raw_pkt = raw(pkt)
raw_pkt
assert raw_pkt == b'\x00P\x00P\x00\x00\x00\x00\x00\x00\x00\x00P\x02 \x00\x00\x00\x00\x00GET /download HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US,en;q=0.5\r\nCache-Control: max-age=0\r\nConnection: keep-alive\r\nHost: scapy.net\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0\r\n\r\n'

= HTTP 1.1 -> HTTP 2.0 Upgrade (h2c)
~ Test h2c

conf.debug_dissector = True
load_layer("http")
from scapy.contrib.http2 import H2Frame

import os

tmp = "/test/pcaps/http2_h2c.pcap"
filename = os.path.abspath(os.path.join(os.path.dirname(__file__),"../")) + tmp
filename = os.getenv("SCAPY_ROOT_DIR")+tmp if not os.path.exists(filename) else filename

pkts = sniff(offline=filename, session=TCPSession)

assert HTTPResponse in pkts[1]
assert pkts[1].Connection == b"Upgrade"
assert H2Frame in pkts[1]
assert pkts[1][H2Frame].settings[0].id == 3

for i in range(3, 10):
    assert HTTP not in pkts[i]
    assert H2Frame in pkts[i]

= Test chunked with gzip

conf.contribs["http"]["auto_compression"] = False
z = b'\x1f\x8b\x08\x00S\\-_\x02\xff\xb3\xc9(\xc9\xcd\xb1\xcb\xcd)\xb0\xd1\x07\xb3\x00\xe6\xedpt\x10\x00\x00\x00'
a = IP(dst="1.1.1.1", src="2.2.2.2")/TCP(seq=1)/HTTP()/HTTPResponse(Content_Encoding="gzip", Transfer_Encoding="chunked")/(b"5\r\n" + z[:5] + b"\r\n")
b = IP(dst="1.1.1.1", src="2.2.2.2")/TCP(seq=len(a[TCP].payload)+1)/HTTP()/(hex(len(z[5:])).encode()[2:] + b"\r\n" + z[5:] + b"\r\n0\r\n\r\n")
xa, xb = IP(raw(a)), IP(raw(b))
conf.contribs["http"]["auto_compression"] = True

c = sniff(offline=[xa, xb], session=TCPSession)[0]
assert gzip_decompress(z) == c.load
