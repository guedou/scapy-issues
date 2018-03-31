## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##               2015, 2016, 2017 Maxence Tury
## This program is published under a GPLv2 license

"""
TLS Pseudorandom Function.
"""

from __future__ import absolute_import
from scapy.error import warning
from scapy.utils import strxor

from scapy.layers.tls.crypto.hash import _tls_hash_algs
from scapy.layers.tls.crypto.h_mac import _tls_hmac_algs
from scapy.modules.six.moves import range
from scapy.compat import *


### Data expansion functions

def _tls_P_hash(secret, seed, req_len, hm):
    """
    Provides the implementation of P_hash function defined in
    section 5 of RFC 4346 (and section 5 of RFC 5246). Two
    parameters have been added (hm and req_len):

    - secret : the key to be used. If RFC 4868 is to be believed,
               the length must match hm.key_len. Actually,
               python hmac takes care of formatting every key.
    - seed : the seed to be used.
    - req_len : the length of data to be generated by iterating
               the specific HMAC function (hm). This prevents
               multiple calls to the function.
    - hm : the hmac function class to use for iteration (either
           Hmac_MD5 or Hmac_SHA1 in TLS <= 1.1 or
           Hmac_SHA256 or Hmac_SHA384 in TLS 1.2)
    """
    hash_len = hm.hash_alg.hash_len
    n = (req_len + hash_len - 1) // hash_len

    res = b""
    a = hm(secret).digest(seed)  # A(1)

    while n > 0:
        res += hm(secret).digest(a + raw(seed))
        a = hm(secret).digest(a)
        n -= 1

    return res[:req_len]


def _tls_P_MD5(secret, seed, req_len):
    return _tls_P_hash(secret, seed, req_len, _tls_hmac_algs["HMAC-MD5"])


def _tls_P_SHA1(secret, seed, req_len):
    return _tls_P_hash(secret, seed, req_len, _tls_hmac_algs["HMAC-SHA"])


def _tls_P_SHA256(secret, seed, req_len):
    return _tls_P_hash(secret, seed, req_len, _tls_hmac_algs["HMAC-SHA256"])


def _tls_P_SHA384(secret, seed, req_len):
    return _tls_P_hash(secret, seed, req_len, _tls_hmac_algs["HMAC-SHA384"])


def _tls_P_SHA512(secret, seed, req_len):
    return _tls_P_hash(secret, seed, req_len, _tls_hmac_algs["HMAC-SHA512"])


### PRF functions, according to the protocol version

def _sslv2_PRF(secret, seed, req_len):
    hash_md5 = _tls_hash_algs["MD5"]()
    rounds = (req_len + hash_md5.hash_len - 1) // hash_md5.hash_len

    res = b""
    if rounds == 1:
        res += hash_md5.digest(secret + seed)
    else:
        r = 0
        while r < rounds:
            label = str(r).encode("utf8")
            res += hash_md5.digest(secret + label + seed)
            r += 1

    return res[:req_len]


def _ssl_PRF(secret, seed, req_len):
    """
    Provides the implementation of SSLv3 PRF function:

     SSLv3-PRF(secret, seed) =
        MD5(secret || SHA-1("A" || secret || seed)) ||
        MD5(secret || SHA-1("BB" || secret || seed)) ||
        MD5(secret || SHA-1("CCC" || secret || seed)) || ...

    req_len should not be more than  26 x 16 = 416.
    """
    if req_len > 416:
        warning("_ssl_PRF() is not expected to provide more than 416 bytes")
        return ""

    d = [b"A", b"B", b"C", b"D", b"E", b"F", b"G", b"H", b"I", b"J", b"K", b"L",
         b"M", b"N", b"O", b"P", b"Q", b"R", b"S", b"T", b"U", b"V", b"W", b"X",
         b"Y", b"Z"]
    res = b""
    hash_sha1 = _tls_hash_algs["SHA"]()
    hash_md5 = _tls_hash_algs["MD5"]()
    rounds = (req_len + hash_md5.hash_len - 1) // hash_md5.hash_len

    for i in range(rounds):
        label = d[i] * (i+1)
        tmp = hash_sha1.digest(label + secret + seed)
        res += hash_md5.digest(secret + tmp)

    return res[:req_len]


def _tls_PRF(secret, label, seed, req_len):
    """
    Provides the implementation of TLS PRF function as defined in
    section 5 of RFC 4346:

    PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
                               P_SHA-1(S2, label + seed)

    Parameters are:

    - secret: the secret used by the HMAC in the 2 expansion
              functions (S1 and S2 are the halves of this secret).
    - label: specific label as defined in various sections of the RFC
             depending on the use of the generated PRF keystream
    - seed: the seed used by the expansion functions.
    - req_len: amount of keystream to be generated
    """
    l = (len(secret) + 1) // 2
    S1 = secret[:l]
    S2 = secret[-l:]

    a1 = _tls_P_MD5(S1, label+seed, req_len)
    a2 = _tls_P_SHA1(S2, label+seed, req_len)

    return strxor(a1, a2)


def _tls12_SHA256PRF(secret, label, seed, req_len):
    """
    Provides the implementation of TLS 1.2 PRF function as
    defined in section 5 of RFC 5246:

    PRF(secret, label, seed) = P_SHA256(secret, label + seed)

    Parameters are:

    - secret: the secret used by the HMAC in the 2 expansion
              functions (S1 and S2 are the halves of this secret).
    - label: specific label as defined in various sections of the RFC
             depending on the use of the generated PRF keystream
    - seed: the seed used by the expansion functions.
    - req_len: amount of keystream to be generated
    """
    return _tls_P_SHA256(secret, label+seed, req_len)


def _tls12_SHA384PRF(secret, label, seed, req_len):
    return _tls_P_SHA384(secret, label+seed, req_len)


def _tls12_SHA512PRF(secret, label, seed, req_len):
    return _tls_P_SHA512(secret, label+seed, req_len)


class PRF(object):
    """
    The PRF used by SSL/TLS varies based on the version of the protocol and
    (for TLS 1.2) possibly the Hash algorithm of the negotiated cipher suite.
    The various uses of the PRF (key derivation, computation of verify_data,
    computation of pre_master_secret values) for the different versions of the
    protocol also changes. In order to abstract those elements, the common
    _tls_PRF() object is provided. It is expected to be initialised in the
    context of the connection state using the tls_version and the cipher suite.
    """

    def __init__(self, hash_name="SHA256", tls_version=0x0303):
        self.tls_version = tls_version
        self.hash_name = hash_name

        if tls_version < 0x0300:            # SSLv2
            self.prf = _sslv2_PRF
        elif tls_version == 0x0300:         # SSLv3
            self.prf = _ssl_PRF
        elif (tls_version == 0x0301 or      # TLS 1.0
              tls_version == 0x0302):       # TLS 1.1
            self.prf = _tls_PRF
        elif tls_version == 0x0303:         # TLS 1.2
            if hash_name == "SHA384":
                self.prf = _tls12_SHA384PRF
            elif hash_name == "SHA512":
                self.prf = _tls12_SHA512PRF
            else:
                self.prf = _tls12_SHA256PRF
        else:
            warning("Unknown TLS version")

    def compute_master_secret(self, pre_master_secret,
                              client_random, server_random):
        """
        Return the 48-byte master_secret, computed from pre_master_secret,
        client_random and server_random. See RFC 5246, section 6.3.
        """
        seed = client_random + server_random
        if self.tls_version < 0x0300:
            return None
        elif self.tls_version == 0x0300:
            return self.prf(pre_master_secret, seed, 48)
        else:
            return self.prf(pre_master_secret, b"master secret", seed, 48)

    def derive_key_block(self, master_secret, server_random,
                         client_random, req_len):
        """
        Perform the derivation of master_secret into a key_block of req_len
        requested length. See RFC 5246, section 6.3.
        """
        seed = server_random + client_random
        if self.tls_version <= 0x0300:
            return self.prf(master_secret, seed, req_len)
        else:
            return self.prf(master_secret, b"key expansion", seed, req_len)

    def compute_verify_data(self, con_end, read_or_write,
                            handshake_msg, master_secret):
        """
        Return verify_data based on handshake messages, connection end,
        master secret, and read_or_write position. See RFC 5246, section 7.4.9.

        Every TLS 1.2 cipher suite has a verify_data of length 12. Note also:
        "This PRF with the SHA-256 hash function is used for all cipher
         suites defined in this document and in TLS documents published
         prior to this document when TLS 1.2 is negotiated."
        Cipher suites using SHA-384 were defined later on.
        """
        if self.tls_version < 0x0300:
            return None
        elif self.tls_version == 0x0300:

            if read_or_write == "write":
                d = {"client": b"CLNT", "server": b"SRVR"}
            else:
                d = {"client": b"SRVR", "server": b"CLNT"}
            label = d[con_end]

            sslv3_md5_pad1 = b"\x36"*48
            sslv3_md5_pad2 = b"\x5c"*48
            sslv3_sha1_pad1 = b"\x36"*40
            sslv3_sha1_pad2 = b"\x5c"*40

            md5 = _tls_hash_algs["MD5"]()
            sha1 = _tls_hash_algs["SHA"]()

            md5_hash = md5.digest(master_secret + sslv3_md5_pad2 +
                                  md5.digest(handshake_msg + label +
                                             master_secret + sslv3_md5_pad1))
            sha1_hash = sha1.digest(master_secret + sslv3_sha1_pad2 +
                                    sha1.digest(handshake_msg + label +
                                                master_secret + sslv3_sha1_pad1))
            verify_data = md5_hash + sha1_hash

        else:

            if read_or_write == "write":
                d = {"client": "client", "server": "server"}
            else:
                d = {"client": "server", "server": "client"}
            label = ("%s finished" % d[con_end]).encode()

            if self.tls_version <= 0x0302:
                s1 = _tls_hash_algs["MD5"]().digest(handshake_msg)
                s2 = _tls_hash_algs["SHA"]().digest(handshake_msg)
                verify_data = self.prf(master_secret, label, s1 + s2, 12)
            else:
                if self.hash_name in ["MD5", "SHA"]:
                    h = _tls_hash_algs["SHA256"]()
                else:
                    h = _tls_hash_algs[self.hash_name]()
                s = h.digest(handshake_msg)
                verify_data = self.prf(master_secret, label, s, 12)

        return verify_data

    def postprocess_key_for_export(self, key, client_random, server_random,
                                   con_end, read_or_write, req_len):
        """
        Postprocess cipher key for EXPORT ciphersuite, i.e. weakens it.
        An export key generation example is given in section 6.3.1 of RFC 2246.
        See also page 86 of EKR's book.
        """
        s = con_end + read_or_write
        s = (s == "clientwrite" or s == "serverread")

        if self.tls_version < 0x0300:
            return None
        elif self.tls_version == 0x0300:
            if s:
                tbh = key + client_random + server_random
            else:
                tbh = key + server_random + client_random
            export_key = _tls_hash_algs["MD5"]().digest(tbh)[:req_len]
        else:
            if s:
                tag = b"client write key"
            else:
                tag = b"server write key"
            export_key = self.prf(key,
                                  tag,
                                  client_random + server_random,
                                  req_len)
        return export_key

    def generate_iv_for_export(self, client_random, server_random,
                               con_end, read_or_write, req_len):
        """
        Generate IV for EXPORT ciphersuite, i.e. weakens it.
        An export IV generation example is given in section 6.3.1 of RFC 2246.
        See also page 86 of EKR's book.
        """
        s = con_end + read_or_write
        s = (s == "clientwrite" or s == "serverread")

        if self.tls_version < 0x0300:
            return None
        elif self.tls_version == 0x0300:
            if s:
                tbh = client_random + server_random
            else:
                tbh = server_random + client_random
            iv = _tls_hash_algs["MD5"]().digest(tbh)[:req_len]
        else:
            iv_block = self.prf("",
                                b"IV block",
                                client_random + server_random,
                                2*req_len)
            if s:
                iv = iv_block[:req_len]
            else:
                iv = iv_block[req_len:]
        return iv

