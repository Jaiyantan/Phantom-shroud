import hashlib
from scapy.layers.inet import TCP
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello

def compute_ja3_from_packet(pkt):
    # Only works for scapy TLS handshake packets
    if not (pkt.haslayer(TCP) and pkt.haslayer(TLSClientHello)):
        return None
    ch = pkt[TLSClientHello]
    buf = [
        str(ch.version),
        '-'.join(str(c) for c in ch.ciphers),
        '-'.join(str(e) for e in getattr(ch, 'ext', [])),
        '-'.join(str(e[1]) for e in getattr(ch, 'ext', []) if isinstance(e, tuple) and len(e) > 1),
        '0',  # Not all fields always present
    ]
    ja3str = ','.join(buf)
    ja3 = hashlib.md5(ja3str.encode()).hexdigest()
    return ja3

def compute_ja3s_from_packet(pkt):
    if not (pkt.haslayer(TCP) and pkt.haslayer(TLSServerHello)):
        return None
    sh = pkt[TLSServerHello]
    buf = [
        str(sh.version),
        '-'.join(str(c) for c in sh.ciphers),
        '-'.join(str(e) for e in getattr(sh, 'ext', [])),
        '-'.join(str(e[1]) for e in getattr(sh, 'ext', []) if isinstance(e, tuple) and len(e) > 1),
        '0',
    ]
    ja3sstr = ','.join(buf)
    ja3s = hashlib.md5(ja3sstr.encode()).hexdigest()
    return ja3s
