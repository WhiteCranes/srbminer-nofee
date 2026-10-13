#!/usr/bin/env python3
# spki_util.py —— 纯 Python 从 DER 证书提取 SPKI SHA-256（不依赖 openssl 命令）
#
#  DER 结构（RFC 5280）：
#    Certificate ::= SEQUENCE {
#        tbsCertificate,       <- 第 1 个元素
#        signatureAlgorithm,
#        signatureValue
#    }
#    TBSCertificate ::= SEQUENCE {
#        [0] version,          <- 可选
#        serialNumber,
#        signature,
#        issuer,
#        validity,
#        subject,
#        subjectPublicKeyInfo  <- ★ 我们要的就是这段的完整 DER
#    }


def _read_tlv(data, pos):
    """读一个 TLV，返回 (tag, value_start, value_len, next_pos)"""
    tag = data[pos]
    pos += 1
    ln = data[pos]
    pos += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, pos, ln, pos + ln


def extract_spki_der(cert_der: bytes) -> bytes:
    """从证书 DER 里取出 SubjectPublicKeyInfo 的完整 DER 编码"""
    # 1. 外层 SEQUENCE (Certificate)
    tag, p, ln, _ = _read_tlv(cert_der, 0)
    cert_body = p

    # 2. 第 1 个元素 = tbsCertificate (SEQUENCE)
    tag, tbs_body, tbs_len, _ = _read_tlv(cert_der, cert_body)

    # 3. 遍历 TBSCertificate 的子元素，找第 7 个（若首元素是 [0] version 则第 7，否则第 6）
    pos = tbs_body
    end = tbs_body + tbs_len
    fields = []
    while pos < end:
        tag, vstart, vlen, nxt = _read_tlv(cert_der, pos)
        fields.append((tag, pos, vstart, vlen, nxt))
        pos = nxt

    # fields 顺序: [version?] serial signature issuer validity subject spki ...
    # SPKI 的 tag 是 0x30 (SEQUENCE)
    # 用"倒数"更稳：从末尾往前，第一个 tag==0x30 且长度较大的就是 SPKI
    for f in reversed(fields):
        tag, start, vstart, vlen, nxt = f
        if tag == 0x30 and vlen > 60:      # SPKI 通常 > 60 字节
            return cert_der[start:nxt]
    raise ValueError("未能定位 SPKI")


def spki_sha256_from_der(cert_der: bytes) -> str:
    import hashlib
    return hashlib.sha256(extract_spki_der(cert_der)).hexdigest()


def spki_from_peer_cert(tls_sock) -> str:
    """从已握手的 TLS socket 取对端证书并算 SPKI"""
    der = tls_sock.getpeercert(binary_form=True)
    if not der:
        raise ValueError("拿不到对端证书")
    return spki_sha256_from_der(der)


if __name__ == "__main__":
    # 自测：用本地 cert.pem
    import ssl, sys, os
    p = sys.argv[1] if len(sys.argv) > 1 else None
    if p and os.path.exists(p):
        # PEM -> DER
        import base64
        txt = open(p, encoding="utf-8").read()
        b64 = "".join(l for l in txt.splitlines() if "-----" not in l)
        der = base64.b64decode(b64)
        print("SPKI:", spki_sha256_from_der(der))
    else:
        print("用法: python spki_util.py <cert.pem>")
