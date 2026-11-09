#!/usr/bin/env python3
"""国密技术知识手册——测试向量一键复核脚本

覆盖范围（对应手册第二部分各章 + RFC 8998）：
  * SM3：GB/T 32905 附录 A 全部 KAT（"abc" / "abcd"×64）
  * HMAC-SM3：RFC 2104 构造，3 组向量（经 OpenSSL 3.0 独立实现交叉复核）
  * SM4：GB/T 32907 附录 A KAT + 全部 32 个轮密钥 + 解密对合性
  * CMAC-SM4：RFC 4493 构造移植，子密钥 + 4 组消息向量
  * ZUC：GM/T 0001.1 附录 C 官方向量（全零 / 全 FF）
  * 128-EEA3：GM/T 0001.2 附录 B 官方向量（示例 1/2，密标委官方英译本核对）
  * 128-EIA3：GM/T 0001.3 附录 B 示例 1 的 MAC、示例 2 的 IV 构造与完整 MAC
  * HKDF-SM3：RFC 5869 构造，2 组向量（经 OpenSSL 3.0 kdf 命令交叉复核）
  * SM2：sm2p256v1 曲线自检（在曲线上 / a=p−3 / [n]G=O）、
          手册 3.4 节签名示例全链路（P_A/Z_A/e/x₁/r/s）、
          手册 3.6 节确定性签名（RFC 6979 结构 + SM3）的 k/r/s、
          手册 5.4 节加密示例全链路（C₁/C₂/C₃）、
          手册 4.3 节密钥交换示例全链路（RA/RB/x̄/t/V=U/K/S_A/S_B）
  * SM4-GCM/CCM：RFC 8998 附录 A 测试向量（含 GCM/CCM 模式的独立实现）
  * SM9：GB/T 38635 曲线自检（P₁/P₂ 在曲线上、[n]P=O），附录 A 签名示例与
          附录 C/D 加密示例的全部非配对分量（主公钥、H1、用户私钥/公钥、
          C₁ 点、C₂/C₃ 公式）、附录 B 密钥交换的 R_A——配对相关分量
          （w/g^r/KDF 密钥）依赖双线性对，以标准文本为准

用法：python3 scripts/verify_test_vectors.py    （全部通过退出码 0，否则 1）
依赖：仅 Python 标准库（3.8+）。
"""
import struct
import sys

M32 = 0xFFFFFFFF
RESULTS = []


def check(name, got, exp):
    def fmt(v):
        if isinstance(v, (bytes, bytearray)):
            return v.hex().upper()
        if isinstance(v, bool):
            return str(int(v))
        if isinstance(v, int):
            return f"{v:08X}" if 0 <= v <= 0xFFFFFFFF else f"{v:X}"
        return str(v)

    g, e = fmt(got), fmt(exp)
    ok = g == e
    RESULTS.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        print(f"       got = {g}")
        print(f"       exp = {e}")


def rol(x, n):
    n %= 32
    return ((x << n) | (x >> (32 - n))) & M32 if n else x


def i2b(x, length):
    return x.to_bytes(length, "big")


def hmac_sm3(key: bytes, msg: bytes) -> bytes:
    """HMAC-SM3（RFC 2104 构造：SM3 块长 64、输出 32）"""
    if len(key) > 64:
        key = sm3(key)
    key = key + b"\x00" * (64 - len(key))
    ipad = bytes(k ^ 0x36 for k in key)
    opad = bytes(k ^ 0x5C for k in key)
    return sm3(opad + sm3(ipad + msg))


def hkdf_sm3_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-SM3 extract（RFC 5869：salt 为空时取 32 字节零，即 HashLen）"""
    return hmac_sm3(salt if salt else b"\x00" * 32, ikm)


def hkdf_sm3_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SM3 expand（RFC 5869：T(i) = HMAC(PRK, T(i-1)‖info‖i)）"""
    t, okm, i = b"", b"", 1
    while len(okm) < length:
        t = hmac_sm3(prk, t + info + bytes([i]))
        okm += t
        i += 1
    return okm[:length]


# ----------------------------------------------------------------------
# SM3（GB/T 32905-2016 / 原GM/T 0004-2012）
# ----------------------------------------------------------------------
SM3_IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
          0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]


def sm3_p0(x):
    return x ^ rol(x, 9) ^ rol(x, 17)


def sm3_p1(x):
    return x ^ rol(x, 15) ^ rol(x, 23)


def sm3(msg: bytes) -> bytes:
    ml = len(msg) * 8
    msg = msg + b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += struct.pack(">Q", ml)

    V = SM3_IV[:]
    for off in range(0, len(msg), 64):
        W = list(struct.unpack(">16I", msg[off:off + 64]))
        for j in range(16, 68):
            W.append(sm3_p1(W[j - 16] ^ W[j - 9] ^ rol(W[j - 3], 15))
                     ^ rol(W[j - 13], 7) ^ W[j - 6])
        Wp = [W[j] ^ W[j + 4] for j in range(64)]

        A, B, C, D, E, F, G, H = V
        for j in range(64):
            T = 0x79CC4519 if j < 16 else 0x7A879D8A
            SS1 = rol((rol(A, 12) + E + rol(T, j)) & M32, 7)
            SS2 = SS1 ^ rol(A, 12)
            FF = (A ^ B ^ C) if j < 16 else ((A & B) | (A & C) | (B & C))
            GG = (E ^ F ^ G) if j < 16 else ((E & F) | ((E ^ M32) & G))
            TT1 = (FF + D + SS2 + Wp[j]) & M32
            TT2 = (GG + H + SS1 + W[j]) & M32
            D, C, B, A = C, rol(B, 9), A, TT1
            # 注意：F 取“轮前的 E”（F ← E），这是手册 SM3 章强调的高发笔误点
            H, G, F, E = G, rol(F, 19), E, sm3_p0(TT2)
        V = [v ^ x for v, x in zip(V, [A, B, C, D, E, F, G, H])]
    return struct.pack(">8I", *V)


# ----------------------------------------------------------------------
# SM4（GB/T 32907-2016 / 原GM/T 0002-2012）
# ----------------------------------------------------------------------
SM4_SBOX = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c05"
    "2b679a762abe04c3aa44132649860699"
    "9c4250f491ef987a33540b43edcfac62"
    "e4b31ca9c908e89580df94fa758f3fa6"
    "4707a7fcf37317ba83593c19e6854fa8"
    "686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887"
    "d40046579fd327524c3602e7a0c4c89e"
    "eabf8ad240c738b5a3f7f2cef96115a1"
    "e0ae5da49b341a55ad933230f58cb1e3"
    "1df6e22e8266ca60c02923ab0d534e6f"
    "d5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad8"
    "0ac13188a5cd7bbd2d74d012b8e5b4b0"
    "8969974a0c96777e65b9f109c56ec684"
    "18f07dec3adc4d2079ee5f3ed7cb3948")
SM4_FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]


def sm4_tau(x):
    return ((SM4_SBOX[x >> 24] << 24)
            | (SM4_SBOX[(x >> 16) & 0xFF] << 16)
            | (SM4_SBOX[(x >> 8) & 0xFF] << 8)
            | SM4_SBOX[x & 0xFF])


def sm4_l(b):
    return b ^ rol(b, 2) ^ rol(b, 10) ^ rol(b, 18) ^ rol(b, 24)


def sm4_lp(b):
    return b ^ rol(b, 13) ^ rol(b, 23)


def sm4_ck(i):
    return sum(((4 * i + j) * 7 % 256) << (24 - 8 * j) for j in range(4))


def sm4_key_schedule(mk):
    K = list(struct.unpack(">4I", mk))
    K = [K[i] ^ SM4_FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        rk.append(K[i] ^ sm4_lp(sm4_tau(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ sm4_ck(i))))
        K.append(rk[-1])
    return rk


def sm4_crypt(block, rk):
    X = list(struct.unpack(">4I", block))
    for i in range(32):
        X.append(X[i] ^ sm4_l(sm4_tau(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i])))
    return struct.pack(">4I", X[35], X[34], X[33], X[32])


def sm4_enc(key16, block16):
    """单分组加密 E(K, B)：GCM/CCM 模式的底层调用"""
    return sm4_crypt(block16, sm4_key_schedule(key16))


def sm4_cmac(key: bytes, msg: bytes) -> bytes:
    """CMAC-SM4（GB/T 15852.1 / RFC 4493 结构移植）：
    子密钥 L→K1→K2 在 GF(2^128) 上乘 x（约减常数 0x87），与 AES-CMAC 同构"""
    rk = sm4_key_schedule(key)
    l = int.from_bytes(sm4_crypt(b"\x00" * 16, rk), "big")
    k1 = ((l << 1) ^ (0x87 if l >> 127 else 0)) & ((1 << 128) - 1)
    k2 = ((k1 << 1) ^ (0x87 if k1 >> 127 else 0)) & ((1 << 128) - 1)
    k1b, k2b = k1.to_bytes(16, "big"), k2.to_bytes(16, "big")
    n = (len(msg) + 15) // 16
    if n == 0:
        body, last = b"", bytes(a ^ b for a, b in zip(
            (1).to_bytes(16, "big"), k2b))
    elif len(msg) % 16 == 0:
        body, last = msg[:-16], bytes(a ^ b for a, b in zip(msg[-16:], k1b))
    else:
        pad = msg + b"\x80" + b"\x00" * (15 - len(msg) % 16)
        body, last = msg[: (len(msg) // 16) * 16], bytes(
            a ^ b for a, b in zip(pad[-16:], k2b))
    x = b"\x00" * 16
    for i in range(0, len(body), 16):
        x = sm4_crypt(bytes(a ^ b for a, b in zip(x, body[i:i + 16])), rk)
    return sm4_crypt(bytes(a ^ b for a, b in zip(x, last)), rk)


# ----------------------------------------------------------------------
# ZUC（GM/T 0001.1-2012 / GB/T 33133.1-2016）
# ----------------------------------------------------------------------
ZUC_P = (1 << 31) - 1


def zuc_addm(a, b):
    c = a + b
    return (c & 0x7FFFFFFF) + (c >> 31)


def zuc_mul_pow2(x, k):
    return ((x << k) | (x >> (31 - k))) & 0x7FFFFFFF


ZUC_S0 = bytes.fromhex(
    "3e725b47cae0003304d1549809b96dcb" "7b1bf932af9d6aa5b82dfc1d08530390"
    "4d4e8499e4ced991ddb685488b296eac" "cdc1f81e734369c6b5bdfd396320d438"
    "767db2a7cfed57c5f32cbb142106559b" "e3ef5e314f7f5aa40d8251495fba581c"
    "4a16d517a892241f8cffd8ae2e01d3ad" "3b4bda46ebc9de9a8f87d73a806f2fc8"
    "b1b437f70a2213287ccc3c89c7c39656" "07bf7ef00b2b975235417961a64c10fe"
    "bc2695888ab0a3fbc01894f2e1e5e95d" "d0dc1166645cec59427512f5749caa23"
    "0e86abbe2a02e767e644a26cc2939ff1" "f6fa36d250689e6271153dd640c4e20f"
    "8e83776b25053f0c30ea70b7a1e8a965" "8d271adb81b3a0f4457a19dfee783460")
ZUC_S1 = bytes.fromhex(
    "55c263713bc847869f3cda5b29aafd77" "8cc5940ca61a1300e3a8167240f9f842"
    "4426689681d9453e1076c6a78b3943e1" "3ab5562ac06db3052266bfdc0bfa6248"
    "dd20110636c9c1cff62752bb69f5d487" "7f844cd29c57a4bc4f9adffed68d7aeb"
    "2b53d85ca11417fb23d57d3067730809" "eeb7703f61b2198e4ee54b938f5ddba9"
    "adf1ae2ecb0dfcf42d466e1d97e8d1e9" "4d37a5755e839eab829db91ce0cd4989"
    "01b6bd5824a25f387899159050b895e4" "d091c7ceed0fb46fa0ccf0024a79c3de"
    "a3efea51e66b18ec1b2c80f774e7ff21" "5a6a541e41319235c433070aba7e0e34"
    "88b1987cf33d606c7bcad31f32650428" "64be859b2f598ad7b025acaf1203e2f2")
ZUC_D = [0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
         0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC]


def zuc_l1(x):
    return x ^ rol(x, 2) ^ rol(x, 10) ^ rol(x, 18) ^ rol(x, 24)


def zuc_l2(x):
    return x ^ rol(x, 8) ^ rol(x, 14) ^ rol(x, 22) ^ rol(x, 30)


def zuc_s(w):
    b = [(w >> 24) & 0xFF, (w >> 16) & 0xFF, (w >> 8) & 0xFF, w & 0xFF]
    o = [ZUC_S0[b[0]], ZUC_S1[b[1]], ZUC_S0[b[2]], ZUC_S1[b[3]]]
    return (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]


class ZUC:
    """祖冲之序列密码：LFSR(素域GF(2^31-1)) + BR(比特重组) + F(非线性函数)"""

    def __init__(self, key: bytes, iv: bytes):
        assert len(key) == 16 and len(iv) == 16
        self.s = [(key[i] << 23) | (ZUC_D[i] << 8) | iv[i] for i in range(16)]
        self.R1 = self.R2 = 0
        for _ in range(32):                      # 初始化 32 拍（F 输出右移1位进 LFSR）
            self._br()
            w = self._f()
            self._lfsr(u=w >> 1)
        self._br()
        self._f()                                # 丢弃一拍
        self._lfsr()

    def _br(self):
        s = self.s
        self.X0 = (((s[15] >> 15) & 0xFFFF) << 16) | (s[14] & 0xFFFF)
        self.X1 = ((s[11] & 0xFFFF) << 16) | (s[9] >> 15)
        self.X2 = ((s[7] & 0xFFFF) << 16) | (s[5] >> 15)
        self.X3 = ((s[2] & 0xFFFF) << 16) | (s[0] >> 15)

    def _f(self):
        W = ((self.X0 ^ self.R1) + self.R2) & 0xFFFFFFFF
        W1 = (self.R1 + self.X1) & 0xFFFFFFFF   # 模加
        W2 = self.R2 ^ self.X2                   # 异或
        u = zuc_l1(((W1 << 16) & 0xFFFFFFFF) | (W2 >> 16))
        v = zuc_l2(((W2 << 16) & 0xFFFFFFFF) | (W1 >> 16))
        self.R1, self.R2 = zuc_s(u), zuc_s(v)
        return W

    def _lfsr(self, u=None):
        s = self.s
        v = zuc_addm(s[0], zuc_mul_pow2(s[0], 8))     # (1+2^8)·s0
        v = zuc_addm(v, zuc_mul_pow2(s[4], 20))       # 2^20·s4
        v = zuc_addm(v, zuc_mul_pow2(s[10], 21))      # 2^21·s10
        v = zuc_addm(v, zuc_mul_pow2(s[13], 17))      # 2^17·s13
        v = zuc_addm(v, zuc_mul_pow2(s[15], 15))      # 2^15·s15
        if u is not None:
            v = zuc_addm(v, u)
        self.s = s[1:] + [v if v else ZUC_P]

    def next_word(self):
        self._br()
        z = self._f() ^ self.X3
        self._lfsr()
        return z


def eia3_iv(count: int, bearer: int, direction: int) -> bytes:
    """128-EIA3 的 IV 构造（GB/T 33133.3 附录 A.2）"""
    iv = bytearray(16)
    iv[0:4] = count.to_bytes(4, "big")
    iv[4] = (bearer << 3) & 0xFF
    iv[8] = iv[0] ^ ((direction << 7) & 0xFF)
    iv[9:12] = iv[1:4]
    iv[12] = iv[4]
    iv[13] = iv[5]
    iv[14] = iv[6] ^ ((direction << 7) & 0xFF)
    iv[15] = iv[7]
    return bytes(iv)


def eia3_mac(ik: bytes, count, bearer, direction, length_bits, msg: bytes) -> int:
    """128-EIA3：置位窗口累加式 MAC（bit 计数 MSB-first）"""
    L = (length_bits + 31) // 32 + 2
    z = ZUC(ik, eia3_iv(count, bearer, direction))
    ks = b"".join(z.next_word().to_bytes(4, "big") for _ in range(L))

    def window(i):  # 密钥流第 i 比特起的 32 位窗口
        v = 0
        for j in range(i, i + 32):
            v = (v << 1) | ((ks[j >> 3] >> (7 - (j & 7))) & 1)
        return v

    bits = "".join(f"{b:08b}" for b in msg)[:length_bits]
    T = 0
    for i, c in enumerate(bits):
        if c == "1":
            T ^= window(i)
    T ^= window(length_bits)
    return T ^ window(32 * (L - 1))


def eea3_iv(count: int, bearer: int, direction: int) -> bytes:
    """128-EEA3 的 IV 构造（GM/T 0001.2 附录 A.2）：
    IV[0..3]=COUNT；IV[4]=BEARER(5位)‖DIRECTION(1位)‖00(2位)；
    IV[5..7]=0；IV[8..11]=IV[0..3]；IV[12..15]=IV[4..7]
    注意与 EIA3 不同：EEA3 的方向位进 IV[4]，且 IV[8] 不与方向位异或"""
    iv = bytearray(16)
    iv[0:4] = count.to_bytes(4, "big")
    iv[4] = ((bearer << 3) | (direction << 2)) & 0xFF
    iv[5:8] = b"\x00\x00\x00"
    iv[8:12] = iv[0:4]
    iv[12:16] = iv[4:8]
    return bytes(iv)


def eea3(ck: bytes, count, bearer, direction, msg: bytes) -> bytes:
    """128-EEA3：ZUC 密钥流与明文按位异或（加密解密同体）"""
    words = (len(msg) * 8 + 31) // 32
    z = ZUC(ck, eea3_iv(count, bearer, direction))
    ks = b"".join(z.next_word().to_bytes(4, "big") for _ in range(words))
    return bytes(m ^ k for m, k in zip(msg, ks))


# ----------------------------------------------------------------------
# SM2（GB/T 32918-2016 / 原GM/T 0003-2012）
# ----------------------------------------------------------------------
SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_A = SM2_P - 3
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
SM2_G = (SM2_GX, SM2_GY)


def ec_add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and (y1 + y2) % SM2_P == 0:
        return None
    if P1 == P2:
        lam = (3 * x1 * x1 + SM2_A) * pow(2 * y1, -1, SM2_P) % SM2_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, SM2_P) % SM2_P
    x3 = (lam * lam - x1 - x2) % SM2_P
    return (x3, (lam * (x1 - x3) - y1) % SM2_P)


def ec_mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = ec_add(r, pt)
        pt = ec_add(pt, pt)
        k >>= 1
    return r


def sm2_kdf(z: bytes, klen: int) -> bytes:
    """GB/T 32918.1 附录：SM3 计数器模式 KDF"""
    out, ct = b"", 1
    while len(out) < klen:
        out += sm3(z + ct.to_bytes(4, "big"))
        ct += 1
    return out[:klen]


def sm2_z(uid: bytes, pub) -> bytes:
    """Z 值 = SM3(ENTL‖ID‖a‖b‖Gx‖Gy‖x_A‖y_A)"""
    entl = (len(uid) * 8).to_bytes(2, "big")
    return sm3(entl + uid
               + i2b(SM2_A, 32) + i2b(SM2_B, 32)
               + i2b(SM2_GX, 32) + i2b(SM2_GY, 32)
               + i2b(pub[0], 32) + i2b(pub[1], 32))


# ----------------------------------------------------------------------
# 复核用例
# ----------------------------------------------------------------------
def main():
    print("== SM3（GB/T 32905 附录 A） ==")
    check('SM3("abc")', sm3(b"abc"),
          bytes.fromhex("66c7f0f462eeedd9d1f2d46bdc10e4e2"
                        "4167c4875cf2f7a2297da02b8f4ba8e0"))
    check('SM3("abcd"×64)', sm3(b"abcd" * 64),
          bytes.fromhex("b965764c8bebb091c7602b74afd34eef"
                        "b531dccb4e0076d9b7cd813199b45971"))

    print()
    print("== HMAC-SM3（RFC 2104 构造，经 OpenSSL 交叉复核） ==")
    check('HMAC-SM3(key=0x0b×20, "Hi There")',
          hmac_sm3(b"\x0b" * 20, b"Hi There"),
          bytes.fromhex("51b00d1fb49832bfb01c3ce27848e59f"
                        "871d9ba938dc563b338ca964755cce70"))
    check('HMAC-SM3("key", "The quick brown fox…")',
          hmac_sm3(b"key", b"The quick brown fox jumps over the lazy dog"),
          bytes.fromhex("bd4a34077888162b210645b8ebf74b9a"
                        "f357303789357a27c7fc457244ebd398"))
    check('HMAC-SM3(key=0xAA×131 超长密钥, 54B 消息)',
          hmac_sm3(b"\xaa" * 131,
                   b"Test Using Larger Than Block-Size Key - Hash Key First"),
          bytes.fromhex("b4fd844e13342002f0b2e0690ea7741f"
                        "1497d993a70494cea601e657bedf67a0"))

    print("\n== SM4（GB/T 32907 附录 A） ==")
    mk = bytes.fromhex("0123456789abcdeffedcba9876543210")
    rk = sm4_key_schedule(mk)
    check("SM4 KAT（密钥=明文的巧合向量）", sm4_crypt(mk, rk),
          bytes.fromhex("681edf34d206965e86b3e94f536e4246"))
    doc_rk = [int(w, 16) for w in """
        F12186F9 41662B61 5A6AB19A 7BA92077 367360F4 776A0C61 B6BB89B3 24763151
        A520307C B7584DBD C30753ED 7EE55B57 6988608C 30D895B7 44BA14AF 104495A1
        D120B428 73B55FA3 CC874966 92244439 E89E641F 98CA015A C7159060 99E1FD2E
        B79BD80C 1D2115B0 0E228AEB F1780C81 428D3654 62293496 01CF72E5 9124A012
    """.split()]
    check("SM4 全部 32 个轮密钥", 1 if rk == doc_rk else 0, 1)
    check("SM4 解密=逆序轮密钥再加密", sm4_crypt(sm4_crypt(mk, rk), rk[::-1]), mk)

    print()
    print("== CMAC-SM4（RFC 4493 构造移植） ==")
    ck = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    crk = sm4_key_schedule(ck)
    l0 = int.from_bytes(sm4_crypt(b"\x00" * 16, crk), "big")
    k1 = ((l0 << 1) ^ (0x87 if l0 >> 127 else 0)) & ((1 << 128) - 1)
    k2 = ((k1 << 1) ^ (0x87 if k1 >> 127 else 0)) & ((1 << 128) - 1)
    check("L = E_K(0¹²⁸)", l0.to_bytes(16, "big"),
          bytes.fromhex("09cbe15d851b5b0bbba4ca42eae3ff70"))
    check("K1 = L·x（0x87 回卷）", k1.to_bytes(16, "big"),
          bytes.fromhex("1397c2bb0a36b61777499485d5c7fee0"))
    check("K2 = K1·x", k2.to_bytes(16, "big"),
          bytes.fromhex("272f8576146d6c2eee93290bab8ffdc0"))
    m16 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    m40 = m16 + bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51") + m16[:8]
    m64 = m40 + m16[:8] + bytes.fromhex(
        "30c81c46a35ce411e5fbc1191a0a52ef") + m16[:4]
    check("CMAC-SM4(空消息)", sm4_cmac(ck, b""),
          bytes.fromhex("178ae41f93ec6e9c430864360932ef6b"))
    check("CMAC-SM4(16B 整块)", sm4_cmac(ck, m16),
          bytes.fromhex("4e4c2a4417e567fef081e0fab55a5762"))
    check("CMAC-SM4(40B 非整块)", sm4_cmac(ck, m40),
          bytes.fromhex("d221ad48e4318a5b308a91b915d7f75b"))
    check("CMAC-SM4(64B)", sm4_cmac(ck, m64),
          bytes.fromhex("6ce2999f2464aefe04396323135ba08c"))

    print("\n== ZUC（GM/T 0001.1 附录 C） ==")
    z = ZUC(b"\x00" * 16, b"\x00" * 16)
    check("ZUC 向量1 z1（全零密钥/IV）", z.next_word(), 0x27BEDE74)
    check("ZUC 向量1 z2", z.next_word(), 0x018082DA)
    z = ZUC(b"\xff" * 16, b"\xff" * 16)
    check("ZUC 向量2 z1（全FF密钥/IV）", z.next_word(), 0x0657CFA0)
    check("ZUC 向量2 z2", z.next_word(), 0x7096398B)

    print("\n== 128-EIA3（GM/T 0001.3 附录 B） ==")
    check("EIA3 示例1 MAC（IK=0,COUNT=0,BEARER=0,DIR=0,LEN=1bit,M=0）",
          eia3_mac(b"\x00" * 16, 0, 0, 0, 1, b"\x00"), 0xC8A9595E)
    check("EIA3 示例2 IV 构造（COUNT=A94059DA,BEARER=A,DIR=1）",
          eia3_iv(0xA94059DA, 0xA, 1),
          bytes.fromhex("a94059da50000000294059da50008000"))
    # 示例2 完整验证：IK=C9E6…, LENGTH=0x241=577bit（72B 消息 + 1 个 0 比特）
    eia3_m2 = bytes.fromhex(
        "983b41d47d780c9e1ad11d7eb70391b1de0b35da2dc62f83e7b78d6306ca0ea0"
        "7e941b7be91348f9fcb170e2217fecd97f9f68adb16e5d7d21e569d280ed775c"
        "ebde3f4093c5388100")
    check("EIA3 示例2 完整 MAC（577bit 完整消息）",
          eia3_mac(bytes.fromhex("c9e6cec4607c72db000aefa88385ab0a"),
                   0xA94059DA, 0xA, 1, 577, eia3_m2), 0xFAE8FF0B)

    print("\n== 128-EEA3（GM/T 0001.2 附录 B 官方向量） ==")
    check("EEA3 示例1 IV（COUNT=66035492,BEARER=F,DIR=0）",
          eea3_iv(0x66035492, 0xF, 0),
          bytes.fromhex("66035492780000006603549278000000"))
    # 示例1：LENGTH=0xC1=193bit（24 整字节 + 1 个 0 比特），仅有效位参与比较
    eea3_c1 = eea3(bytes.fromhex("173d14ba5003731d7a60049470f00a29"),
                   0x66035492, 0xF, 0,
                   bytes.fromhex("6cf65340735552ab0c9752fa6f9025fe"
                                 "0bd675d9005875b200"))
    check("EEA3 示例1 密文（前 24 字节）", eea3_c1[:24],
          bytes.fromhex("a6c85fc66afb8533aafc2518dfe784940ee1e4b030238cc8"))
    check("EEA3 示例1 第 193 位密文位", (eea3_c1[24] >> 7) & 1, 0)
    check("EEA3 示例2 IV（COUNT=00056823,BEARER=18,DIR=1）",
          eea3_iv(0x56823, 0x18, 1),
          bytes.fromhex("00056823c400000000056823c4000000"))
    eea3_c2 = eea3(bytes.fromhex("e5bd3ea0eb55ade866c6ac58bd54302a"),
                   0x56823, 0x18, 1,
                   bytes.fromhex(
                       "14a8ef693d678507bbe7270a7f67ff5006c3525b9807e467c4e56000"
                       "ba338f5d429559036751822246c80d3b"
                       "38f07f4be2d8ff5805f5132229bde93bbbdcaf382bf1ee972fbf9977"
                       "bada8945847a2a6c9ad34a667554e04d1f7fa2c33241bd8f01ba220d"))
    check("EEA3 示例2 密文（LENGTH=0x320=800bit 整字节）", eea3_c2,
          bytes.fromhex(
              "131d43e0dea1be5c5a1bfd971d852cbf712d7b4f57961fea3208afa8bca433f4"
              "56ad09c7417e58bc69cf8866d1353f74865e80781d202dfb3ecff7fcbc3b190f"
              "e82a204ed0e350fc0f6f2613b2f2bca6df5a473a57a4a00d985ebad880d6f238"
              "64a07b01"))

    print("\n== SM2 曲线自检（GB/T 32918.5） ==")
    check("Gy² ≡ Gx³+ax+b (mod p)",
          (SM2_GY * SM2_GY - (SM2_GX ** 3 + SM2_A * SM2_GX + SM2_B)) % SM2_P, 0)
    check("a = p − 3", SM2_A, SM2_P - 3)
    check("[n]G = O（无穷远点）", 1 if ec_mul(SM2_N, SM2_G) is None else 0, 1)

    print("\n== SM2 签名示例（手册 3.4 节，缺省 ID） ==")
    d_a = 0x3945208F7B2144B13F36E38AC6D3989E4E42A33E18C4A28A9280C43B7D4F23C7
    k_s = 0x6CB28D99385C175C75F7C80F08E505B530191B5DCDC80AA5B61CB5A5F9F0A8AD
    pa = ec_mul(d_a, SM2_G)
    check("P_A = [d_A]G", 1 if pa == (
        0xDDBF0694F9FFF658829C198F0F820DE0A4559C55B221A3CB142BA778D8ED6825,
        0xEE70DF71AF0C930852B62B892F1E9F586F64B81DA07632D76E3BBDEC6B17916E) else 0, 1)
    z_a = sm2_z(b"1234567812345678", pa)
    check("Z_A", z_a,
          bytes.fromhex("fd415d660b901cebe89e83fb916a5d0695ce8789e31cf550fd28b36f2a8ab749"))
    e = int.from_bytes(sm3(z_a + b"message digest"), "big")
    check("e = SM3(Z_A‖M)", e,
          0xB97B7E0C4EFA4AFD03661733539CAEE29F84790831784D4F282604ABCD0B725E)
    x1 = ec_mul(k_s, SM2_G)[0]
    check("x₁ = [k]G.x", x1,
          0x69B1F01122463B72C5EFC4E529350CAA9F1E86EAFC1098A6A2864C7805139849)
    r = (e + x1) % SM2_N
    check("r = (e+x₁) mod n", r,
          0x232D6E1E7140866FC955DC187CD1BB8DCC9F20880BC2E0CA76F05D1A9849C984)
    s = pow(1 + d_a, -1, SM2_N) * (k_s - r * d_a) % SM2_N
    check("s = (1+d)⁻¹(k−rd) mod n", s,
          0x35A4EB74DDC465AB33D53BDCEE3DB7F4E318E864795C3DE78CEC9BC63E5DCF4A)

    print()
    print("== SM2 确定性签名（手册 3.6 节，RFC 6979 结构 + SM3） ==")

    def sm2_derive_k(d: int, e: int):
        """RFC 6979 的 HMAC 循环移植：HMAC→HMAC-SM3，q=n，h1=e（mod n）"""
        q = SM2_N
        int2octets = lambda x: x.to_bytes(32, "big")
        h1 = e % q
        bho = int2octets(h1)
        V = b"\x01" * 32
        K = b"\x00" * 32
        K = hmac_sm3(K, V + b"\x00" + int2octets(d) + bho)
        V = hmac_sm3(K, V)
        K = hmac_sm3(K, V + b"\x01" + int2octets(d) + bho)
        V = hmac_sm3(K, V)
        while True:
            T = b""
            while len(T) < 32:
                V = hmac_sm3(K, V)
                T += V
            k = int.from_bytes(T, "big")
            if 1 <= k <= q - 1:
                yield k
            K = hmac_sm3(K, V + b"\x00")
            V = hmac_sm3(K, V)

    for k_det in sm2_derive_k(d_a, e):
        x1d = ec_mul(k_det, SM2_G)[0]
        rd = (e + x1d) % SM2_N
        if rd == 0 or rd + k_det == SM2_N:
            continue
        sd = pow(1 + d_a, -1, SM2_N) * (k_det - rd * d_a) % SM2_N
        if sd == 0:
            continue
        check("确定性 k（RFC 6979 结构派生）", k_det, int(
            "78F1C31494614F9931F7752C0E605982"
            "BA2D5CAA412CCA61FD5D0FB5DB34B66E", 16))
        check("确定性签名 r", rd, int(
            "EA3A91414124E6D2A6BCB670FBCEE293"
            "1B9983FDE8739D36D21AD2CF25B48975", 16))
        check("确定性签名 s", sd, int(
            "30EDC7CAE5892B6A421A5C4FDDB229D2"
            "F485B9D9FA36848378AD7C99CBA860DB", 16))
        break

    print("\n== SM2 加密示例（手册 5.4 节） ==")
    d_b = 0x3F59C7DD1D3F84B1B2A9F5A4021EBFA6C9CD3B6E2E5F0C4A0F4D07C8C3B3E1D3
    k_e = 0x7E0E9A5C3F8B7D2A6E1F4C0B9D8A3E7215C6B0F4D2E8A1C3B7F9E5D04A6C2B88
    c1 = ec_mul(k_e, SM2_G)
    check("C₁ = [k]G", 1 if c1 == (
        0xF5AF3EE5F35827F745419C3DBDC344B41F320FBC101D6984CF6F517CB7A23B67,
        0x3458CD1538936CBC8967EDFE21720FDFDFBA14F6E8B14E9F8961D61476FD7858) else 0, 1)
    x2, y2 = ec_mul(k_e, ec_mul(d_b, SM2_G))
    t = sm2_kdf(i2b(x2, 32) + i2b(y2, 32), 19)
    c2 = bytes(m ^ ti for m, ti in zip(b"encryption standard", t))
    check("C₂ = M ⊕ KDF(x₂‖y₂)", c2,
          bytes.fromhex("f6668dc249e64fc87de845f6be52f68113e698"))
    c3 = sm3(i2b(x2, 32) + b"encryption standard" + i2b(y2, 32))
    check("C₃ = SM3(x₂‖M‖y₂)", c3,
          bytes.fromhex("72bf3d0ba986804c18bedddd822c750061de9ec8dd1324f542377e55d2dab533"))

    print()
    print("== SM2 密钥交换（手册 4.3 节，自选参数全链路） ==")
    d_kx_a = 0x4C8F63C398AC90CB18B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C
    d_kx_b = 0x1D06E1F3BE6D3E38AC6D3989E4E42A33E18C4A28A9280C43B7D4F23C739459A2
    r_kx_a = 0x7E0E9A5C3F8B7D2A6E1F4C0B9D8A3E7215C6B0F4D2E8A1C3B7F9E5D04A6C2B88
    r_kx_b = 0x5A8C2D9E3F1B7A6C0D4E8F2A6B9C1D3E5F7A0B2C4D6E8F1A3B5C7D9E0F2A4B6C8
    P_kxA = ec_mul(d_kx_a, SM2_G)
    P_kxB = ec_mul(d_kx_b, SM2_G)
    Z_kxA = sm2_z(b"1234567812345678", P_kxA)
    Z_kxB = sm2_z(b"1234567812345678", P_kxB)
    RA_pt = ec_mul(r_kx_a, SM2_G)
    RB_pt = ec_mul(r_kx_b, SM2_G)
    check("RA = [r_A]G", 1 if RA_pt == (
        0xF5AF3EE5F35827F745419C3DBDC344B41F320FBC101D6984CF6F517CB7A23B67,
        0x3458CD1538936CBC8967EDFE21720FDFDFBA14F6E8B14E9F8961D61476FD7858) else 0, 1)
    check("RB = [r_B]G", 1 if RB_pt == (
        0x269401AD265BC406DA5903F5CD4D2CDD5FDB5A7A1366C799C1D6AE01549F1B51,
        0x2AA065843664DE39C4B39F1B429336EF92954383596496733E8D0A2D04B29524) else 0, 1)
    w = 127                                     # w = ⌈⌈log2 n⌉/2⌉ − 1 = 127
    fold = lambda x: (1 << w) + (x & ((1 << w) - 1))
    xbA = fold(RA_pt[0])
    xbB = fold(RB_pt[0])
    check("x̄_A = 2^127 + (RA.x & (2^127−1))", xbA,
          0x9F320FBC101D6984CF6F517CB7A23B67)
    check("x̄_B = 2^127 + (RB.x & (2^127−1))", xbB,
          0xDFDB5A7A1366C799C1D6AE01549F1B51)
    t_a = (d_kx_a + xbA * r_kx_a) % SM2_N
    t_b = (d_kx_b + xbB * r_kx_b) % SM2_N
    check("t_A = (d_A + x̄_A·r_A) mod n", t_a,
          0x9570D2C131D2F29B6533F2EB26196922E01BECBAE394B3D6ACD4C744B9D2AFBB)
    check("t_B = (d_B + x̄_B·r_B) mod n", t_b,
          0x396F65FF96AEBA1C199D26C39E3E25FC7235EB8FBB038130D55C073BAF36C5FE)
    V_pt = ec_mul(t_b, ec_add(P_kxA, ec_mul(xbA, RA_pt)))   # B 侧共享点
    U_pt = ec_mul(t_a, ec_add(P_kxB, ec_mul(xbB, RB_pt)))   # A 侧共享点
    check("V = [t_B](P_A + [x̄_A]RA)", 1 if V_pt == (
        0x03FADB8917756A2D7B5646D5D54A2549BEC6F3FF45219D0F59D42DE1008502B0,
        0xD156686A55BBF87C7DDE8F8EE71358DF2AAF022109AAC276672077EEC6CF0937) else 0, 1)
    check("U = [t_A](P_B + [x̄_B]RB) 且 U = V", 1 if U_pt == V_pt else 0, 1)
    kx_k = sm2_kdf(i2b(V_pt[0], 32) + i2b(V_pt[1], 32) + Z_kxA + Z_kxB, 16)
    check("K = KDF(x_V‖y_V‖Z_A‖Z_B, 16)", kx_k,
          bytes.fromhex("b017243aad01b6079daf6cc2dc3e2f41"))
    inner_b = (i2b(V_pt[0], 32) + Z_kxA + Z_kxB + i2b(xbA, 32) + i2b(xbB, 32)
               + i2b(RB_pt[0], 32) + i2b(RB_pt[1], 32))
    s_b = sm3(b"\x02" + i2b(V_pt[1], 32) + sm3(inner_b))
    inner_a = (i2b(V_pt[0], 32) + Z_kxA + Z_kxB + i2b(xbA, 32) + i2b(xbB, 32)
               + i2b(RA_pt[0], 32) + i2b(RA_pt[1], 32))
    s_a = sm3(b"\x03" + i2b(V_pt[1], 32) + sm3(inner_a))
    check("S_B = Hash(02‖y_V‖Hash(x_V‖Z_A‖Z_B‖x̄_A‖x̄_B‖RB))", s_b,
          bytes.fromhex("9478a012aa50b467b2648fee273155c563e4c6b14f467cacb977d344de73b064"))
    check("S_A = Hash(03‖y_U‖Hash(x_U‖Z_A‖Z_B‖x̄_A‖x̄_B‖RA))", s_a,
          bytes.fromhex("4e67ecff1d125558bac89f532f7422e3d2bea0747ec8fe773d54ae0cbdf8718f"))

    print()
    print("== HKDF-SM3（RFC 5869 构造，经 OpenSSL kdf 交叉复核） ==")
    prk1 = hkdf_sm3_extract(bytes(range(0x00, 0x0D)), b"\x0b" * 22)
    check("用例1 PRK = HMAC(salt, IKM)", prk1,
          bytes.fromhex("e0d6f7b0bd056327b7659f1f39ad8505"
                        "61fbcf4fb10fb58e88eafa55cf7cd01e"))
    check("用例1 OKM（salt=13B, info=10B, L=42）",
          hkdf_sm3_expand(prk1, bytes(range(0xF0, 0xFA)), 42),
          bytes.fromhex("c69fe91b7aaee2dd5718d72dcaee0cce"
                        "93f1b8e41f792da51261b6a517e68b36"
                        "ed2c595572b01dfa359b"))
    prk2 = hkdf_sm3_extract(b"", b"\x11" * 32)
    check("用例2 PRK（salt 为空 → 32 字节零）", prk2,
          bytes.fromhex("017a01368be62168dca3c5a3e6bf119a"
                        "64c14d6b6f18c596f69440a2386d0ba0"))
    check("用例2 OKM（info='tlcp session key', L=16）",
          hkdf_sm3_expand(prk2, b"tlcp session key", 16),
          bytes.fromhex("18ab6a719741d1ff20ecf9b8da6eec0d"))

    # ------------------------------------------------------------------
    # SM4-GCM / SM4-CCM（RFC 8998 附录 A）
    # ------------------------------------------------------------------
    print("\n== SM4-GCM / SM4-CCM（RFC 8998 附录 A） ==")

    def gcm_mult(x, y):
        R = 0xE1 << 120
        z, v = 0, y
        for i in range(127, -1, -1):
            if (x >> i) & 1:
                z ^= v
            v = (v >> 1) ^ R if v & 1 else v >> 1
        return z

    def ghash(h, a, c):
        pad = lambda b: b + b"\x00" * ((16 - len(b) % 16) % 16)
        data = pad(a) + pad(c) + struct.pack(">QQ", len(a) * 8, len(c) * 8)
        y = 0
        for i in range(0, len(data), 16):
            y = gcm_mult(y ^ int.from_bytes(data[i:i + 16], "big"), h)
        return y

    def gcm_encrypt(key, iv, pt, aad):
        h = int.from_bytes(sm4_enc(key, b"\x00" * 16), "big")
        j0 = iv + b"\x00\x00\x00\x01"            # 96 位 IV 的 J0
        ct, ctr = b"", int.from_bytes(j0[12:], "big")
        for i in range(0, len(pt), 16):
            ctr = (ctr + 1) % 2**32               # 加密计数块自 inc32(J0) 起
            ks = sm4_enc(key, j0[:12] + ctr.to_bytes(4, "big"))
            ct += bytes(p ^ k for p, k in zip(pt[i:i + 16], ks))
        tag = int.from_bytes(sm4_enc(key, j0), "big") ^ ghash(h, aad, ct)
        return ct, tag.to_bytes(16, "big")

    def ccm_encrypt(key, nonce, pt, aad, tlen=16, q=3):
        """RFC 3610 / SP 800-38C，参数按 RFC 8998：n=12、t=16、q=3"""
        flags0 = (0x40 if aad else 0) | (((tlen - 2) // 2) << 3) | (q - 1)
        b0 = bytes([flags0]) + nonce + len(pt).to_bytes(q, "big")
        x = sm4_enc(key, b0)
        if aad:
            alen = len(aad)
            ab = (alen.to_bytes(2, "big") if alen < 0xFF00
                  else b"\xFF\xFE" + alen.to_bytes(8, "big")) + aad
            ab += b"\x00" * ((16 - len(ab) % 16) % 16)
            for i in range(0, len(ab), 16):
                x = sm4_enc(key, bytes(u ^ v for u, v in zip(x, ab[i:i + 16])))
        pp = pt + b"\x00" * ((16 - len(pt) % 16) % 16)
        for i in range(0, len(pp), 16):
            x = sm4_enc(key, bytes(u ^ v for u, v in zip(x, pp[i:i + 16])))
        ctr = lambda i: bytes([q - 1]) + nonce + i.to_bytes(q, "big")
        ct, k = b"", 1
        for i in range(0, len(pt), 16):
            ks = sm4_enc(key, ctr(k)); k += 1
            ct += bytes(p ^ s for p, s in zip(pt[i:i + 16], ks))
        tag = bytes(u ^ v for u, v in zip(x[:tlen], sm4_enc(key, ctr(0))))
        return ct, tag

    rk = bytes.fromhex("0123456789abcdeffedcba9876543210")
    riv = bytes.fromhex("00001234567800000000abcd")
    rpt = bytes.fromhex("aa" * 8 + "bb" * 8 + "cc" * 8 + "dd" * 8
                        + "ee" * 8 + "ff" * 8 + "ee" * 8 + "aa" * 8)
    raad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    ct, tag = gcm_encrypt(rk, riv, rpt, raad)
    check("SM4-GCM 密文（RFC 8998 A.1）", ct,
          bytes.fromhex("17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735"
                        "d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d"))
    check("SM4-GCM 标签（RFC 8998 A.1）", tag,
          bytes.fromhex("83de3541e4c2b58177e065a9bf7b62ec"))
    ct2, tag2 = ccm_encrypt(rk, riv, rpt, raad)
    check("SM4-CCM 密文（RFC 8998 A.2）", ct2,
          bytes.fromhex("48af93501fa62adbcd414cce6034d895dda1bf8f132f042098661572e7483094"
                        "fd12e518ce062c98acee28d95df4416bed31a2f04476c18bb40c84a74b97dc5b"))
    check("SM4-CCM 标签（RFC 8998 A.2）", tag2,
          bytes.fromhex("16842d4fa186f56ab33256971fa110f4"))

    # ------------------------------------------------------------------
    # SM9（GB/T 38635 附录 A/B/C/D 的全部非配对分量）
    # ------------------------------------------------------------------
    print("\n== SM9（GB/T 38635.2 附录 A/B/C/D，非配对分量） ==")
    SM9_P = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D
    SM9_N = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25
    SM9_G1 = (0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD,
              0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616)
    # P₂（扭曲线 E': y² = x³ + 5u 上的生成元；F_p² = F_p[u]/(u²+2)，元素记 (r, w) = r + w·u）
    SM9_G2 = ((0x3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B,
               0x85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141),
              (0xA7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7,
               0x17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96))

    def f2_add(a, b): return ((a[0] + b[0]) % SM9_P, (a[1] + b[1]) % SM9_P)
    def f2_sub(a, b): return ((a[0] - b[0]) % SM9_P, (a[1] - b[1]) % SM9_P)
    def f2_mul(a, b): return ((a[0] * b[0] - 2 * a[1] * b[1]) % SM9_P,
                              (a[0] * b[1] + a[1] * b[0]) % SM9_P)
    def f2_inv(a):
        t = pow(a[0] * a[0] + 2 * a[1] * a[1], -1, SM9_P)
        return ((a[0] * t) % SM9_P, (-a[1] * t) % SM9_P)

    def tw_add(Pt, Qt):
        if Pt is None: return Qt
        if Qt is None: return Pt
        x1, y1 = Pt; x2, y2 = Qt
        if x1 == x2 and f2_add(y1, y2) == (0, 0): return None
        if Pt == Qt:
            lam = f2_mul(f2_mul((3, 0), f2_mul(x1, x1)), f2_inv(f2_mul((2, 0), y1)))
        else:
            lam = f2_mul(f2_sub(y2, y1), f2_inv(f2_sub(x2, x1)))
        x3 = f2_sub(f2_sub(f2_mul(lam, lam), x1), x2)
        y3 = f2_sub(f2_mul(lam, f2_sub(x1, x3)), y1)
        return (x3, y3)

    def tw_mul(k, Pt):
        r = None
        while k:
            if k & 1: r = tw_add(r, Pt)
            Pt = tw_add(Pt, Pt); k >>= 1
        return r

    def tw_marshal(Pt):  # 序列化：x.u ‖ x.r ‖ y.u ‖ y.r（GM 系实现惯例）
        x, y = Pt
        return (x[1].to_bytes(32, "big") + x[0].to_bytes(32, "big")
                + y[1].to_bytes(32, "big") + y[0].to_bytes(32, "big"))

    def sm9_add(Pt, Qt):  # G₁：y² = x³ + 5 (mod p)
        if Pt is None: return Qt
        if Qt is None: return Pt
        x1, y1 = Pt; x2, y2 = Qt
        if x1 == x2 and (y1 + y2) % SM9_P == 0: return None
        if Pt == Qt:
            lam = (3 * x1 * x1) * pow(2 * y1, -1, SM9_P) % SM9_P
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, SM9_P) % SM9_P
        x3 = (lam * lam - x1 - x2) % SM9_P
        return (x3, (lam * (x1 - x3) - y1) % SM9_P)

    def sm9_g1_mul(k, Pt):
        r = None
        while k:
            if k & 1: r = sm9_add(r, Pt)
            Pt = sm9_add(Pt, Pt); k >>= 1
        return r

    def sm9_g1_marshal(Pt):
        return Pt[0].to_bytes(32, "big") + Pt[1].to_bytes(32, "big")

    def sm9_h1(z: bytes) -> int:
        """GB/T 38635.1 密码函数：SM3×2 取前 40 字节，(mod (n-1)) + 1"""
        ha = (sm3(b"\x01" + z + (1).to_bytes(4, "big"))
              + sm3(b"\x01" + z + (2).to_bytes(4, "big")))
        return (int.from_bytes(ha[:40], "big") % (SM9_N - 1)) + 1

    check("P₁ 在 y²=x³+5 (mod p) 上", (SM9_G1[1] ** 2 - (SM9_G1[0] ** 3 + 5)) % SM9_P, 0)
    check("[n]P₁ = O", 0 if sm9_g1_mul(SM9_N, SM9_G1) is None else 1, 0)
    lx, ly = SM9_G2
    check("P₂ 在 y²=x³+5u (F_p²) 上",
          1 if f2_mul(ly, ly) == f2_add(f2_mul(f2_mul(lx, lx), lx), (0, 5)) else 0, 1)
    check("[n]P₂ = O", 0 if tw_mul(SM9_N, SM9_G2) is None else 1, 0)

    # ---- 附录 A 签名示例（Alice / "Chinese IBS standard" / hid=01） ----
    s_mk = 0x000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4
    check("Ppub-s = [s]P₂（附录 A）", tw_marshal(tw_mul(s_mk, SM9_G2)),
          bytes.fromhex("9f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c408"
                        "29dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e32"
                        "69850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c2"
                        "541e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e3216d"))
    h1 = sm9_h1(b"Alice" + bytes([1]))
    ta = s_mk * pow(s_mk + h1, -1, SM9_N) % SM9_N
    da = sm9_g1_mul(ta, SM9_G1)
    check("d_A = [s·(s+h₁)⁻¹]P₁（附录 A）", sm9_g1_marshal(da),
          bytes.fromhex("a5702f05cf1315305e2d6eb64b0deb923db1a0bcf0caff90523ac8754aa69820"
                        "78559a844411f9825c109f5ee3f52d720dd01785392a727bb1556952b2b013d3"))
    r_sig = 0x033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE
    h_sig = 0x823C4B21E4BD2DFE1ED92C606653E996668563152FC33F55D7BFBB9BD9705ADB
    check("S = [(r−h)]·d_A（附录 A）",
          sm9_g1_marshal(sm9_g1_mul((r_sig - h_sig) % SM9_N, da)),
          bytes.fromhex("73bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d598c"
                        "856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa05"))

    # ---- 附录 C/D 加密示例（Bob / "Chinese IBE standard" / hid=03） ----
    ke_mk = 0x0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22
    ppub_e = sm9_g1_mul(ke_mk, SM9_G1)
    check("Ppub-e = [ke]P₁（附录 C/D）", sm9_g1_marshal(ppub_e),
          bytes.fromhex("787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff"
                        "769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1"))
    hb = sm9_h1(b"Bob" + bytes([3]))
    tb = ke_mk * pow(ke_mk + hb, -1, SM9_N) % SM9_N
    check("de_B = [ke·(ke+h_B)⁻¹]P₂（附录 C/D）", tw_marshal(tw_mul(tb, SM9_G2)),
          bytes.fromhex("94736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf4168"
                        "3115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b15"
                        "87aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55"
                        "f27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1"))
    qb = sm9_add(sm9_g1_mul(hb, SM9_G1), ppub_e)
    check("Q_B = [h_B]P₁ + Ppub-e（附录 C/D）", sm9_g1_marshal(qb),
          bytes.fromhex("709d165808b0a43e2574e203fa885abcbab16a240c4c1916552e7c43d09763b8"
                        "693269a6be2456f43333758274786b6051ff87b7f198da4ba1a2c6e336f51fcc"))
    r_wrap = 0x74015F8489C01EF4270456F9E6475BFB602BDE7F33FD482AB4E3684A6722
    check("封装 C₁ = [r]Q_B（附录 C）", sm9_g1_marshal(sm9_g1_mul(r_wrap, qb)),
          bytes.fromhex("1edee2c3f465914491de44cefb2cb434ab02c308d9dc5e2067b4fed5aaac8a0f"
                        "1c9b4c435eca35ab83bb734174c0f78fde81a53374aff3b3602bbc5e37be9a4c"))
    r_enc = 0xAAC0541779C8FC45E3E2CB25C12B5D2576B2129AE8BB5EE2CBE5EC9E785C
    check("加密 C₁ = [r]Q_B（附录 D）", sm9_g1_marshal(sm9_g1_mul(r_enc, qb)),
          bytes.fromhex("2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff"
                        "42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0"))
    k_enc = bytes.fromhex("58373260f067ec48667c21c144f8bc33cd3049788651ffd5f738003e51df311"
                          "74d0e4e402fd87f4581b612f74259db574f67ece6")  # KDF(C₁‖w‖ID_B, 52)
    m_enc = b"Chinese IBE standard"
    exp_ct = bytes.fromhex(
        "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff"
        "42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0b"
        "a672387bcd6de5016a158a52bb2e7fc429197bcab70b25afee37a2b9db9f36"
        "71b5f5b0e951489682f3e64e1378cdd5da9513b1c")
    c2 = bytes(m ^ k for m, k in zip(m_enc, k_enc))
    check("C₂ = M ⊕ K[0:klen]（附录 D）", c2, exp_ct[96:])
    check("C₃ = SM3(C₂‖K[klen:])（附录 D）", sm3(c2 + k_enc[len(m_enc):]), exp_ct[64:96])

    # ---- 附录 B 密钥交换：发起方临时值 ----
    kex_mk = 0x0002E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F
    ppub_kex = sm9_g1_mul(kex_mk, SM9_G1)
    qb2 = sm9_add(sm9_g1_mul(sm9_h1(b"Bob" + bytes([2])), SM9_G1), ppub_kex)
    r_a = 0x5879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8
    check("R_A = [r_A]·([h_B]P₁+Ppub-e)（附录 B）",
          b"\x04" + sm9_g1_marshal(sm9_g1_mul(r_a, qb2)),
          bytes.fromhex("047cba5b19069ee66aa79d490413d11846b9ba76dd22567f809cf23b6d964bb2"
                        "65a9760c99cb6f706343fed05637085864958d6c90902aba7d405fbedf7b781599"))

    total = len(RESULTS)
    passed = sum(1 for _, ok in RESULTS if ok)
    print(f"\n===== 复核结果：{passed}/{total} 通过 =====")
    failed = [name for name, ok in RESULTS if not ok]
    if failed:
        print("未通过项：", *failed, sep="\n  - ")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
