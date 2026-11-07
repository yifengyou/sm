#!/usr/bin/env python3
"""国密技术知识手册——测试向量一键复核脚本

覆盖范围（对应手册第二部分各章）：
  * SM3：GB/T 32905 附录 A 全部 KAT（"abc" / "abcd"×64）
  * SM4：GB/T 32907 附录 A KAT + 全部 32 个轮密钥 + 解密对合性
  * ZUC：GM/T 0001.1 附录 C 官方向量（全零 / 全 FF）
  * 128-EIA3：GM/T 0001.3 附录 B 示例 1 的 MAC 与示例 2 的 IV 构造
  * SM2：sm2p256v1 曲线自检（在曲线上 / a=p−3 / [n]G=O）、
          手册 3.4 节签名示例全链路（P_A/Z_A/e/x₁/r/s）、
          手册 5.4 节加密示例全链路（C₁/C₂/C₃）

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
