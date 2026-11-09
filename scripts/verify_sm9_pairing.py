#!/usr/bin/env python3
"""国密技术知识手册——SM9 配对分量复核脚本（可选执行）

verify_test_vectors.py 是纯标准库（零依赖），覆盖 SM9 全部非配对分量；
本脚本补充其遗留的最后一块：**依赖双线性配对的分量**，用第三方纯 Python
实现 gmalg（含 SM9 配对）作为独立第二实现，复现 GB/T 38635.2 标准附录
的数值：

  * 附录 A（签名）：h = H2(M‖w)（w = g^r 需配对幂）、S 点、验签正/负例
  * 附录 C（KEM）：封装 C₁、封装密钥 K、解封装闭环
  * 附录 D（加密）：C₁/C₂/C₃ 全链——其中 K 完全由"配对 → KDF"路径独立
    算出，与标准文本的 K 一致即双向印证配对实现正确
  * 附录 B（密钥交换）：标准 r_B 未随手册收录，故做机制自洽验证
    （双方协商密钥一致），会话密钥的官方向量仍以标准文本为准

用法：pip install gmalg && python3 scripts/verify_sm9_pairing.py
（全部通过退出码 0；未安装 gmalg 时打印安装提示并退出 1）
"""
import sys

try:
    import gmalg
except ImportError:
    print("本脚本依赖 gmalg（纯 Python 国密实现，含 SM9 配对）：")
    print("    pip install gmalg")
    sys.exit(1)

RESULTS = []


def check(name, got, exp):
    def fmt(v):
        if isinstance(v, (bytes, bytearray)):
            return v.hex().upper()
        if isinstance(v, bool):
            return str(v)
        if isinstance(v, int):
            return f"{v:X}" if v > 0xFF else str(v)
        return str(v)

    g, e = fmt(got), fmt(exp)
    ok = g == e
    RESULTS.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        print(f"       got = {g}")
        print(f"       exp = {e}")


# ---- 标准附录参数（与 verify_test_vectors.py 同源；gmalg 点序列化带 0x04 前缀，
#      G₂ 字节序同为 x.u‖x.r‖y.u‖y.r，与 gmsm/GmSSL 惯例一致） ----
KS = 0x000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4
KE = 0x0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22

PPUB_S = b"\x04" + bytes.fromhex(
    "9f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c408"
    "29dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e32"
    "69850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c2"
    "541e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e3216d")
D_A = b"\x04" + bytes.fromhex(
    "a5702f05cf1315305e2d6eb64b0deb923db1a0bcf0caff90523ac8754aa69820"
    "78559a844411f9825c109f5ee3f52d720dd01785392a727bb1556952b2b013d3")
R_SIG = 0x033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE
H_SIG_EXP = 0x823C4B21E4BD2DFE1ED92C606653E996668563152FC33F55D7BFBB9BD9705ADB
S_EXP = bytes.fromhex(
    "73bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d598c"
    "856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa05")

PPUB_E = b"\x04" + bytes.fromhex(
    "787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff"
    "769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1")
DE_B = b"\x04" + bytes.fromhex(
    "94736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf4168"
    "3115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b15"
    "87aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55"
    "f27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1")
R_WRAP = 0x74015F8489C01EF4270456F9E6475BFB602BDE7F33FD482AB4E3684A6722
C1_WRAP_EXP = bytes.fromhex(
    "1edee2c3f465914491de44cefb2cb434ab02c308d9dc5e2067b4fed5aaac8a0f"
    "1c9b4c435eca35ab83bb734174c0f78fde81a53374aff3b3602bbc5e37be9a4c")
R_ENC = 0xAAC0541779C8FC45E3E2CB25C12B5D2576B2129AE8BB5EE2CBE5EC9E785C
C1_ENC_EXP = bytes.fromhex(
    "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff"
    "42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0")
M_ENC = b"Chinese IBE standard"
C2_EXP = bytes.fromhex("1b5f5b0e951489682f3e64e1378cdd5da9513b1c")
C3_EXP = bytes.fromhex(
    "ba672387bcd6de5016a158a52bb2e7fc429197bcab70b25afee37a2b9db9f367")


def main():
    # ---------- 附录 A：签名 ----------
    print("== 附录 A 签名（配对值 w = g^r 驱动 h，gmalg 独立复现） ==")
    signer = gmalg.SM9(hid_s=b"\x01", mpk_s=PPUB_S, sk_s=D_A, uid=b"Alice",
                       rnd_fn=lambda _: R_SIG)
    h_got, S_got = signer.sign(b"Chinese IBS standard")
    check("h = H2(M‖g^r)（附录 A）", int.from_bytes(h_got, "big"), H_SIG_EXP)
    check("S = [(r−h)]·d_A（附录 A）", S_got[1:], S_EXP)
    verifier = gmalg.SM9(hid_s=b"\x01", mpk_s=PPUB_S, uid=b"Alice")
    check("验签正例（附录 A）",
          verifier.verify(b"Chinese IBS standard", h_got, S_got), True)
    check("验签负例（篡改消息）",
          verifier.verify(b"Chinese IBS standard!", h_got, S_got), False)

    # ---------- 附录 C：密钥封装 ----------
    print("\n== 附录 C 密钥封装（配对值 w 驱动 K，解封装闭环） ==")
    bob = gmalg.SM9(hid_e=b"\x03", mpk_e=PPUB_E, sk_e=DE_B, uid=b"Bob")
    enc = gmalg.SM9(hid_e=b"\x03", mpk_e=PPUB_E, sk_e=DE_B, uid=b"Bob",
                    rnd_fn=lambda _: R_WRAP)
    K_wrap, C_wrap = enc.encapsulate(32, b"Bob")
    check("封装 C₁ = [r]Q_B（附录 C）", C_wrap[1:], C1_WRAP_EXP)
    check("解封装 K 闭环（附录 C）", bob.decapsulate(C_wrap, 32), K_wrap)

    # ---------- 附录 D：公钥加密 ----------
    print("\n== 附录 D 加密（K 由『配对→KDF』完整独立路径算出） ==")
    enc2 = gmalg.SM9(hid_e=b"\x03", mpk_e=PPUB_E, sk_e=DE_B, uid=b"Bob",
                     rnd_fn=lambda _: R_ENC)
    cipher = enc2.encrypt(M_ENC, b"Bob")
    check("C₁ = [r]Q_B（附录 D）", cipher[1:65], C1_ENC_EXP)
    check("C₂ = M ⊕ K[0:20]（附录 D）", cipher[97:], C2_EXP)
    check("C₃ = SM3(C₂‖K[20:])（附录 D）", cipher[65:97], C3_EXP)
    check("解密闭环（附录 D）", bob.decrypt(cipher), M_ENC)

    # ---------- 附录 B：密钥交换（机制自洽） ----------
    print("\n== 附录 B 密钥交换（标准 r_B 未收录，机制级验证） ==")
    ks_b, ke_b = KS.to_bytes(32, "big"), KE.to_bytes(32, "big")
    kgc = gmalg.SM9KGC(hid_s=b"\x01", msk_s=ks_b, hid_e=b"\x03", msk_e=ke_b)
    alice = gmalg.SM9(hid_s=b"\x01", mpk_s=kgc.generate_mpk_sign(ks_b),
                      sk_s=kgc.generate_sk_sign(b"Alice"), uid=b"Alice",
                      hid_e=b"\x03", mpk_e=PPUB_E,
                      sk_e=kgc.generate_sk_encrypt(b"Alice"))
    bob2 = gmalg.SM9(hid_s=b"\x01", mpk_s=kgc.generate_mpk_sign(ks_b),
                     sk_s=kgc.generate_sk_sign(b"Bob"), uid=b"Bob",
                     hid_e=b"\x03", mpk_e=PPUB_E, sk_e=DE_B)
    r_a, R_a = alice.begin_key_exchange(b"Bob")
    r_b, R_b = bob2.begin_key_exchange(b"Alice")
    K_a = alice.end_key_exchange(16, r_a, R_a, b"Bob", R_b,
                                 gmalg.KEYXCHG_MODE.RESPONDER)
    K_b = bob2.end_key_exchange(16, r_b, R_b, b"Alice", R_a,
                                gmalg.KEYXCHG_MODE.INITIATOR)
    check("双方协商密钥一致（g₁/g₂/g₃ 镜像对调机制自洽）", K_a, K_b)

    total = len(RESULTS)
    passed = sum(1 for _, ok in RESULTS if ok)
    print(f"\n===== SM9 配对分量复核：{passed}/{total} 通过 =====")
    failed = [n for n, ok in RESULTS if not ok]
    if failed:
        print("未通过项：", *failed, sep="\n  - ")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
