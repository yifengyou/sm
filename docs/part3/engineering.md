# 国密算法工程实现

算法原理（第二部分）解决"对不对"，工程实现解决"好不好用、能不能落地"。本章覆盖软件库选型、多语言代码实战、硬件与接口标准、性能工程与迁移策略。

## 1. 软件栈全景

| 生态 | 库 | 覆盖 | 备注 |
| --- | --- | --- | --- |
| C/C++ | **GmSSL** | SM2/SM3/SM4/SM9/ZUC、TLCP、证书 | 北京大学团队，自带 CLI 工具链，3.x 版本 API 重构 |
| C/C++ | **Tongsuo（铜锁，原 BabaSSL）** | OpenSSL 全量 + TLCP/NTLS、RFC 8998、SM2/SM3/SM4/SM9 | 蚂蚁集团主导的 OpenSSL 分支，国密 Web 场景首选，多架构汇编优化 |
| C | **OpenSSL（原生）** | 1.1.1+：SM2 曲线/签名、SM3、SM4（ECB/CBC/CTR/OFB/CFB）；3.0+：SM4-GCM/CCM（EVP 层）；3.2：SM4-XTS、ARM SIMD；3.6：Intel SM4 新指令加速；4.0：RFC 8998 TLS 1.3 套件 | **不含 TLCP/双证书**，国密 HTTPS 需换 Tongsuo |
| Java | **BouncyCastle** | SM2/SM3/SM4/SM9、证书、CMS/PKCS | JCE + 轻量 API 双形态，生态最广 |
| Java | 腾讯 Kona / 各厂商 SDK | TLS 1.3 国密、TLCP | 面向 App 客户端接入 |
| Go | **emmansun/gmsm** | SM2/SM3/SM4/SM9/ZUC、PKCS#7/#8/#12、smx509、CFCA 互操作、DRBG、TLS 1.3 混合密钥交换 | 生产级，多架构 SIMD（amd64/arm64/riscv64/loong64…），性能对标 Go 标准库 P-256 |
| Go | Trisia/gotlcp | TLCP 协议栈 | gmsm 作者配套 |
| Python | gmssl / pyCryptodome 扩展 | 基础算法 | 原型验证为主 |
| JavaScript | sm-crypto、jsrsasign-sm、sjcl-sm | SM2/SM3/SM4 | 浏览器端轻量场景 |
| Rust | smcrypto 等 | 基础算法 | 生态在成长期 |

选型速断：

- **国密 HTTPS（TLCP 双证书）**：Tongsuo（服务端）+ Tongsuo/gotlcp/Kona（客户端）；
- **应用层国密（签名/加密/摘要）**：C 系 GmSSL/Tongsuo、Java BC、Go gmsm 三足鼎立，按技术栈选；
- **合规/密评项目**：优先"有商用密码产品认证证书的密码模块/密码机"，开源库用于业务逻辑层封装与联调；
- **研究/原型**：任何实现先跑标准 KAT（SM3"abc"、SM4 单分组、SM2 曲线校验、ZUC 全零向量）。

## 2. 命令行实战（GmSSL / OpenSSL）

```bash
# ---------- GmSSL 3.x 专用工具（以 GmSSL 3.1 为例） ----------
gmssl sm2keygen -out priv.pem                    # 生成 SM2 私钥
gmssl sm2sign -key priv.pem -in msg.bin -out sig.der    # 签名（DER）
gmssl sm2verify -pubkey pub.pem -sig sig.der -in msg.bin
gmssl sm2encrypt -pubkey pub.pem -in msg.bin -out ct.bin
gmssl sm2decrypt -key priv.pem -in ct.bin -out pt.bin
gmssl sm3 -in msg.bin                            # SM3 摘要
gmssl sm4enc -key <32位hex> -in msg.bin -out ct.bin
gmssl sm4dec -key <32位hex> -in ct.bin -out pt.bin

# ---------- 原生 OpenSSL（1.1.1+ 即可） ----------
printf 'abc' | openssl dgst -sm3
openssl enc -sm4-cbc -K <32hex> -iv <32hex> -in msg.bin -out ct.bin
openssl ecparam -name SM2 -genkey -noout -out key.pem   # SM2 密钥对
```

## 3. Java 实战（BouncyCastle）

```java
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.crypto.params.SM2ParameterSpec;
import org.bouncycastle.crypto.engines.SM2Engine;
import java.security.*;

Security.addProvider(new BouncyCastleProvider());

// ---------- SM2 密钥对 ----------
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
kpg.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));
KeyPair kp = kpg.generateKeyPair();

// ---------- SM2 签名（SM3withSM2，含 Z 值） ----------
Signature signer = Signature.getInstance("SM3withSM2", "BC");
signer.setParameter(new SM2ParameterSpec("1234567812345678".getBytes()));
signer.initSign(kp.getPrivate());
signer.update(message);
byte[] sig = signer.sign();                    // DER：SEQUENCE{r, s}

// 验签
signer.initVerify(kp.getPublic());
signer.update(message);
boolean ok = signer.verify(sig);

// ---------- SM2 加密（轻量 API，显式指定密文顺序） ----------
SM2Engine enc = new SM2Engine(SM2Engine.Mode.C1C3C2);   // 新国标顺序
enc.init(true, new ParametersWithRandom(kp.getPublic(), new SecureRandom()));
byte[] ct = enc.processBlock(data, 0, data.length);     // C1‖C3‖C2

// ---------- SM3 / SM4 ----------
MessageDigest md = MessageDigest.getInstance("SM3", "BC");
byte[] digest = md.digest(data);

javax.crypto.Cipher sm4 = javax.crypto.Cipher.getInstance(
    "SM4/GCM/NoPadding", "BC");               // GCM 优先，CBC 次之
```

关键点：**SM2ParameterSpec 必须与对端一致**（缺省 `"1234567812345678"`）；SM2 密文要显式约定 C1C3C2/C1C2C3 模式，BC 两种都支持。

## 4. Go 实战（emmansun/gmsm）

```go
import (
    "crypto/rand"
    "github.com/emmansun/gmsm/sm2"
    "github.com/emmansun/gmsm/sm3"
    "github.com/emmansun/gmsm/sm4"
    "github.com/emmansun/gmsm/zuc"
)

// SM3
digest := sm3.Sum([]byte("hello gmsm"))

// SM2 签名/验签（含 Z 值，缺省 UID）
priv, _ := sm2.GenerateKey(rand.Reader)
sig, _ := priv.Sign(rand.Reader, message, sm2.DefaultSM2SignerOpts)
ok := sm2.VerifyASN1WithSM2(&priv.PublicKey, nil, message, sig)

// 自定义 UID
opts := sm2.NewSM2SignerOption(true, []byte("user@corp.cn"))
sig2, _ := priv.Sign(rand.Reader, message, opts)

// SM4-GCM（AEAD）
block, _ := sm4.NewCipher(key16)
gcm, _ := cipher.NewGCM(block)
ct := gcm.Seal(nil, nonce12, plaintext, aad)

// ZUC/EEA3（流密码）
stream, _ := zuc.NewEEACipher(key16, count, bearer, direction)
stream.XORKeyStream(dst, src)
```

gmsm 的附加能力值得注意：SM9 全套、ZUC-256、PKCS#7/#8/#12 与 smx509（国密证书）、CFCA SADK 互操作、SM2 密钥对保护结构（GB/T 35276）、以及 NIST PQC（ML-KEM/ML-DSA/SLH-DSA）——最后一个预示了"国密 + 后量子"双栈的演进方向。

## 5. 硬件与接口标准

### 5.1 设备形态

| 形态 | 定位 | 接口标准 |
| --- | --- | --- |
| PCI-E 密码卡 | 服务器内置加速 | GM/T 0018（SDF） |
| 服务器密码机 | 独立设备，集群服务 | GM/T 0018（SDF）/ GM/T 0030（产品规范） |
| 云密码机/云 HSM | 云上托管实例 | SDF over 服务封装 |
| USB-Key（智能密码钥匙） | 个人私钥载体 | GM/T 0016（SKF）/ GB/T 35291 |
| 安全芯片（SE） | 嵌入式根信任 | 芯片级 COS |

### 5.2 SDF 调用骨架（GM/T 0018）

```c
void *hDevice = NULL, *hSession = NULL;
ECCrefPublicKey  pub;
ECCrefPrivateKey pri;
unsigned char sig[ECC_MAX_LEN]; unsigned int sigLen;

SDF_OpenDevice(&hDevice);                       /* 打开密码卡 */
SDF_OpenSession(hDevice, &hSession);            /* 建立会话 */
SDF_GenerateKeyPair_ECC(hSession, SGD_SM2_256,
                        &pri, &pub);            /* 密钥对在卡内生成，私钥不出卡 */
SDF_InternalSign_ECC(hSession, ..., &pri,
                     msg, msgLen, sig, &sigLen);/* 内部密钥签名 */
SDF_InternalVerifySign_ECC(hSession, ..., &pub, msg, msgLen, sig, sigLen);
SDF_ExternalDecrypt_ECC(hSession, SGD_SM2_256, &pri, ct, ctLen, pt, &ptLen);
SDF_CloseSession(hSession);
SDF_CloseDevice(hDevice);
```

（函数原型以 GM/T 0018-2012 文本为准；合规要点：**签名/解密私钥留在设备内，应用只拿到结果**——密评对"密钥不出设备"有明确检查项。）

### 5.3 典型部署拓扑

```text
App/浏览器 ──TLCP──► 国密网关（Tengine/Tongsuo nginx，双证书）──► 业务服务
                        │
                        └──SDF/TCP──► 服务器密码机集群（签名/验签/加密卸载）
```

nginx 侧：Tengine 及 Tongsuo 生态通过 `ssl_sign_certificate(_key)`、`ssl_enc_certificate(_key)` 指令配置双证书（不同版本的编译开关与 listen 参数以对应版本文档为准）。

## 6. 性能工程

**指令加速现状**（2026 视角，变化很快，落地前实测）：

| 平台 | SM3/SM4 加速路径 |
| --- | --- |
| Intel x86 | 早期无 SM4 指令 → AVX2 bitslicing/GFNI 软优化；**Lunar Lake/Arrow Lake S 起提供 SM4 指令扩展**，OpenSSL 3.6+ 支持（CBC 约 3.6×、XTS 约 9.2× 提升，官方数据） |
| ARM（鲲鹏 920 等） | ARMv8 SM3/SM4 密码扩展指令 + NEON；gmsm/OpenSSL/Tongsuo 均有相应路径 |
| RISC-V | 向量密码扩展 Zvksh（SM3）/Zvksed（SM4），gmsm 已支持 |
| 龙芯/海光等 | 各自指令集或内置引擎 |

SM2 的性能要点在第二部分已述（固定基点预计算、双标量乘、快速约简）。批量验签场景（网关逐请求验签）优先：HSM 批量接口、多核并行、必要时批验签算法。

**批验签（batch verification）展开**：ECC 签名的验签瓶颈是"每签名一次双标量乘"。批验签利用线性结构把 n 个签名的验证压成常数次大标量乘：对 n 个 `(Mᵢ, rᵢ, sᵢ)` 生成随机系数 δᵢ（防攻击者构造批内碰撞），检查 Σδᵢ·sᵢ·G + Σδᵢ·tᵢ·Pᵢ 是否等于对应 [Σδᵢ·kᵢ]G 类的聚合点（SM2 版本需按其验签方程适配，学术方案与部分密码机固件已实现）。收益：n 个签名一次验签约比逐个快 2~4 倍（n 越大越接近理论界）；代价与红线：**批内任一失败必须回退逐个验签定位**（不能整批拒绝），随机系数必须每批新生成，攻击面分析（ rogue-key/批碰撞构造）依赖系数不可预测——网关类高并发场景值得做，业务系统一般不必。

**同平台实测对照表**（本手册实测样机：AMD Ryzen 9 7945HX，OpenSSL 3.0.13 单核，`openssl speed`，2026-11。读数要点：这台机器**无 SM3/SM4 专有指令**而 AES/SHA 走 AES-NI/SHA-NI 硬件路径，所以差距是"软实现 vs 指令加速"的差距，不是算法本身的差距）：

| 运算 | 国密（软实现） | 国际（指令加速） | 比值 |
| --- | --- | --- | --- |
| SM3 大块吞吐 | 471 MB/s | SHA-256：2651 MB/s | ≈ 1:5.6 |
| SM4-CBC 大块吞吐 | 180 MB/s | AES-128-CBC：2122 MB/s | ≈ 1:11.8 |
| SM2 签名 | 4395 次/秒 | ECDSA-P256 签名：76803 次/秒 | ≈ 1:17 |
| SM2 验签 | 5144 次/秒 | ECDSA-P256 验签：25160 次/秒 | ≈ 1:4.9 |

这张表的三个工程结论：

- **有 SM 指令的平台（Lunar Lake、鲲鹏、Zvksh/Zvksed）上比值会反转或大幅收窄**——买硬件前按"实测工具速查"跑一遍，别套用本表数字；
- TLS/TLCP 网关这类"握手密集"负载，SM2 验签吞吐是配密码机数量的第一依据（表中单核 5 千次/秒 × 核数 × 密码机加速比）；
- SM4 的 1:11.8 会直接打穿"流量密集"系统的性能预算——这正是指令加速与密码卡卸载存在的理由。

**实测工具速查**（性能预算清单第 2 步的落地方法）：

```bash
# OpenSSL（1.1.1+；Tongsuo 同构且另有 TLCP 相关测速目标）
openssl speed sm3                           # SM3 吞吐
openssl speed -evp sm4-cbc                  # SM4-CBC（务必走 EVP 路径，才有优化实现）
openssl speed -evp sm4-gcm                  # 3.0+；新 Intel 平台 + 3.6+ 走 SM4 指令
openssl speed -multi $(nproc) -evp sm4-gcm  # 多核汇总

# SM2 公钥运算基准（吞吐与延迟分开测）——gmsm 仓库自带基准套件
git clone https://github.com/emmansun/gmsm && cd gmsm
go test -bench=. -benchmem ./sm2/... ./sm4/...
```

读数注意：`openssl speed` 同时输出 b/s 与 ops/s 两个口径，对照 AES 时用同一分组大小；"握手密集"负载把 SM2 签名/验签 ops/s 换算成"每核每秒握手数"，再按密码机/核数配比外推；密码机吞吐用厂商 SDF 工具压测，重点关注**并发会话下的衰减曲线**而非单连接峰值。

**性能预算清单**（做国密改造前先测）：

1. 记录现有算法吞吐基线（如 AES-GCM GB/s 级、ECDSA P-256 验签次数/秒）；
2. 测目标平台 SM4/SM2 吞吐（同一台机器，同一测试工具）；
3. 区分"握手密集"（公钥运算为主）与"流量密集"（对称运算为主）负载，分别预算；
4. 无指令加速平台预留 3~5 倍对称性能缺口，考虑密码卡卸载。

## 7. 迁移策略：从国际算法到国密

```text
阶段0 评估：资产盘点（算法使用点：传输/存储/签名/随机数）
阶段1 旁路：引入国密库，双算法能力并存，配置开关（crypto-agility）
阶段2 并行：双栈对外服务（TLS 国际+TLCP 双虚拟主机；存储双写或信封迁移）
阶段3 切流：按客户端类型灰度切到国密路径，监控握手成功率/延迟
阶段4 收敛：下线国际算法路径（或保留为应急回退，需防降级攻击）
```

关键工程纪律：

- **信封化迁移存量加密数据**：用新密钥+SM4 重加密数据密钥，避免整库重写；
- **随机数**：合规场景使用符合 GM/T 0105（软件随机数发生器设计指南）或硬件随机源的实现，`/dev/urandom` 直用在密评中会被开整改项；
- **防降级**：双栈并存期间，两个协议栈的会话、缓存、状态严格隔离；网关对"国密客户端被降级到国际套件"要有显式告警；
- **密钥分级**：主密钥（HSM 内）→ 密钥加密密钥 → 数据密钥的三层结构在国密语境同样是最佳实践，且密评有对应检查。

## 8. 测试与验证

1. **KAT 自测**：每个算法跑标准向量（本手册各章均已给出，配套 `scripts/verify_test_vectors.py` 一键复核 76 项：SM3 两条、HMAC-SM3 三组、SM4 单分组+全轮密钥、CMAC-SM4 子密钥+四组消息、ZUC 两条、EEA3 官方两例、EIA3 示例 1/2、HKDF-SM3 两组、SM2 曲线自检+签名/加密/密钥交换/确定性签名示例、RFC 8998 的 SM4-GCM/CCM 向量、SM9 非配对分量）；
2. **互操作矩阵**：自研实现 × 主流库（GmSSL/Tongsuo/BC/gmsm）两两对跑签名/加密/握手；
3. **协议模糊测试**：TLCP 握手状态机过 fuzzing（畸形 ClientHello、截断消息、乱序）；
4. **侧信道初筛**：签名/解密路径的计时方差分析（TLCCer/dudect 类工具）；
5. **密评预检**：对照 GB/T 39786 自查（见第四部分）。

---

**延伸阅读**：GmSSL 与 Tongsuo 官方文档；emmansun/gmsm 的 docs/ 目录（sm2/sm3/sm4/sm9/zuc 应用指南）；GM/T 0018/0016/0019 接口文本；guanzhi/GM-Standards 仓库（GM/T 标准文本合集）；OpenSSL CHANGES（各版本国密能力时间线）。
