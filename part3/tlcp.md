# TLCP 传输层密码协议

TLCP（Transport Layer Cryptographic Protocol，传输层密码协议）是国密版的 TLS，标准为 **GB/T 38636-2020（前身 GM/T 0054-2018）**。它以 TLS 1.2 为骨架，全面替换密码算法（SM2/SM3/SM4）并引入国密体系最具标志性的设计——**双证书**。国密 HTTPS、国密 SSL VPN 网关、政务/金融专线网关的核心协议就是它。

标准沿革：

```text
GM/T 0024-2014《SSL VPN 技术规范》──► GM/T 0054-2018《传输层密码协议 TLCP》──► GB/T 38636-2020
（各厂商 GM SSL 双证书协议的收敛统一）        （独立成标准）                        （国家标准）
```

另有一条"现代化路线"：**RFC 8998** 在标准 TLS 1.3 上直接叠加国密套件（单证书、AEAD、1-RTT），见本章第 10 节——两者是**并列而非替代**关系。

## 1. 双证书：TLCP 的灵魂

TLCP 规定服务器（双向认证时客户端同样）必须同时出示**两张证书**：

| 证书 | 密钥用途 | 私钥持有人 | X.509 Key Usage |
| --- | --- | --- | --- |
| **签名证书** | 身份认证：签 CertificateVerify / ServerKeyExchange | 服务器自己（本地生成密钥对） | digitalSignature / nonRepudiation |
| **加密证书** | 密钥封装：SM2 加密预主密钥 | 密钥对由 CA/密管中心（KMC）生成，加密私钥历史上在 KMC 托管 | keyEncipherment / dataEncipherment |

设计动机来自国密 PKI 的密管制度（见证书一章）：加密私钥可被合规托管（支持司法调证/密钥恢复），而签名私钥绝不可托管（否则可伪造签名）。把两种职能拆成两张证书、两把私钥，就形成了"签名私钥自主保管 + 加密私钥可托管"的制度性分权。

工程影响：

- 部署国密 HTTPS 必须同时配置两对证书/私钥（`-cert/-key` + `-cert2/-key2`）；
- Certificate 消息中**签名证书在前、加密证书在后**，顺序不能错；
- 证书签发、续期、撤销都要"成对"管理，运维复杂度高于国际 TLS。

## 2. 协议常量与记录层

- **协议版本**：`0x0101`（TLS 是 3.0~3.4 版本号体系，TLCP 单独编号，记录层与握手消息中均填 `01 01`）；
- **记录层结构**：与 TLS 完全同构——`类型(1) ‖ 版本(2) ‖ 长度(2) ‖ 载荷`，握手/alert/change_cipher_spec/application_data 四种类型；
- **CBC 套件记录层**：TLS 1.2 风格的 MAC-then-encrypt：
  ```text
  MAC = HMAC-SM3(mac_key, seq_num ‖ type ‖ version ‖ length ‖ fragment)
  密文记录 = 显式IV ‖ SM4-CBC(fragment ‖ MAC)
  ```
- **GCM 套件记录层**：AEAD（SM4-GCM），AAD = `seq_num ‖ type ‖ version ‖ length`，nonce 由 key_block 派生材料 + 记录序号构成（TLS 1.2 GCM 风格）；
- 密钥块 key_block 按"客户端 MAC 密钥 → 服务端 MAC 密钥 → 客户端加密密钥 → 服务端加密密钥 → 客户端 IV → 服务端 IV"的顺序切分（CBC 套件 MAC 密钥为 HMAC-SM3 的 32 字节密钥、加密密钥 16 字节、IV 16 字节；GCM 套件无独立 MAC 密钥）；
- 遗留告警码：TLCP 保留了 GM/T 0024 时代的国密专有告警（如 200 UNSUPPORTED_SITE2SITE、203 BAD_IBCPARAM 等，源于 SSL VPN 网关互联时代）。

## 3. 密码套件

GB/T 38636 定义的套件（双字节编码；名称沿用 GB/T 38636 风格）：

| 套件 | 编码 | 密钥交换 | 认证 | 说明 |
| --- | --- | --- | --- | --- |
| ECC_SM4_CBC_SM3 | `{E0,13}` | SM2 静态（加密证书） | 签名证书 | 无前向保密 |
| ECC_SM4_GCM_SM3 | `{E0,53}` | 同上 | 同上 | AEAD，优先选择 |
| ECDHE_SM4_CBC_SM3 | `{E0,11}` | SM2 临时密钥 | 签名证书签名 | 有前向保密 |
| ECDHE_SM4_GCM_SM3 | `{E0,51}` | 同上 | 同上 | **推荐默认** |
| IBSDH_SM9_SM4_CBC/GCM_SM3 | `{E0,15}`/`{E0,55}` | SM9 密钥交换 | SM9 标识 | 依赖 KGC 体系 |
| IBC_SM9_SM4_CBC/GCM_SM3 | `{E0,17}`/`{E0,57}` | SM9 加密 | SM9 标识 | 同上 |
| RSA_SM4_CBC/GCM_SM3 | `{E0,19}`/`{E0,59}` | RSA | RSA 证书 | 国际证书过渡场景 |
| （遗留）ECC_SM1_SM3 等 | `{E0,01}`/`{E0,03}` | SM2 + SM1 | — | GM/T 0024 时代，仅硬件网关 |

（编码值与 Tongsuo 等主流实现核对一致。）

## 4. 握手全流程

以最常用的 **ECDHE 套件 + 单向认证**为主线（`*` 为双向认证时出现）：

```text
Client                                                          Server
------                                                          ------
1. ClientHello ──────────────────────────────────────────────────►
   client_version=0x0101、Random(32)、会话ID、
   支持的套件列表（如 ECC/ECDHE_SM4_GCM_SM3）

                                                                  2. ServerHello ◄─────────────────────────────
                                                                     选定版本 0x0101、Random、选定套件
                                                                  3. Certificate ◄────────────────────────────
                                                                     签名证书 + 加密证书（先签名后加密）
                                                                  4. ServerKeyExchange ◄─────────────────────
                                                                     服务器临时 SM2 公钥 +
                                                                     用【签名证书私钥】对
                                                                     (ClientRandom‖ServerRandom‖临时公钥)
                                                                     的 SM2 签名
                                                                  5. [CertificateRequest*] ◄────────────────
                                                                  6. ServerHelloDone ◄───────────────────────

7. [ClientCertificate*] ────────────────────────────────────────►
   （客户端双证书）
8. ClientKeyExchange ───────────────────────────────────────────►
   ECC 套件：48 字节随机预主密钥，
     用【服务器加密证书公钥】SM2 加密（DER 封装，字段序遵循 GM/T 0009）
   ECDHE 套件：客户端临时 SM2 公钥
9. [CertificateVerify*] ────────────────────────────────────────►
   客户端【签名证书私钥】SM2 签名握手摘要
10. ChangeCipherSpec + Finished ────────────────────────────────►
    Finished 校验值 = PRF 的 12 字节输出（见下节）
                                                                  11. ChangeCipherSpec + Finished ◄─────────
其后进入应用数据阶段（SM4 加密 + HMAC-SM3/AEAD 记录层）
```

会话恢复与 TLS 1.2 相同：ClientHello 带上先前 session_id，服务端命中缓存即可走简化握手（ServerHello → ChangeCipherSpec → Finished …），省去证书与公钥运算。

## 5. 密钥推导

```text
预主密钥（48 字节）：
  ECC 套件   客户端生成 48 字节随机数 → SM2(加密证书公钥) 加密后放入 ClientKeyExchange
  ECDHE 套件 双方临时密钥对做 ECDHE，取共享点 x 坐标，左侧补零至 48 字节

PRF          TLS 1.2 风格，HMAC-SM3 为基础：
             PRF(secret, label, seed) = P_<HMAC-SM3>(secret, label ‖ seed)

master_secret = PRF(pre_master_secret, "master secret",
                   ClientRandom ‖ ServerRandom)[0..48]

key_block     = PRF(master_secret, "key expansion",
                    ServerRandom ‖ ClientRandom)      # 注意此处 ServerRandom 在前
                → 切出双方 MAC/加密密钥与 IV（见第 2 节）

verify_data   = PRF(master_secret, finished_label,
                    SM3(此前全部握手消息))[0..12]      # finished_label：
                                                    # "client finished"/"server finished"
```

为什么 ECDHE 套件要做"证书签名 + 临时密钥"：SM2 临时公钥本身没有身份，用签名证书的私钥对（双方随机数 + 临时公钥）签名，既完成身份认证又保证密钥新鲜性——这正是 TLS 的 ECDHE 思想在 SM2 上的重演（注意：这里**没有**直接使用 GB/T 32918.3 的 SM2 密钥交换协议，TLCP 是 TLS 式的组合构造）。

## 6. 记录层与会话安全属性

- **完整性**：所有记录带 HMAC-SM3（CBC）或 GCM 标签，序号参与 MAC/AAD，防重放靠序号窗口；
- **机密性**：SM4-CBC（遗留）或 SM4-GCM（推荐）；
- **前向保密**：只有 ECDHE 套件具备。ECC 套件下，服务器加密私钥一旦泄露（或被托管方调取），历史全部流量可解——这是双证书制度与生俱来的属性，选型时必须明示业务方。

## 7. 安全性分析：与 TLS 1.2 同病，与 TLS 1.3 有代差

| 议题 | TLCP 现状 | 说明 |
| --- | --- | --- |
| CBC 填充预言 | 存在（Lucky13 类） | MAC-then-encrypt 的 TLS 1.2 遗留病；优先选 GCM 套件 |
| 前向保密 | ECDHE 套件有 | ECC 套件无（见上） |
| 重协商/降级 | TLCP 取消了 TLS 重协商 | 但网关若同时开国际 TLS+国密双栈，需警惕跨协议降级（ALPN/SNI 区分） |
| SM2 签名随机数 | 协议不感知 | 服务端签名私钥的 k 若弱/重用即灾难（见 SM2 章），HSM 内签名是正解 |
| 握手轮次 | 2-RTT（TLS 1.2 同级） | 对比 TLS 1.3 的 1-RTT/0-RTT 有移动端体验差距 |
| 算法后量子 | 无 | 国密体系后量子标准化（如 ML-KEM 商密化引入）尚在演进，TLCP 框架可扩展 |

**结论性建议**：新建系统优先 `ECDHE_SM4_GCM_SM3`；必须兼容存量网关时至少强制 GCM；把"TLCP 双证书 + ECDHE"当作国密合规的现代基线。

## 8. RFC 8998：TLS 1.3 的国密套件

RFC 8998（2021，独立提交，IETF 注明"非 IETF 推荐"）在标准 TLS 1.3 上叠加国密：

```text
CipherSuite   TLS_SM4_GCM_SM3 = { 0x00, 0xC6 }      # AEAD_SM4_GCM
CipherSuite   TLS_SM4_CCM_SM3 = { 0x00, 0xC7 }      # AEAD_SM4_CCM
SignatureScheme  sm2sig_sm3  = 0x0708               # TLS 1.3 签名方案
NamedGroup    curveSM2      = 41                    # supported_groups/key_share
```

要点与细节：

- **单证书**：沿用 TLS 1.3 证书体系，一张 SM2 证书（digitalSignature 用途）即可，无双证书；
- **SM2 标识符（Z 值 ID）规则**——容易踩坑的细节：
  - TLS 1.3 握手内签名（CertificateVerify）统一使用 `"TLSv1.3+GM+Cipher+Suite"`；
  - 验证证书里的 CA 签名时使用缺省 `"1234567812345678"`（但以签发 CA 的实际声明为准）；
- 密钥调度完全遵循 TLS 1.3 的 HKDF 体系（RFC 8446），不使用 SM2 密钥交换协议；
- AEAD 参数：SM4-GCM/CCM 均为 16 字节密钥、12 字节 nonce、16 字节标签；
- RFC 附录给出 SM4-GCM/SM4-CCM 测试向量（如 SM4-GCM：Key=`0123456789ABCDEFFEDCBA9876543210`，IV=`00001234567800000000ABCD`，AAD=`FEEDFACEDEADBEEF…`，64 字节 A..F 明文 → 密文 `17F399F0…1233B8D`，标签 `83DE3541E4C2B58177E065A9BF7B62EC`），实现自测首选。

**TLCP 与 RFC 8998 选型对照**：

| 维度 | TLCP（GB/T 38636） | TLS 1.3 + RFC 8998 |
| --- | --- | --- |
| 证书 | 双证书 + 密管托管制度 | 单证书（国际同构） |
| 前向保密 | ECDHE 套件可选 | 内建（1-RTT ECDHE） |
| 性能 | 2-RTT、CBC 或 GCM | 1-RTT、AEAD-only |
| 合规认可 | 国内密评/关基通行 | 部分场景认可，需与监管确认 |
| 生态 | 国产网关/浏览器/客户端 SDK | Tongsuo、OpenSSL 3.2+、浏览器未广泛支持 |
| 典型选择 | 政务、金融存量、网关互联 | 新一代网关、国际化系统 |

## 9. 部署实战（Tongsuo）

Tongsuo（铜锁，原 BabaSSL，OpenSSL 分支）是 TLCP 支持最完整的开源实现：

```bash
# 1) 生成签名密钥对与自签证书
tongsuo genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:sm2 -pkeyopt ec_param_enc:named_curve \
  -out sign.key
tongsuo req -x509 -sm2 -key sign.key -days 365 \
  -subj "/CN=example.com" -out sign.crt

# 2) 生成加密密钥对与自签证书（生产环境应向 CA/密管申请，
#    加密证书由 CA/KMC 生成加密密钥对后签发）
tongsuo genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:sm2 -pkeyopt ec_param_enc:named_curve \
  -out enc.key
tongsuo req -x509 -sm2 -key enc.key -days 365 \
  -subj "/CN=example.com" -out enc.crt

# 3) 启动 TLCP 服务端（双证书）
tongsuo s_server -enable_ntls -ntls -accept 443 \
  -cert sign.crt -key sign.key \
  -cert2 enc.crt -key2 enc.key -www

# 4) 客户端联调
tongsuo s_client -enable_ntls -ntls -connect localhost:443
```

生产形态的常见拓扑：

```text
浏览器/App（国密 SDK 或国际 TLS）
        │
        ▼
国密网关 / Nginx+Tongsuo（TLCP 终结，双证书）──► 后端服务（内网，可继续 TLCP 或普通 TLS）
```

## 10. 客户端生态现状

- **浏览器**：主流国际浏览器不内置 TLCP；国内政务场景依赖专用浏览器或国密安全控件；
- **App/SDK**：腾讯 Kona（Java）、各密码厂商 SDK、Tongsuo/GmSSL 移动端裁剪版承担大部分客户端接入；
- **网关互联**：国密 SSL VPN 网关（GM/T 0024 体系设备）与 TLCP 网关对接时注意套件兼容（老设备可能只支持 CBC/SM1 套件）。

## 11. 排错清单（按频率排序）

| 症状 | 根因 |
| --- | --- |
| `certificate verify failed` | 双证书顺序装反（签名/加密）；证书用途不匹配（用加密证书去验签名） |
| `handshake failure` | 套件不匹配：客户端只报 GCM、网关只配 CBC；或版本不是 0x0101 |
| ClientKeyExchange 后失败 | SM2 加密预主密钥的密文封装格式（DER/裸序、C1C2C3/C1C3C2）两端实现不一致 |
| 验签偶发失败 | SM2 签名 ID 两端不一致（缺省值 vs 自定义） |
| ECDHE 握手失败 | ServerKeyExchange 签名内容覆盖范围（随机数顺序）两端实现有差异 |
| 会话恢复失效 | 网关集群 session 缓存未共享，或会话超时策略不一致 |

---

**延伸阅读**：GB/T 38636-2020 全文（含握手报文格式与全部套件定义）；GM/T 0054-2018；RFC 8998；RFC 8446（TLS 1.3，理解 TLCP 的对照系）；Tongsuo 文档（TLCP/NTLS 实现与 wiki）。
