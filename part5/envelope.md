# 消息语法与数字信封

算法解决"怎么加密/签名"，**消息语法**解决"结果怎么装进报文跨系统交换"。国密的消息语法体系是 CMS（RFC 5652，前身 PKCS#7）的国密化改造：**GM/T 0010-2012 → GB/T 35275-2017《信息安全技术 SM2 密码算法加密签名消息语法规范》**。政务接口、银行报文、电子文档保护、电子签章的数据结构几乎全部建立在这套语法之上。

## 1. CMS 国密化：结构与算法标识的替换

CMS 的抽象结构不动，只替换算法标识与参数：

| CMS 概念 | 国际实现 | 国密实现 |
| --- | --- | --- |
| 内容加密 | AES-CBC/GCM | SM4-CBC/GCM（OID：1.2.156.10197.1.104.x） |
| 收件人密钥封装 | RSA-KEM / ECDH | **SM2 公钥加密封装 CEK** |
| 摘要算法 | SHA-256 | SM3 |
| 签名 | RSA-PSS / ECDSA | SM2WithSM3（OID 1.2.156.10197.1.501） |
| 证书 | X.509（RSA/EC） | X.509（SM2，GM/T 0015） |

核心数据类型（ASN.1，与 CMS 同构）：

```text
ContentInfo ::= SEQUENCE { contentType OID, content [0] ANY }

SignedData     —— 签名信封：内容 + 签名者信息 + 证书 + SM2 签名值集合
EnvelopedData  —— 数字信封：SM4 加密的内容 + 每个收件人的 SM2 密钥封装
DigestedData   —— 摘要信封
EncryptedData  —— 对称加密信封（无收件人封装，密钥带外）
```

## 2. 数字信封（EnvelopedData）逐行拆解

数字信封 = "用对称密钥加密大内容，用公钥加密小密钥"，是 SM2+SM4 组合的最常用形态：

```text
封装方（发送者）：
1. 生成一次性内容加密密钥 CEK（SM4-128，合规随机源）
2. 用 CEK 以 SM4-CBC/GCM 加密内容 → encryptedContent
3. 对每个收件人 i：
     用收件人 i 的 SM2 加密证书公钥加密 CEK
     → RecipientInfo_i { 收件人证书标识, SM2 密文(DER), 算法标识 }
4. （可选）对整个信封再签名（SignedData 套 EnvelopedData）
5. 组装 EnvelopedData ASN.1 结构分发

解封方（收件人 i）：
1. 按证书标识找到自己的 RecipientInfo
2. 用自己的 SM2 加密私钥解出 CEK（设备内解密）
3. 用 CEK 解密内容
```

工程细节：

- CEK 一次一用，IV/nonce 随 CEK 同行（明文置于信封头，无需保密）；
- 收件人列表天然支持"一信多收"（政务多级会签、群发加密通知）；
- SM2 密文的 DER 编码遵循 GM/T 0009/35276 封装（C1/C2/C3 的 ASN.1 序列）——**跨库对解时的头号检查项**（同 SM2 章的 C1C2C3 问题）；
- 签名套信封的顺序（先信封后签名 vs 先签名后信封）要约定：先签后封=签名对明文负责；先封后签=签名对密文负责（不可抵赖性更强，但审计方必须能解封）。

## 3. 实战

**BouncyCastle（Java）**——CMS 国密信封的收件人生成器类名随版本演进，**不要凭记忆拼 API**，以 BC 当前版本测试用例为准。这里给出底层构造（任何版本都成立）：手动 SM2 加密 CEK + SM4 加密内容，再组装 GB/T 35275 风格的 EnvelopedData：

```java
// 1) CEK 与 IV（合规随机源）
byte[] cek = new byte[16], iv = new byte[16];
secureRandom.nextBytes(cek); secureRandom.nextBytes(iv);

// 2) SM4-GCM 加密内容（EVP 风格，BC JCE）
Cipher sm4 = Cipher.getInstance("SM4/GCM/NoPadding", "BC");
sm4.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "SM4"),
         new GCMParameterSpec(128, iv));
byte[] cipherText = sm4.doFinal(content);

// 3) SM2 加密 CEK（轻量 API，密文顺序显式声明）
SM2Engine enc = new SM2Engine(SM2Engine.Mode.C1C3C2);
enc.init(true, new ParametersWithRandom(recipientEncCertPubKey, secureRandom));
byte[] cekCipher = enc.processBlock(cek, 0, cek.length);

// 4) 组装报文（JSON 信封形态，见第 5 节；ASN.1 形态交给
//    gmsm pkcs7 / BC CMS 按标准装配）
```

**gmsm（Go）**——`pkcs7` 与 `pkcs12` 包对 GB/T 35275 与国密 PKCS#12 有直接支持（fork 自 mozilla-services/pkcs7 并做国密扩展），信封解析/解封有现成 API 与测试向量，可作为 ASN.1 形态的首选实现（具体函数签名以官方文档为准）。

**openssl 命令行**：原生 OpenSSL 的 `cms`/`smime` 子命令可处理标准 CMS，对 GB/T 35275 的国密标识支持取决于版本（Tongsuo 更完整）；跨实现联调时先用同一份样例报文互解。

## 4. 私钥与证书的封装格式

| 格式 | 用途 | 国密状态 |
| --- | --- | --- |
| PKCS#8 | 私钥 DER/PEM（明文或加密） | 主流库均支持 SM2 私钥；加密私钥配合 GB/T 35276 结构 |
| PKCS#12 | 私钥+证书+链的归档容器（.pfx） | 国密化实现分散：gmsm 的 PKCS12_SM2、CFCA SADK 的封装；**跨厂商 .pfx 互导是经典坑**（PBES 算法族与 SM 系组合不同） |
| JKS/PKCS#11 | Java/硬件密钥库 | PKCS#11 无国密官方标准映射，厂商以扩展机制接入 |

## 5. 应用层报文：政务/银行的"信封+签名"惯例

大量政务与银行接口不直接用 ASN.1，而是把信封思想映射到 JSON/XML：

```json
{
  "header": { "appId": "...", "sn": "202611070001", "ts": "..." },
  "encAlg": "SM4-CBC", "signAlg": "SM3withSM2",
  "keyCipher": "Base64(SM2加密的CEK, DER)",
  "dataCipher": "Base64(SM4加密的业务报文)",
  "iv": "Base64(...)",
  "certSn": "签名证书序列号",
  "signature": "Base64(SM2签名(header‖密文字段…))"
}
```

要点：签名的覆盖字段范围**必须在接口文档中逐字段写死**（最常见纠纷：A 方签了 header，B 方验签只拼了 body）；CEK 与 IV 的生成来源要合规；此类自定义封装与标准 GB/T 35275 信封在密评中都认可，但**结构要成文、实现要有向量级测试**。

## 6. 置标语法：XML/HTML 的密码标签

密码行业标准化技术委员会为网页/文档场景定义了**密码应用置标语法**——用标签（tag）在 HTML/XML 文档中标记需要签名/加密/信封化的片段，浏览器或文档引擎据此执行国密处理：

- GM/T 0126-2023《HTML 密码应用置标语法》（2023 年 12 月发布、2024 年 6 月实施）；
- 同批标准中还有 XML 版本的置标语法与之配套（编号以密标委公告为准）。

这类标准瞄准"电子表单、政务网页直接内嵌密码操作"的场景，是国密向应用层纵深发展的代表性方向。

## 7. 电子文档与电子签章

版式文档（中国的"PDF"）与电子签章构成完整闭环：

| 环节 | 标准 | 说明 |
| --- | --- | --- |
| 版式文档格式 | **GB/T 33190-2016** OFD | 中国版式文档格式（电子发票、电子证照的载体） |
| 电子签章密码 | **GB/T 38540-2020**《信息安全技术 安全电子签章密码技术规范》 | 印章数据结构、签章生成与验证流程 |
| 行标体系 | GM/T 0031《安全电子签章密码技术规范》（2014 版，**2025 修订版 GM/T 0031-2025 于 2026-07-01 实施**） | 与国标配套的行标族 |
| 签名嵌入 | 基于 GB/T 35275 的文档签名信封 | 签章 = 可视印章图像 + 底层 SM2 签名数据 |

电子发票 OFD、电子合同、电子证照均走"OFD/版式 + 电子签章（SM2/SM3）+ 可信时间戳"的技术路线，验签方（如税务/司法平台）按 GB/T 38540 校验签章与证书链。

## 8. 互操作坑清单

1. SM2 密文 DER 裸序/C1C2C3 三重组合不一致（信封里 RecipientInfo 解不开的首因）；
2. SM4 模式 OID 带不带模式后缀（104.2 vs "SM4"）；
3. 签名覆盖范围两边拼装顺序不同；
4. .pfx 跨厂商导入失败的 PBES 参数差异；
5. 内容类型 OID 不识别（国密 OID 未注册进对方库）→ 解析直接报 unknown OID；
6. 双证书用错：信封的收件人封装必须用**加密证书**，签名必须用**签名证书**。

---

**延伸阅读**：GB/T 35275-2017 与 GM/T 0010-2012；RFC 5652（CMS 原型）；GB/T 35276-2017（SM2 使用规范，密文/私钥封装）；GB/T 33190-2016（OFD）；GB/T 38540-2020 与 GM/T 0031（电子签章）；GM/T 0126-2023（HTML 置标语法）；gmsm pkcs7/pkcs12 源码与文档。
