# 国密技术知识手册

本仓库系统梳理中国商用密码（国密 / SM 系列算法）技术体系，覆盖算法原理、协议设计、证书体系、工程实现、合规评估与专题深化。


## 第一部分 总览

* [第一部分导读](docs/part1/README.md)
* [国密概述与发展历程](docs/part1/overview.md)
* [国密标准体系与密码法规](docs/part1/standards.md)

## 第二部分 核心算法

* [第二部分导读](docs/part2/README.md)
* [SM2 椭圆曲线公钥密码算法](docs/part2/sm2.md)
* [SM3 密码杂凑算法](docs/part2/sm3.md)
* [SM4 分组密码算法](docs/part2/sm4.md)
* [SM9 标识密码算法](docs/part2/sm9.md)
* [ZUC 祖冲之序列密码算法](docs/part2/zuc.md)
* [SM1 与其他受限算法](docs/part2/sm1.md)

## 第三部分 协议与应用

* [第三部分导读](docs/part3/README.md)
* [TLCP 传输层密码协议](docs/part3/tlcp.md)
* [国密数字证书与 PKI 体系](docs/part3/certificate.md)
* [国密算法工程实现](docs/part3/engineering.md)

## 第四部分 安全评估

* [第四部分导读](docs/part4/README.md)
* [商用密码应用安全性评估（密评）](docs/part4/assessment.md)

## 第五部分 专题深化

* [第五部分导读](docs/part5/README.md)
* [随机数与随机性检测](docs/part5/random.md)
* [密钥管理体系](docs/part5/keymgmt.md)
* [消息语法与数字信封](docs/part5/envelope.md)
* [工作模式与 MAC 的国标体系](docs/part5/modes.md)
* [安全接入协议族与 WAPI](docs/part5/vpn.md)
* [可信计算与 TCM](docs/part5/trusted.md)
* [行业应用画像](docs/part5/applications.md)
* [后量子时代的国密](docs/part5/pqc.md)

## 附录

* [附录 A：国密标准总索引](docs/appendix/standards.md)
* [附录 B：常见问题 FAQ](docs/appendix/faq.md)
* [附录 C：术语表](docs/appendix/glossary.md)

测试向量一键复核：`python3 scripts/verify_test_vectors.py`（SM3/SM4/ZUC/EIA3 官方 KAT、RFC 8998 SM4-GCM/CCM、SM2 与 SM9 数值示例，42/42 通过）

