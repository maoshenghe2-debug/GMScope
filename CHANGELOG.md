# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added
- SM2 封装（gmssl 内核）：签名 / 验签 / 加解密；支持**注入随机数 k** 的确定性签名（KAT 可复现）
- SM2 解密**补强 C3 完整性校验**（gmssl 原版不校验）；DER 签名编解码辅助（OpenSSL 互操作）
- SM4-GCM 认证加密（自研 GHASH + CTR）与标签校验（先验签后解密）
- 自建 KAT 冻结向量（`src/gmscope/kat_data.py`）：SM2 经 OpenSSL 双向互验、SM4-GCM 经 cryptography 交叉验证
  - 互操作实测：OpenSSL 的 SM2 默认用户标识为**空串**，须显式传 `-pkeyopt distid:1234567812345678` 才能与 GM/T 默认 ID 互通
- `gmscope bench`：SM3 / SM4(ECB/CBC/GCM) / SM2 性能基准（本库 vs gmssl vs cryptography）
- `gmscope crosscheck` 新增 SM2 五项对照与 SM4-GCM 对照；`gmscope selftest` 纳入 KAT
- `scripts/gen_kat.py`：KAT 生成器（OpenSSL / cryptography 双源，可复现）
- TLCP 离线解析：记录层 / 握手消息 / 协议画像；双证书（签名+加密）与国密套件识别（0xE011/E013/E051/E053，编号对齐 GmSSL 参考实现）
- `gmscope parse <pcap|bin>`：TLCP/TLS 协议画像（人类可读 / `--json`）
- `gmscope tlcp-fixture`：全合成 TLCP 演示样本生成器（PCAP / 原始流；含 SM2 OID 伪证书，仅演示用）
- 极简 PCAP 读写与以太网/IPv4/TCP 帧构造（含校验和，产物可用 Wireshark 打开）

### Fixed
- 交叉验证 SM2 加解密步骤：gmssl 实例未显式 `mode=1` 导致密文顺序错位（gmssl 默认 C1C2C3 vs 本库 C1C3C2）——已对齐，并补充「全量交叉验证入口」回归测试（CI demo 步骤同步覆盖）
- SM2 加密 KDF 退化（短消息约 1/256 概率）自动更换随机数重试 + 回归用例
- 规避 gmssl 上游缺陷：128 位十六进制公钥以 `04` 开头时（约 1/256 概率，如 d=11）被 `lstrip("04")` 误剥为 126 字符，导致 SM2 验签/加密偶发崩溃——新增 `new_gmssl_ctx` 统一构造入口（封装 / crosscheck / gen_kat 全量接入）+ d=11 回归用例

### Planned
- v0.2.0：API 文档 · 更多演示素材
- v0.5.0：密评检测引擎（GB/T 39786 四层面 60+ 检查项）+ HTML 报告
- v1.0.0：侧信道演示 · KMS · API · 完整文档与演示素材

## [0.1.0] - 2026-09-17

### Added
- 工程骨架：src 布局 / pyproject（hatchling）/ GitHub Actions CI（ubuntu + windows × py3.10-3.12）
- SM3 纯 Python 参考实现（含 HMAC-SM3），附 GM/T 0004 标准向量校验
- SM4 纯 Python 参考实现（ECB / CBC / CTR + PKCS#7），附 GM/T 0002 标准向量校验
- `gmscope selftest`：标准向量一键自检（人类可读表格 / `--json`）
- `gmscope crosscheck`：与 gmssl、cryptography 双库交叉验证（学术可信性）
- 合规声明与第三方依赖清单（THIRD_PARTY_NOTICES.md）
