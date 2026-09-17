# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Planned
- v0.2.0：SM2（基于 gmssl 集成 + crosscheck）· bench · TLCP 离线解析
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
