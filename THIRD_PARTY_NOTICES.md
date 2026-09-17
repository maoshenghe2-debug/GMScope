# 第三方组件与许可说明（THIRD_PARTY_NOTICES）

本仓库不包含任何第三方源代码副本；所有第三方组件均以**依赖引用**或**子进程调用**方式使用。
以下为当前直接依赖清单（后续版本持续更新）：

## 运行时依赖

| 组件 | 版本约束 | 许可 | 用途 |
|---|---|---|---|
| [Typer](https://github.com/fastapi/typer) | >=0.12 | MIT | CLI 框架 |
| [Rich](https://github.com/Textualize/rich) | >=13.7 | MIT | 终端输出与表格 |
| [Jinja2](https://github.com/pallets/jinja2) | >=3.1 | BSD-3-Clause | 报告模板渲染 |
| [gmssl](https://pypi.org/project/gmssl/)（PyPI, 纯 Python） | >=3.2.2 | Apache-2.0 | 国密算法参考实现（SM2/SM3/SM4），用于交叉验证 |
| [cryptography](https://github.com/pyca/cryptography) | >=42.0 | Apache-2.0 / BSD-3-Clause | SM4/SM3 交叉验证（OpenSSL 后端） |

## 开发依赖

| 组件 | 许可 | 用途 |
|---|---|---|
| pytest / pytest-cov | MIT | 测试 |
| ruff | MIT | 代码质量 |

## 外部工具（文档提及，不随仓库分发）

| 工具 | 许可 | 用途 | 使用方式 |
|---|---|---|---|
| [GmSSL (C)](https://github.com/guanzhi/GmSSL) | Apache-2.0 | 生成 TLCP 测试流量（s_server）、命令行交叉验证 | 用户自行安装，子进程调用 |

## 许可合规约定

1. 直接依赖仅使用 Apache-2.0 / MIT / BSD 系许可；
2. 强 copyleft 组件（AGPL/LGPL/GPL）一律仅以子进程方式调用，不链接、不修改分发；
3. 本仓库对外许可：Apache-2.0（见 LICENSE）。
