# Quickstart · GMScope（3 分钟上手）

> 本机无 `pip`，统一使用 [uv](https://docs.astral.sh/uv/)（评审整改，详见规划库 `docs/06 §14`）。

## 1. 安装（Python 3.11）

```bash
uv venv --python 3.11
uv pip install -e ".[all]"
```

## 2. 三命令验证

```bash
# ① 标准向量自检（GM/T 0002 / GM/T 0004）——全绿即安装成功
gmscope selftest

# ② 与 gmssl / cryptography 交叉验证（固定 seed 随机用例）
gmscope crosscheck -n 64

# ③ 离线一键演示（自检 + 交叉验证 + 下一步指引）
gmscope demo
```

## 3. 常见问题

| 现象 | 原因 | 处理 |
|---|---|---|
| `No module named pip` | 本机只有 uv | 用 `uv pip install ...`（见上） |
| `crosscheck` 显示「跳过」 | 缺少 gmssl 或 cryptography | `uv pip install -e ".[crypto]"` |
| `cryptography` 提示不支持 SM4/SM3 | OpenSSL 版本过旧 | 升级 cryptography ≥42；或忽略（仅少一路对照） |
| Windows 终端中文乱码 | 代码页问题 | 使用 Windows Terminal / `chcp 65001` |

## 4. 运行测试（开发者）

```bash
uv pip install -e ".[all]"
python -m pytest              # 快速套件（默认跳过 slow）
python -m pytest -m slow      # 含 GM/T 百万次迭代向量（约 1-2 分钟）
```

## 5. 下一步（路线图）

- v0.2.0：`gmscope parse`（TLCP 离线解析）· `gmscope bench`（SM2/SM3/SM4 基准）
- v0.5.0：`gmscope audit`（密评自查 60+ 检查项）+ HTML 差距报告
- v1.0.0：时间侧信道演示 · 完整文档与演示素材
