"""GMScope · 国密应用安全检测与协议分析平台。

模块边界（规划与现状）：

- ``gmscope.crypto``       纯 Python 参考实现（SM3/SM4；教学与交叉验证，主链路以成熟库为准）
- ``gmscope.protocol``     TLCP / TLS 协议解析与画像（v0.2.0）
- ``gmscope.audit``        密评检查项引擎（v0.5.0）
- ``gmscope.sidechannel``  侧信道测评演示（v1.0.0）
- ``gmscope.kms``          密钥管理演示（v1.0.0）
"""

__version__ = "0.2.0"
__author__ = "Maosheng He (maoshenghe2-debug)"
