"""自动生成的 KAT（已知答案测试）数据 —— 由 ``scripts/gen_kat.py`` 生成，请勿手改。

- SM2：密钥与签名经 OpenSSL 独立验证（checks 字段为生成时的校验结果）。
- SM4-GCM：向量由 cryptography（OpenSSL）计算，本库实现比对一致后收录。
"""

KAT = {'SM2_SIGN': {'private_key': 'cd78dd07f13cb9357afcf8c909627cd84581b68097dcd984de7d032ada87c601',
              'public_key': '863a365ff8d216be5d8cf277fb413bdc88c109b9153d1a991fc2344358ec88d283696d530d336e748e6ce4c2f4e0663ab4a831efdd740aaf462e0c4794f5ad4e',
              'message_hex': 'e59bbde5af86e7ae97e6b39520474d53636f706520c2b720534d3220e7adbee5908d204b415420e794a8e4be8b202331',
              'k': 18589980749199645412286842309513751186657817853392369826452519994486233829151,
              'signature': '7b72cbcc3b4ffc73faf8e211d7f87e67234b684a39aa19435947542f76fc927ebdbec8df663499d8bdd6a168cfd91ec92c2b052e71de3b14623dce3e1af75756',
              'uid_hex': '31323334353637383132333435363738',
              'checks': {'gmssl_native_verify': True,
                         'za_e_matches_gmssl': True,
                         'openssl_verify': True,
                         'openssl_sign_then_gmscope_verify': True},
              'generator': 'openssl-3.x'},
 'SM4_GCM': {'key': '0123456789abcdeffedcba9876543210',
             'iv': '000102030405060708090a0b',
             'iv16': '000102030405060708090a0b0c0d0e0f',
             'aad': '474d53636f70652d414144',
             'plaintext': 'e59bbde5af86e7ae97e6b39520474d53636f706520c2b720534d342d47434d20e8aea4e8af81e58aa0e5af86204b415420e794a8e4be8b202331',
             'ciphertext': 'b0baa5741e374eb1f366303efb1b2b06eb9659c86093099f15f99d02d7ae5e5ba1ab69b28b88d89fa754f0b634dacac43a68b00bdfc1875be77b',
             'tag': 'd0c1d61a9d30cc968bacbbf0dd74eaed',
             'ciphertext_iv16': '4f9f751ef8edc47897d018fc4bfc5d614a6a4812148c2650f8f87db88bca539fe211907faf95d6cf86c8ff68da057e06beaea613a04bea266caf',
             'tag_iv16': '6785891c5c233261166e1488a3f827b9',
             'generator': 'cryptography/OpenSSL'}}
