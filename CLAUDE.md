# CLAUDE.md

Claude Code 在每次会话会自动读取本文件作为项目上下文。请遵循以下约定。

## 项目是什么

一个 **CMP（RFC 4210）CA 模拟器**，用于**证书协议负向测试**。
它以 HTTP 服务扮演 CA，接收客户端（EE）发来的 `ir`/`kur`/`certconf`，回以
`ip`/`kup`/`pkiconf`。核心能力是一个**字段级 mock 注入器**，可在**签名前**
篡改响应报文的任意字段，验证对端是否正确拒绝异常证书响应。

代码已整理为单一顶层包 `cmpserver`，可 `pip install` / 发布到 PyPI。

## 架构（自顶向下）

```
客户端(EE)   --ir/kur/certconf(DER)--> [POST /cmp] CmpServer
                                          └─ msgHandler 按 body 分发
                                              └─ issue_end_entity 签发 EE 证书
                                              └─ builder.build() --mock 注入--> 签名
客户端(EE)   <--ip/kup/pkiconf(DER)-------- 返回
```

| 路径 | 职责 |
|---|---|
| `cmpserver/controllers/basic_server.py` | 轻量 HTTP 路由框架（`@handler`、`Request.send_der`→`application/pkixcmp`） |
| `cmpserver/controllers/cmp_server.py` | `CmpServer`：`POST /cmp` 收 DER；持有 `ca_info`（CA 材料）+ `mock`（注入器） |
| `cmpserver/controllers/handlers/cmpHandler.py` | `msgHandler` 按 `body.name` 分发并构建响应 |
| `cmpserver/cmpbuilder/__init__.py` | 三个 builder + `_assemble_message`（签名 + mock 注入） |
| `cmpserver/cmpbuilder/cmp_mock.py` | `MockSpec` / `OMIT` / `Raw` / `general_name` |
| `cmpserver/asn1crypto_cmp/rfc4210.py` | CMP/CRMF 的 ASN.1 结构定义 |
| `cmpserver/scripts/ca.py` | 自签根 CA、签发 EE 证书 |

## 关键约定与不变量（改代码务必遵守）

1. **只构建 CA→EE 方向**：模拟器只构建 `ip`/`kup`/`pkiconf`（及 `error`）。
   `ir`/`kur`/`certconf` 是收取解析、**不要为它们写 builder**。

2. **mock 是签名前注入**：`mock.header`/`mock.body` 的覆盖必须发生在
   `_assemble_message` 计算 PKIProtection **之前**，使签名覆盖篡改后内容。
   **不要把注入挪到签名之后** —— 那会变成验签测试，语义不同。
   测验签请用 `mock.protection` 旋钮，勿动注入顺序。

3. **rfc4210 的“没被点名”≠“没用上”**：大量结构类不在业务代码出现名字，
   但 `PKIMessage.load()` 解析收到的报文时按 ASN.1 结构树必须用到它们。
   **删类前先做可达性确认**。已确认真正可删的只有 `CMPCertificate`、`PKIMessages`。

4. **所有 import 走顶层包 `cmpserver`**：
   - 包内互引：`from cmpserver.cmpbuilder import ...`、
     `from cmpserver.controllers... import ...`、`from cmpserver.scripts.ca import ...`。
   - 包外统一 `from cmpserver import ...`（`MockSpec`/`OMIT`/`Raw`/`general_name`
     已 re-export；也可 `from cmpserver.cmpbuilder import ...`）。
   - `cmpserver/cmpbuilder/cmp_mock.py` 不得反向 import `cmpbuilder`（会循环）。

5. **sender/recipient 覆盖必须用 `general_name()` 包装**：
   `mock.header['sender']` 直接写进 GeneralName 字段，传裸 `x509.Name` 会被 asn1crypto 拒绝。

## 运行 / 测试

- 依赖：`asn1crypto`、`oscrypto`、`certbuilder`（见 `pyproject.toml`）。
- `tests/` 是**私有本地测试**（`.gitignore` 已排除，永不上传）：用例通过 MML 驱动
  真实对端，依赖现场网络/凭据与内部测试框架。无现场环境时，
  只能做导入级验证。本地跑测试前先 `pip install -e .` 使 `cmpserver` 可导入。
- 语法/导入自检：`python -m py_compile <file>`；核心导入验证：
  `python -c "from cmpserver import CmpServer, MockSpec, OMIT; print('OK')"`。
- 打包：`python -m build`；发布：`twine upload dist/*`。

## 已知待办

- `mock.extra_certs = []` 当前等同“不带”；“在但空的 extra_certs”暂不可表达
  （需把判断从 `if certs:` 改为区分 `None` 与 `[]`）。
- `error` 报文暂未接入 mock 注入。
- 签名后篡改（header_post / body_post）按需求暂未实现。

## 文档

- `README.md` —— 设计概览 + 快速开始 + mock 用法 + Example。
- 打包元数据见 `pyproject.toml`，许可证见 `LICENSE`。
