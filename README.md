# cmp-mock-tester

A field-level mocking **CMP (RFC 4210) CA simulator** for negative-testing
certificate protocols on base stations (EE).

一个用于**对基站（EE）做证书协议负向测试**的 CMP（RFC 4210）CA 模拟器。
它以 HTTP 服务的形式扮演 CA，接收基站发来的 `ir` / `kur` / `certconf`，
回以 `ip` / `kup` / `pkiconf`；核心能力是一个**通用字段注入器**，可在签名前
对响应报文的任意字段做篡改，从而验证基站是否正确校验/拒绝异常证书响应。

---

## 特性

- 只构建 **CA → EE** 方向的报文：`ip` / `kup` / `pkiconf`（及 `error`）。
- **字段级 mock 注入器**：在计算 PKIProtection **之前**篡改任意字段，签名覆盖篡改后内容。
- 支持 6 档操作：替换合法值、替换协议非法值、置空/零长度/NULL、删除可选字段（`OMIT`）、
  新增字段、`Raw` 原样注入。
- 独立的**验签旋钮** `mock.protection`：`normal` / `skip` / `wrong_key` / `corrupt` / `empty`。
- 轻量 HTTP 服务（标准库 `http.server`），`POST /cmp` 收 DER、回 DER。

---

## 安装

依赖 `asn1crypto`、`oscrypto`、`certbuilder`，均为 PyPI 可安装的纯 Python 包。

```bash
# 从源码（开发模式）
pip install -e .

# 或直接从 PyPI 安装
pip install cmp-mock-tester
```

> **Python 版本**：3.8+ 均可（纯 Python 实现，已在 3.10 / 3.14 / 3.15 实测通过）。

安装后可用一行命令验证核心模块可导入：

```bash
python -c "from cmp_mock_tester import CmpServer, MockSpec, OMIT, general_name; print('OK')"
```

---

## 快速开始

```python
from oscrypto import asymmetric

from cmp_mock_tester import CmpServer, create_root_cert

# 1. 自签根 CA（onlyData=True 只返回材料，不落盘）
issuer_key, issuer_cert = create_root_cert(onlyData=True)

# 2. 起 CMP 服务
with CmpServer(port=0, host="127.0.0.1") as srv:
    srv.ca_info = {"issuer_key": issuer_key, "issuer_cert": issuer_cert}
    print("CMP 服务:", srv.url)   # http://127.0.0.1:<random-port>
```

真实基站把 CMP 请求（`ir`/`kur`/`certconf`，DER，`application/pkixcmp`）POST 到
`{srv.url}/cmp`，服务自动解析并返回对应的 `ip`/`kup`/`pkiconf`。

---

## 核心：字段级 mock

`CmpServer.mock`（`MockSpec`）是一个**通用字段注入器**，对模拟器下发的报文做字段级篡改：

```text
mock.header[path]      签名前注入 header（dotted-path，支持 OMIT / Raw）
mock.body[path]        签名前注入 body（钻进 CertRepMessage，数字段=数组下标）
mock.protection        'normal' | 'skip' | 'wrong_key' | 'corrupt' | 'empty'
mock.protection_key    wrong_key 模式下用于签名的假私钥
mock.extra_certs       默认(带签名证书) | OMIT/None(不带) | [cert,...](替换)
mock.reset()           清空
```

- **签名前注入**：`header` / `body` 的覆盖发生在计算 PKIProtection 之前，签名覆盖篡改后内容 ——
  用于测设备的**字段语义校验**（会不会因字段非法而拒绝）。
- **验签单独测**：用 `mock.protection` 旋钮。
- **绕过 builder 校验**：注入不经过 builder 的类型/合法值 setter，可填“协议非法但结构合法”的值。

### 示例

```python
from cmp_mock_tester import OMIT, Raw, general_name
from cmp_mock_tester.asn1crypto_cmp.rfc4210 import PKIFailureInfo
from datetime import datetime, timezone

srv.mock.header['pvno']           = 'cmp1999'                          # 协议版本非法
srv.mock.header['transaction_id'] = b''                               # 置零长度
srv.mock.header['message_time']   = datetime(2000, 1, 1, tzinfo=timezone.utc)  # 过期
srv.mock.header['recip_nonce']    = OMIT                              # 删除可选字段
srv.mock.header['sender']         = general_name(fake_cert)           # 换 sender（必须包 general_name）

srv.mock.body['response.0.status.status']    = 'rejection'
srv.mock.body['response.0.status.fail_info'] = PKIFailureInfo({'bad_pop'})

srv.mock.protection = 'corrupt'                                       # 破坏签名（测验签）
# srv.mock.protection = 'wrong_key'; srv.mock.protection_key = fake_key
srv.mock.extra_certs = OMIT                                           # 不带 extra_certs
```

> `mock.header['sender'|'recipient']` 直接写进 GeneralName 字段，不能传裸 `x509.Name`
> （asn1crypto 会拒绝），必须用 `general_name()` 包一下。它接受
> `Certificate` / `Name` / `GeneralName` 三种入参。

---

## 架构

```
真实基站 (EE)                         CMP 模拟器 (CA)
     │   ir / kur / certconf  (DER, application/pkixcmp)   │
     │ ─────────────────────────────────────────────────► │  POST /cmp
     │                                                     │    └─ msgHandler 分发
     │                                                     │        └─ issue_end_entity 签发 EE 证书
     │                                                     │        └─ builder.build() ── mock 注入 ──► 签名
     │   ip / kup / pkiconf   (DER)                        │
     │ ◄───────────────────────────────────────────────── │
```

| 层 | 文件 | 职责 |
|---|---|---|
| 传输/路由 | `cmp_mock_tester/controllers/basic_server.py` | `@handler` 收集路由、后台线程 `HTTPServer`、`Request.send_der` |
| 服务 | `cmp_mock_tester/controllers/cmp_server.py` | `POST /cmp` 收 DER；持有 `ca_info` + `mock` |
| 消息分发 | `cmp_mock_tester/controllers/handlers/cmpHandler.py` | 按 `body.name` 分发并构建响应 |
| 构建 | `cmp_mock_tester/cmpbuilder/__init__.py` | 三个 builder + `_assemble_message`（签名 + mock 注入） |
| 字段注入 | `cmp_mock_tester/cmpbuilder/cmp_mock.py` | `MockSpec` —— 签名前篡改任意字段 |
| ASN.1 | `cmp_mock_tester/asn1crypto_cmp/rfc4210.py` | CMP/CRMF 结构定义，`PKIMessage.load/dump` 的依据 |
| 证书 | `cmp_mock_tester/scripts/ca.py` | 自签根 CA、签发 EE 证书 |

`ir` / `kur` / `certconf` 由真实基站主动发出，模拟器只**收取解析**、不构建；
模拟器只构建 CA→EE 方向的 `ip` / `kup` / `pkiconf`（及 `error`）。

---

## 目录结构

```
cmp_mock_tester/
├── __init__.py               # 公开 API re-export + __version__
├── cmpbuilder/               # CMP 报文构建器（包）
│   ├── __init__.py           #   CMPResponseBuilder(ip/kup) / CMPConfirmBuilder(pkiconf) / CMPErrorBuilder(error)
│   └── cmp_mock.py           #   MockSpec / OMIT / Raw / general_name
├── asn1crypto_cmp/
│   └── rfc4210.py            # CMP/CRMF 的 ASN.1 结构定义（PKIMessage 等）
├── controllers/
│   ├── basic_server.py       # BasicServer / Request / @handler —— 轻量 HTTP 路由框架
│   ├── cmp_server.py         # CmpServer：POST /cmp，持有 ca_info + mock
│   └── handlers/
│       └── cmpHandler.py     # msgHandler：按 body 类型分发并构建响应
└── scripts/
    └── ca.py                 # create_root_cert / issue_end_entity —— 证书工厂
```

> `tests/` 目录为**私有本地测试**，依赖内部测试框架与真实基站环境，**不在本仓库/包中**。

---

## 边界与已知限制

- **可 mock 的报文**：`ip` / `kup` / `pkiconf`。`error` 当前未接入 mock；
  `ir` / `kur` / `certconf` 为收取解析、不构建。
- **只能注入“协议非法但结构合法”的值**（asn1crypto 仍能编码）；尚不支持位级畸形 DER。
- **签名后篡改**（header_post / body_post）暂未实现。
- **已知缺口**：`mock.extra_certs = []` 当前被当作“不带”，故“在但空的 extra_certs”
  暂不可表达；header / body 内的容器字段均支持“在但空”。

---

## License

[MIT](./LICENSE)
