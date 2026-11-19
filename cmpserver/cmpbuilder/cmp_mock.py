# coding: utf-8
"""
字段级 mock 注入层（仅服务端响应侧：ip / kup / pkiconf）。

设计要点
--------
1. 结构化命名空间：所有注入集中在一个 MockSpec 上，按用途分桶，
   而不是给 CmpServer 堆几十个 setter。
2. 绕过 builder 的强类型/合法值校验：override 不经过任何 @_writer setter，
   而是在 build 阶段直接写进已构造好的 asn1crypto 结构里，因此可以填
   "协议非法" 的值（如 pvno=cmp1999、过期 message_time、删除必选 nonce）。
3. 只做 "签名前篡改"：header / body 的注入都发生在计算 PKIProtection 之前，
   因此签名覆盖篡改后的内容，用于测设备的字段语义校验（会不会因字段非法而拒绝）。
4. protection 是 "算出来的" 不是 "赋值的"，所以单独给一个旋钮。

用法::

    srv.mock.header['transaction_id'] = b'\\x00' * 16   # 替换
    srv.mock.header['pvno']           = 'cmp1999'        # 协议非法值
    srv.mock.header['recip_nonce']    = OMIT             # 删除可选字段
    srv.mock.body['response.0.status.status']    = 'rejection'   # 钻进 body
    srv.mock.body['response.0.status.fail_info'] = PKIFailureInfo({'bad_pop'})
    srv.mock.protection = 'corrupt'                       # 损坏签名
    srv.mock.extra_certs = OMIT                           # 不带 extra_certs
"""
from __future__ import unicode_literals

from asn1crypto import x509
from oscrypto import asymmetric


# ---------------------------------------------------------------------------
# 哨兵 / 包装器
# ---------------------------------------------------------------------------
class _Sentinel(object):
    def __init__(self, name):
        self._name = name

    def __repr__(self):
        return self._name


OMIT = _Sentinel('OMIT')      # 删除一个（可选）字段
_UNSET = _Sentinel('_UNSET')  # "用户没碰过这个旋钮"，区别于 None / OMIT


class Raw(object):
    """
    把一个已构造好的 asn1crypto 对象（或 native 值）原样塞进字段，
    跳过任何 builder 侧的封装逻辑。用于 "我知道我在干什么" 的精确注入。
    """
    def __init__(self, value):
        self.value = value


def general_name(value):
    """
    把 Certificate / Name / GeneralName 统一成 x509.GeneralName(directory_name=...)。

    供 mock.header['sender'] / mock.header['recipient'] 使用——因为这是直接写进
    header 字段（GeneralName 类型），不能传裸 x509.Name，必须先包成 GeneralName。
    """
    if isinstance(value, x509.Certificate):
        return x509.GeneralName(name='directory_name', value=value.subject)
    if isinstance(value, x509.Name):
        return x509.GeneralName(name='directory_name', value=value)
    if isinstance(value, x509.GeneralName):
        return value
    raise TypeError(
        'general_name() expects x509.Certificate / x509.Name / x509.GeneralName, '
        'not %r' % type(value).__name__
    )


# ---------------------------------------------------------------------------
# 路径游走：支持 'a.b.0.c' 形式，数字段当作 SequenceOf 下标
# ---------------------------------------------------------------------------
def _walk_to_parent(container, dotted_path):
    """返回 (最终键的父容器, 最终键)。中间路径必须已存在。"""
    parts = dotted_path.split('.')
    cur = container
    for p in parts[:-1]:
        cur = cur[int(p) if p.lstrip('-').isdigit() else p]
    last = parts[-1]
    return cur, (int(last) if last.lstrip('-').isdigit() else last)


def _apply(container, overrides):
    """把一组 {dotted_path: value|OMIT|Raw} 应用到 asn1crypto 结构上（原地）。"""
    if not overrides:
        return
    for path, val in overrides.items():
        parent, key = _walk_to_parent(container, path)
        if val is OMIT:
            del parent[key]
        elif isinstance(val, Raw):
            parent[key] = val.value
        else:
            parent[key] = val


def _corrupt_bytes(data):
    """翻转最后一个字节的最低位，破坏签名但保持长度合法。"""
    if not data:
        return data
    return data[:-1] + bytes([data[-1] ^ 0x01])

def _to_asn1_cert(value):
    if isinstance(value, asymmetric.Certificate):
        return value.asn1
    return value

# ---------------------------------------------------------------------------
# MockSpec
# ---------------------------------------------------------------------------
class MockSpec(object):
    """
    挂在 CmpServer 上的字段级 mock 容器。每个被测用例用一个独立实例
    （fixture 每个用例新建 server，所以天然隔离；也可手动 reset()）。

    当前只支持 "签名前篡改"：header / body 的覆盖都在计算签名之前注入，
    签名覆盖篡改后的内容。
    """

    # protection 旋钮的合法取值
    PROTECTION_MODES = ('normal', 'skip', 'wrong_key', 'corrupt', 'empty')

    def __init__(self):
        self.reset()

    def reset(self):
        self.header = {}        # 签名前注入：dotted-path -> value | OMIT | Raw
        self.body = {}          # 签名前注入（钻进 body）
        self.protection = 'normal'
        self.protection_key = None   # wrong_key 模式下用这个 key 签
        self.extra_certs = _UNSET    # _UNSET=沿用旧逻辑; OMIT/None=不带; [cert,...]=替换

    # ---- 由 _assemble_message 调用的 hook ----

    def apply_pre_protection(self, header, body_value):
        """在计算 PKIProtection 之前，把 header / body 覆盖写进结构。"""
        _apply(header, self.header)
        # pkiconf 的 body 是 Null，没有可钻的字段；有 body override 才动
        if self.body:
            _apply(body_value, self.body)

    def resolve_extra_certs(self, default_cert):
        """
        返回应放进 extra_certs 的证书列表，或 None 表示不带。
        优先级：mock.extra_certs > 旧的 default_cert（来自 extraCerts_flag）。
        """
        if self.extra_certs is _UNSET:
            return [default_cert] if default_cert is not None else None
        if self.extra_certs in (OMIT, None):
            return None
        certs = self.extra_certs

        if isinstance(certs, (x509.Certificate, asymmetric.Certificate)):
            certs = [certs]
        return [_to_asn1_cert(c) for c in certs]
