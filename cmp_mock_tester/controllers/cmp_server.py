# coding: utf-8
import logging

from cmp_mock_tester.controllers.basic_server import BasicServer, Request, handler
from cmp_mock_tester.controllers.handlers.cmpHandler import msgHandler
from cmp_mock_tester.cmpbuilder import MockSpec

logger = logging.getLogger(__name__)


def _writer(func):
    """
    Decorator for a custom writer, but a default reader
    """
    name = func.__name__
    return property(fget=lambda self: getattr(self, '_%s' % name), fset=func)


class CmpServer(BasicServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ca_info = None
        self.mock = MockSpec()                 # 字段级 mock 注入入口（仅签名前篡改）

    @_writer
    def ca_info(self, data):
        self._ca_info = data

    # ------------------------------------------------------------------
    # /cmp  GET — 探活
    # ------------------------------------------------------------------
    @handler("GET", "/cmp")
    def cmp_root(self, req: Request):
        req.send_json({"service": "cmp", "status": "ok"})

    # ------------------------------------------------------------------
    # /cmp  POST — 接收 DER 编码的 CMP 消息（RFC 4210）
    # Content-Type: application/pkixcmp
    # ------------------------------------------------------------------
    @handler("POST", "/cmp")
    def cmp_receive(self, req: Request):
        der = req.body()  # 原始 DER bytes
        try:
            res = msgHandler(self, der)
        except Exception as exc:
            logger.exception("处理 CMP 请求失败")
            req.send_json({"error": str(exc)}, status=500)
            return
        req.send_der(res)

    # ------------------------------------------------------------------
    # /cmp_xxx  扁平路由（按需添加）
    # ------------------------------------------------------------------
    @handler("GET", "/cmp/health")
    def cmp_health(self, req: Request):
        req.send_json({"healthy": True})
