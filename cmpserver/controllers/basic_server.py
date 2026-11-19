# coding: utf-8
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, ClassVar, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse


# ---------------------------------------------------------------------------
# 装饰器：在类定义期间收集路由
# ---------------------------------------------------------------------------
def handler(method: str, path: str):
    """
    类方法装饰器，将路由信息附加到函数上，由元类统一收集。

    用法::

        class MyBasicServer(BasicServer):
            @handler("GET", "/basic_health")
            def health(self, req: Request):
                req.send_json({"ok": True})
    """

    def decorator(fn):
        if not hasattr(fn, "_route_info"):
            fn._route_info = []
        fn._route_info.append((method.upper(), path))
        return fn

    return decorator


# ---------------------------------------------------------------------------
# 请求代理对象（更友好的接口）
# ---------------------------------------------------------------------------
class Request:
    """对 BaseHTTPRequestHandler 的轻量包装，暴露给业务方法使用。"""

    def __init__(self, raw: BaseHTTPRequestHandler):
        self._raw = raw

    # ---------- 读 ----------

    @property
    def method(self) -> str:
        return self._raw.command

    @property
    def path(self) -> str:
        """不含查询串的路径，例如 /basic/items。"""
        return urlparse(self._raw.path).path

    @property
    def full_path(self) -> str:
        """含查询串的完整路径。"""
        return self._raw.path

    @property
    def query(self) -> Dict[str, list]:
        """解析后的查询参数，例如 {'page': ['1']}。"""
        return parse_qs(urlparse(self._raw.path).query)

    @property
    def headers(self) -> dict:
        return dict(self._raw.headers)

    def body(self) -> bytes:
        """读取请求体（依赖 Content-Length）。"""
        length = int(self._raw.headers.get("Content-Length", 0))
        return self._raw.rfile.read(length) if length else b""

    def json(self) -> object:
        """将请求体解析为 JSON。"""
        return json.loads(self.body())

    # ---------- 写 ----------

    def send_json(self, data: object, status: int = 200) -> None:
        payload = json.dumps(data, ensure_ascii=False).encode()
        self._send(status, "application/json", payload)

    def send_text(self, text: str, status: int = 200) -> None:
        self._send(status, "text/plain; charset=utf-8", text.encode())

    def send_der(self, data: bytes, status: int = 200) -> None:
        self._send(status, "application/pkixcmp", data)

    def send_empty(self, status: int = 204) -> None:
        self._raw.send_response(status)
        self._raw.end_headers()

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self._raw.send_response(status)
        self._raw.send_header("Content-Type", content_type)
        self._raw.send_header("Content-Length", str(len(body)))
        self._raw.end_headers()
        self._raw.wfile.write(body)


# ---------------------------------------------------------------------------
# 核心服务器基类
# ---------------------------------------------------------------------------
class BasicServer:
    """
    继承此类来定义业务路由，pytest 用例里只需 start() / stop()。
    """

    def __init__(self, port: int = 0, host: str = "127.0.0.1"):
        self._host = host
        self._port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        # 收集本实例所有带 _route_info 的方法
        self._routes = self._collect_routes()

    def _collect_routes(self) -> Dict[Tuple[str, str], Callable]:
        """扫描子类方法，把带 _route_info 的方法注册进路由表。"""
        routes: Dict[Tuple[str, str], Callable] = {}
        for name in dir(self.__class__):
            fn = getattr(self.__class__, name, None)
            if callable(fn) and hasattr(fn, "_route_info"):
                for method, path in fn._route_info:
                    routes[(method, path)] = getattr(self, name)
        # 内置默认 /basic 路由（子类可覆盖）
        if ("GET", "/basic") not in routes:
            routes[("GET", "/basic")] = self._default_basic
        return routes

    # ------------------------------------------------------------------ #
    # 内置默认路由（可在子类里用 @handler("GET", "/basic") 覆盖）           #
    # ------------------------------------------------------------------ #

    def _default_basic(self, req: Request) -> None:
        req.send_json({"controllers": "basic", "status": "ok"})

    # ------------------------------------------------------------------ #
    # 生命周期                                                             #
    # ------------------------------------------------------------------ #

    def start(self) -> "BasicServer":
        """启动后台 HTTP 服务，返回 self 以便链式调用。"""
        if self._server:
            return self
        routes = self._routes

        class _Handler(BaseHTTPRequestHandler):
            def _dispatch(self_, method: str):  # noqa: N805
                path = urlparse(self_.path).path
                fn = routes.get((method, path))
                if fn is None:
                    # 尝试 ANY
                    fn = routes.get(("ANY", path))
                if fn is None:
                    req = Request(self_)
                    req.send_json(
                        {"error": f"No route: {method} {path}"}, status=404
                    )
                    return
                fn(Request(self_))

            def do_GET(self_):
                self_._dispatch("GET")  # noqa: N805

            def do_POST(self_):
                self_._dispatch("POST")  # noqa: N805

            def do_PUT(self_):
                self_._dispatch("PUT")  # noqa: N805

            def do_DELETE(self_):
                self_._dispatch("DELETE")  # noqa: N805

            def do_PATCH(self_):
                self_._dispatch("PATCH")  # noqa: N805

            def log_message(self_, *_):
                pass  # noqa: N805

        self._server = HTTPServer((self._host, self._port), _Handler)
        self._port = self._server.server_address[1]  # 记录实际端口（port=0时）
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name=f"BasicServer-{self._port}",
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        """关闭服务，释放端口，等待线程退出。"""
        if not self._server:
            return
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    def __enter__(self) -> "BasicServer":
        return self.start()

    def __exit__(self, *_) -> None:
        self.stop()

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        if not self._server:
            raise RuntimeError("服务器尚未启动，请先调用 start()")
        return self._port

    @property
    def url(self) -> str:
        """基础 URL，例如 http://127.0.0.1:54321"""
        return f"http://{self.host}:{self.port}"

    def __repr__(self) -> str:
        state = self.url if self._server else "stopped"
        return f"<{self.__class__.__name__} {state}>"
