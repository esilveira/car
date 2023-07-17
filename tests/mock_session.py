import json as _json
from collections import deque
from dataclasses import InitVar, dataclass, field
from functools import partialmethod
from urllib.parse import urlparse

import aiohttp
from multidict import CIMultiDict, CIMultiDictProxy
import asyncio
from yarl import URL
from unittest.mock import Mock
from contextlib import asynccontextmanager


@dataclass
class FakeRequest:
    method: str
    url: str
    headers: dict[str, str]
    params: dict
    data: dict
    timeout: None | aiohttp.ClientTimeout = None

    def assert_path(self, path):
        assert urlparse(self.url).path == path


@dataclass
class FakeResponse:
    status: int
    headers: dict = field(default_factory=dict)
    body: str = ""
    body_dict: InitVar[dict | None] = None
    request: FakeRequest | None = None
    raise_timeout: bool = False
    content_length: int | None = None
    content_type: str | None = "application/json"

    def __post_init__(self, body_dict):
        if body_dict is not None:
            self.body = _json.dumps(body_dict)
        if self.body:
            if not self.content_length:
                self.content_length = len(self.body)

    async def json(self):
        return _json.loads(self.body)

    async def read(self):
        return self.body

    def raise_for_status(self):
        request_info: Mock | aiohttp.RequestInfo

        if self.status >= 400:
            if self.request is None:
                request_info = Mock(aiohttp.RequestInfo)
            else:
                request_info = aiohttp.RequestInfo(
                    URL(self.request.url),
                    self.request.method,
                    CIMultiDictProxy(CIMultiDict(self.request.headers)),
                    URL(self.request.url))

            raise aiohttp.ClientResponseError(request_info=request_info,
                                              history=(),
                                              status=self.status,)


class FakeSession:
    def __init__(self):
        self.requests: deque[FakeRequest] = deque()
        self.responses: deque[FakeResponse] = deque()

    @asynccontextmanager
    async def request(self, method, url, params=None, headers=None, data=None,
                      json=None, timeout=None):
        if json is not None:
            data = _json.dumps(json)
        self.requests.append(
            FakeRequest(method, url, headers or {}, params or {}, data or {},
                        timeout))

        response = self.responses.popleft()

        if response.raise_timeout:
            raise asyncio.TimeoutError

        yield response

    post = partialmethod(request, "POST")
    get = partialmethod(request, "GET")
    delete = partialmethod(request, "DELETE")
    put = partialmethod(request, "PUT")
    patch = partialmethod(request, "PATCH")
