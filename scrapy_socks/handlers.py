__author__ = 'Constantine Slednev <c.slednev@gmail.com>'

import logging
import os
from io import BytesIO
from time import time
from six.moves.urllib.parse import urldefrag
import hashlib
from twisted.internet import defer, reactor, protocol
from twisted.web.http_headers import Headers as TxHeaders
from twisted.web.http import PotentialDataLoss
from twisted.web.client import ResponseDone
from twisted.protocols.ftp import FTPFileListProtocol
from scrapy.http import Headers
from scrapy.responsetypes import responsetypes
from scrapy.utils.python import to_bytes
from scrapy.core.downloader.handlers.http11 import HTTP11DownloadHandler, \
    ScrapyAgent as ScrapyAgentBase, _RequestBodyProducer
from scrapy.core.downloader.handlers.ftp import FTPDownloadHandler as BaseFTPDownloadHandler, ReceivedDataProtocol
from scrapy.http.response import Response
from scrapy.exceptions import IgnoreRequest
from datetime import datetime
from math import log2
from twisted.internet import _sslverify
from scrapy_socks.agent import ProxyAgent
import dsnparse3
from scrapy_socks.exceptions import ProxyError
from twisted.web.client import Agent as BaseAgent, SchemeNotSupported, BrowserLikePolicyForHTTPS


class HTTPDownloadHandler(HTTP11DownloadHandler):
    def download_request(self, request, spider):
        """Return a deferred for the HTTP download"""
        agent = ScrapyAgent(spider, contextFactory=self._contextFactory, pool=self._pool,
                            maxsize=getattr(spider, 'download_maxsize', self._default_maxsize),
                            warnsize=getattr(spider, 'download_warnsize', self._default_warnsize),
                            fail_on_dataloss=self._fail_on_dataloss)
        return agent.download_request(request)


class ScrapyAgent(ScrapyAgentBase):
    def __init__(self, spider, *a, **kw):
        self.spider = spider
        super(ScrapyAgent, self).__init__(*a, **kw)

    def _get_agent(self, request, timeout):
        bindAddress = request.meta.get('bindaddress') or self._bindAddress
        proxy = request.meta.get('proxy', '').lower()
        timeout = request.meta.pop('proxy_timeout', timeout)

        if proxy:
            parsed_proxy = dsnparse3.parse(proxy)
            if parsed_proxy.scheme in ('http', 'https'):
                return super(ScrapyAgent, self)._get_agent(request, timeout)
            if parsed_proxy.scheme not in ('socks4', 'socks4a', 'socks5', 'socks5h'):
                raise SchemeNotSupported('unsupported scheme', parsed_proxy.scheme)

            return ProxyAgent(reactor=reactor,
                              proxy_scheme=parsed_proxy.scheme,
                              proxy_host=parsed_proxy.host,
                              proxy_port=parsed_proxy.port,
                              proxy_username=parsed_proxy.username,
                              proxy_password=parsed_proxy.password,
                              contextFactory=self._contextFactory,
                              bindAddress=bindAddress)

        return super(ScrapyAgent, self)._get_agent(request, timeout)
