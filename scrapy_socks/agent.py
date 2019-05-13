__author__ = 'Constantine Slednev <c.slednev@gmail.com>'


from twisted.internet import defer
from twisted.internet.error import ConnectionRefusedError
from twisted.internet.interfaces import IStreamClientEndpoint, IReactorTime
from twisted.internet.protocol import Protocol, ClientFactory
from twisted.internet.endpoints import _WrappingFactory, TCP4ClientEndpoint
from twisted.web.client import Agent as BaseAgent, SchemeNotSupported, BrowserLikePolicyForHTTPS
from twisted.web.iweb import IAgentEndpointFactory, IAgent, IPolicyForHTTPS
from twisted.protocols import tls
from zope.interface import implementer
import struct
import socket
import re

@implementer(IAgentEndpointFactory, IAgent)
class ProxyAgent(object):
    _tlsWrapper = TLSWrapClientEndpoint
    endpointFactory = SOCKSWrapper

    def __init__(self, reactor,
                 proxy_scheme,
                 proxy_host,
                 proxy_port,
                 proxy_username=None,
                 proxy_password=None,
                 contextFactory=BrowserLikePolicyForHTTPS(),
                 connectTimeout=None,
                 bindAddress=None,
                 pool=None):
        if not IPolicyForHTTPS.providedBy(contextFactory):
            raise NotImplementedError('contextFactory must implement IPolicyForHTTPS')
        self._policyForHTTPS = contextFactory
        self._wrappedAgent = BaseAgent.usingEndpointFactory(reactor, self, pool=pool)
        self._bindAddress = bindAddress
        self._connectTimeout = connectTimeout
        self.reactor = reactor
        self.proxy_scheme = proxy_scheme
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password

    def request(self, *a, **kw):
        return self._wrappedAgent.request(*a, **kw)

    def endpointForURI(self, uri):
        if uri.scheme not in (b'http', b'https'):
            raise SchemeNotSupported('unsupported scheme', uri.scheme)
        endpoint = TCP4ClientEndpoint(self.reactor,
                                      host=uri.host.decode(),
                                      port=uri.port,
                                      bindAddress=self._bindAddress,
                                      timeout=self._connectTimeout)
        factory = self.endpointFactory(self.reactor, endpoint, self.proxy_config)
        if uri.scheme == b'https':
            tlsPolicy = self._policyForHTTPS.creatorForNetloc(uri.host, uri.port)
            factory = self._tlsWrapper(tlsPolicy, factory)
        return factory
