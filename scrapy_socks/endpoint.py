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


@implementer(IStreamClientEndpoint)
class SOCKSWrapper(object):
    factory = SOCKSClientFactory

    def __init__(self, reactor, endpoint, proxy_config, timestamps=None):
        self._host = proxy_config['host']
        self._port = proxy_config['port']
        self._proxy_config = proxy_config

        self._reactor = reactor
        self._endpoint = endpoint
        self._timestamps = None
        self._timer = None
        if timestamps is not None:
            self._timestamps = timestamps
            self._timer = IReactorTime(reactor)

    def noteTime(self, event):
        if self._timer:
            self._timestamps[event] = self._timer.seconds()

    def connect(self, protocolFactory):
        """
        Return a deferred firing when the SOCKS connection is established.
        """

        self.noteTime('START')
        try:
            # Connect with an intermediate SOCKS factory/protocol,
            # which then hands control to the provided protocolFactory
            # once a SOCKS connection has been established.
            f = self.factory(self._proxy_config)
            f.postHandshakeEndpoint = self._endpoint
            f.postHandshakeFactory = protocolFactory
            f.handshakeDone = defer.Deferred()
            f._timestamps = self._timestamps
            f._timer = self._timer
            wf = _WrappingFactory(f)
            self._reactor.connectTCP(self._host, self._port, wf, timeout=3)
            self.noteTime('SOCKET')
            wf._onConnection.addErrback(f.handshakeDone.errback)
            return f.handshakeDone
        except:
            return defer.fail()