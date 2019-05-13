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

class SOCKSClientFactory(ClientFactory):
    def __init__(self, proxy_config):
        self.proxy_config = proxy_config
        if self.proxy_config['version'] == '4':
            self.protocol = SOCKSv4ClientProtocol
        elif self.proxy_config['version'] == '4a':
            self.protocol = SOCKSv4aClientProtocol
        elif self.proxy_config['version'] == '5' or self.proxy_config['version'] == '5h':
            self.protocol = SOCKSv5ClientProtocol

    def buildProtocol(self, addr):
        r = ClientFactory.buildProtocol(self, addr)
        r.proxy_config = self.proxy_config
        r.postHandshakeEndpoint = self.postHandshakeEndpoint
        r.postHandshakeFactory = self.postHandshakeFactory
        r.handshakeDone = self.handshakeDone
        r._timestamps = self._timestamps
        r._timer = self._timer
        return r
