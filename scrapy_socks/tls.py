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
class TLSWrapClientEndpoint(object):
    """An endpoint which automatically starts TLS.

    :param contextFactory: A `ContextFactory`__ instance.
    :param wrappedEndpoint: The endpoint to wrap.

    __ http://twistedmatrix.com/documents/current/api/twisted.internet.protocol.ClientFactory.html

    """

    _wrapper = tls.TLSMemoryBIOFactory

    def __init__(self, contextFactory, wrappedEndpoint):
        self.contextFactory = contextFactory
        self.wrappedEndpoint = wrappedEndpoint

    def connect(self, fac):
        """Connect to the wrapped endpoint, then start TLS.

        The TLS negotiation is done by way of wrapping the provided factory
        with `TLSMemoryBIOFactory`__ during connection.

        :returns: A ``Deferred`` which fires with the same ``Protocol`` as
            ``wrappedEndpoint.connect(fac)`` fires with. If that ``Deferred``
            errbacks, so will the returned deferred.

        __ http://twistedmatrix.com/documents/current/api/twisted.protocols.tls.html

        """
        wrapped_fac = self._wrapper(self.contextFactory, True, fac)
        return self.wrappedEndpoint.connect(wrapped_fac).addCallback(self._unwrapProtocol)

    def _unwrapProtocol(self, proto):
        return proto.wrappedProtocol

    @property
    def _host(self):
        return self.wrappedEndpoint._host

    @property
    def _port(self):
        return self.wrappedEndpoint._port