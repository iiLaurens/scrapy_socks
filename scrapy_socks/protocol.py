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


class SOCKSClientProtocol(Protocol):
    buf = b''

    def noteTime(self, event):
        if self._timer:
            self._timestamps[event] = self._timer.seconds()

    def abort(self, errmsg, exception=SOCKSError):
        self.transport.loseConnection()
        self.handshakeDone.errback(exception('SOCKS %s: %s' % (self.proxy_config['version'], errmsg)))

    def is_hostname(self, string):
        dns_label_regex = re.compile(r'^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$')
        return all([dns_label_regex.match(label) for label in string.split('.')])

    # Called when verifySocksReply was successful
    def setupRelay(self):
        self.noteTime('RESPONSE')
        # Build protocol from provided factory and transfer control to it.
        self.transport.protocol = self.postHandshakeFactory.buildProtocol(self.transport.getPeer())
        self.transport.protocol.makeConnection(self.transport)
        self.handshakeDone.callback(self.transport.protocol)

    # Checks if the relayRequest was successful
    # Probably ugly to specify members host and port as parameters
    def verifySocksReply(self, host, port):
        pass

    # Also called "connection request". This method initiates a SOCKS connection.
    # All SOCKS versions share this (main) functionality
    def sendRelayRequest(self):
        pass


class SOCKSv5ClientProtocol(SOCKSClientProtocol):
    protocol_state = 'begin'
    # Directly taken from socksipy
    SOCKS5_ERRORS = {
        0x01: "General SOCKS server failure",
        0x02: "Connection not allowed by ruleset",
        0x03: "Network unreachable",
        0x04: "Host unreachable",
        0x05: "Connection refused",
        0x06: "TTL expired",
        0x07: "Command not supported, or protocol error",
        0x08: "Address type not supported"
    }

    def negotiateAuthenticationMethod(self):
        if self.proxy_config['version_specific']['username'] and self.proxy_config['version_specific']['password']:
            # 0x05 is the socks version number, 0x02 is the number of auth methods
            # 0x00 is auth method "No authentication" and 0x02 is auth method "Username/Password"
            self.transport.write(b"\x05\x02\x00\x02")
        else:
            # when the user doesn't specify any user/pass creds, try auth method "no authentication"
            self.transport.write(b'\x05\x01\x00')

        self.protocol_state = 'do_auth'

    def authenticate(self, data):
        where = 'authentication handshake'
        if len(data) < 2:
            self.abort('Too few data from server %s.' % where)
        else:
            version, chosen_auth = struct.unpack('!BB', data)
            if version != 0x5:
                self.abort('expected 0x5 in %s.' % where)
                return False

            if chosen_auth == 0x2:
                # do user/pass authentication
                username, password = self.proxy_config['version_specific']['username'], \
                                     self.proxy_config['version_specific']['password']
                msg = struct.pack('BB%ssB%ss' % (len(username), len(password)),
                                  1,
                                  len(username),
                                  username.encode(),
                                  len(password),
                                  password.encode())
                self.transport.write(msg)
                self.noteTime('DO_USER_PASS_AUTH')
                self.protocol_state = 'check_auth'
            elif chosen_auth == 0x0:
                # no authentication required
                self.noteTime('AUTHENTICATED')
                self.protocol_state = 'authenticated'
            else:
                self.abort('Invalid chosen auth method %d in %s.' % (chosen_auth, where))

    def checkAuth(self, data):
        where = 'authentication check'
        if len(data) < 2:
            self.abort('Too few data from server %s.' % where)
        else:
            version, status_code = struct.unpack('!BB', data)
            if version != 0x1:
                self.abort('expected 0x01 in %s.' % where)
                return False
            if status_code != 0x0:
                self.abort('Authentication with %s failed in %s.' % (
                    repr(self.proxy_config['version_specific']['username']), where))
                return False
            else:
                self.noteTime('AUTHENTICATED')
                self.protocol_state = 'authenticated'

    def sendRelayRequest(self, host, port):
        # Do the actual connection request
        # See http://en.wikipedia.org/wiki/SOCKS and the RFC
        msg = b'\x05'  # message starts with the SOCKS version
        # There are three types of commands. If no cmd_code is given
        # in the proxy_config, assume 0x01 (establish a TCP/IP stream connection)
        msg += b'\x01'
        # The third byte is reserved and must be 0x00
        msg += b'\x00'
        # The fourth bytes specifies the address type
        # 0x01 for an good old IPv4 address, 0x03 for a domain name, 0x04 for a IPv6 address
        # First try to parse the given host as a IPv4 address (the most common case), then
        # assume it's a hostname, if this fails, it must be a IPv6 address, otherwise we have
        # an error. We can't resolve any hostname at this stage locally (we'd need a blocking call
        # to gethostbyname()), so we just accept remote dns resolving if host is a DNS name.
        if self.is_hostname(host):
            # do remote resolving
            msg += b'\x03' + chr(len(host)).encode() + host.encode()
        else:
            try:
                addr_bytes = socket.inet_aton(host)
                msg += b'\x01' + addr_bytes
            except socket.error:
                try:
                    addr_bytes = socket.inet_pton(socket.AF_INET6, host)
                    msg += b'\x04' + addr_bytes
                except socket.error:
                    # Everything failed
                    self.abort('Invalid host')
                    return False

        msg += struct.pack(">H", port)
        self.transport.write(msg)
        self.noteTime('RELAY_REQUEST_SENT')
        self.protocol_state = 'connection_requested'

    def verifySocksReply(self, data):
        where = 'SOCKS5 verifySocksReply'

        if len(data) < 10:  # all hostname are longer than a IPv4 address
            self.abort('Too few data from server %s.' % where)
        else:
            version, reply, rsv, address_type = struct.unpack('!BBBB', data[:4])

            if version != 0x5:
                self.abort('Invalid version')
                return False

            if reply == 0x5:  # Connection refused
                self.abort('Connection refused', exception=ConnectionRefusedError)
                return False

            if reply != 0x0:
                self.abort(
                    'Server reply indicates failure. Reason: %s' % self.SOCKS5_ERRORS.get(reply, "Unknown error"))
                return False

            if address_type == 0x1:  # handle IPv4 address
                self.bound_address, self.bound_port = socket.inet_ntoa(data[4:8]), \
                                                      struct.unpack('>H', data[8:10])[0]
            elif address_type == 0x3:  # handle domain name
                dns_name_len = ord(data[4:5])
                self.bound_address, self.bound_port = data[5:dns_name_len], \
                                                      struct.unpack('>H',
                                                                    data[(5 + dns_name_len):(5 + dns_name_len + 2)])[0]
            elif address_type == 0x4:  # handle Ipv6 address
                self.bound_address, self.bound_port = socket.inet_ntop(socket.AF_INET6, data[4:20]), \
                                                      struct.unpack('>H', data[20:22])[0]

            self.protocol_state = 'connection_verified'
            return True

    def connectionMade(self):
        self.noteTime('CONNECTED')
        self.noteTime('NEGOTIATE_AUTH_METHOD')
        self.negotiateAuthenticationMethod()

    def dataReceived(self, data):
        self.buf += data

        if self.protocol_state == 'do_auth':
            self.authenticate(data)
        elif self.protocol_state == 'check_auth':
            self.checkAuth(data)
        if self.protocol_state == 'authenticated':
            host = self.postHandshakeEndpoint._host
            port = self.postHandshakeEndpoint._port
            self.sendRelayRequest(host, port)
        elif self.protocol_state == 'connection_requested':
            if self.verifySocksReply(data):
                self.setupRelay()


class SOCKSv4ClientProtocol(SOCKSClientProtocol):
    SOCKS4_ERRORS = {
        0x5B: "Request rejected or failed",
        0x5C: "Request rejected because SOCKS server cannot connect to identd on the client",
        0x5D: "Request rejected because the client program and identd report different user-ids"
    }

    def sendRelayRequest(self, host, port):
        username = self.proxy_config['version_specific']['username']
        ver, cmd, username = 0x4, 0x1, [b'\x00', username.encode() + b'\x00'][not not username]
        try:
            addr = socket.inet_aton(host)
        except socket.error:
            self.abort('Not a valid IPv4 address.')
            return False
        msg = struct.pack('!BBH', ver, cmd, port) + addr + username
        self.transport.write(msg)
        self.noteTime('REQUEST')

    def verifySocksReply(self, data):
        """
        Return True on success and False on need-more-data or error.
        In the case of an error, the connection is closed and the
        handshakeDone errback is invoked with a SOCKSError exception
        before False is returned.
        """
        if len(data) < 8:
            return False
        if ord(data[0]) != 0x0:
            self.abort('Expected 0 bytes')
            return False
        status = ord(data[1])
        if status != 0x5a:
            self.abort('Relay request failed. Reason=%s.' % self.SOCKS4_ERRORS.get(data[0], 'Unknown error'))
            return False
        return True

    def connectionMade(self):
        self.noteTime('CONNECT')
        self.noteTime('NEGOTIATE')
        self.sendRelayRequest(self.postHandshakeEndpoint._host, self.postHandshakeEndpoint._port)

    def dataReceived(self, data):
        self.buf += data
        if self.verifySocksReply(data):
            self.setupRelay()


class SOCKSv4aClientProtocol(SOCKSv4ClientProtocol):
    '''Only extends SOCKS 4 to remotely resolve hostnames.'''

    def sendRelayRequest(self, host, port):
        username = self.proxy_config['version_specific']['username']
        ver, cmd, username = 0x4, 0x1, [b'\x00', username.encode() + b'\x00'][not not username]
        try:
            addr = socket.inet_aton(host)
        except socket.error:
            addr = '\x00\x00\x00\x01'
            dnsname = '%s\x00' % host
            msg = struct.pack('!BBH', ver, cmd, port) + addr + username + dnsname
        else:
            msg = struct.pack('!BBH', ver, cmd, port) + addr + username
        self.transport.write(msg)
        self.noteTime('REQUEST')