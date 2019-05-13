__author__ = 'Constantine Slednev <c.slednev@gmail.com>'


class BaseException(Exception):
    def __init__(self, val):
        self.val = val

    def __str__(self):
        return repr(self.val)


class SOCKSError(BaseException):
    pass

class ProxyError(BaseException):
    pass