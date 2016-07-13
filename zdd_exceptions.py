""" Exit Status 1 is already used in the script.
    Zdd returns with exit status 1 when app is not force
    deleted either through argument or through prompt.
    Exit Status 2 is used for Unknown Exceptions.
"""


class InvalidArgException(Exception):
    """ This exception indicates invalid combination of arguments
        passed to zdd"""
    def __init__(self, msg):
        super(InvalidArgException, self).__init__(msg)
        self.error = msg
        self.zdd_exit_status = 3


class MissingFieldException(Exception):
    """ This exception indicates required fields which are missing
        in JSON payload passed to zdd"""
    def __init__(self, msg, field):
        super(MissingFieldException, self).__init__(msg)
        self.error = msg
        self.missing_field = field
        self.zdd_exit_status = 4


class MarathonLbEndpointException(Exception):
    """ This excaption indicates issue with one of the marathonlb
        endpoints specified as argument to Zdd"""
    def __init__(self, msg, url, error):
        super(MarathonLbEndpointException, self).__init__(msg)
        self.msg = msg
        self.url = url
        self.error = error
        self.zdd_exit_status = 5


class MarathonEndpointException(Exception):
    """ This excaption indicates issue with marathon endpoint
        specified as argument to Zdd"""
    def __init__(self, msg, url, error):
        super(MarathonEndpointException, self).__init__(msg)
        self.msg = msg
        self.url = url
        self.error = error
        self.zdd_exit_status = 6


class AppCreateException(Exception):
    """ This exception indicates there was a error while creating the
        new App and hence it was not created."""
    def __init__(self, msg, url, payload, error):
        super(AppCreateException, self).__init__(msg)
        self.msg = msg
        self.error = error
        self.url = url
        self.payload = payload
        self.zdd_exit_status = 7


class AppDeleteException(Exception):
    """ This exception indicates there was a error while deleting the
        old App and hence it was not deleted """
    def __init__(self, msg, url, appid, error):
        super(AppDeleteException, self).__init__(msg)
        self.msg = msg
        self.error = error
        self.url = url
        self.zdd_exit_status = 8


class AppScaleException(Exception):
    """ This exception indicated there was a error while either scaling up
        new app or while scaling down old app"""
    def __init__(self, msg, url, payload, error):
        super(AppScaleException, self).__init__(msg)
        self.msg = msg
        self.error = error
        self.url = url
        self.payload = payload
        self.zdd_exit_status = 9
