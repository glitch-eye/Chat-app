#
# Copyright (C) 2025 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course.
#
# WeApRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#

"""
daemon.httpadapter
~~~~~~~~~~~~~~~~~

This module provides a http adapter object to manage and persist 
http settings (headers, bodies). The adapter supports both
raw URL paths and RESTful route definitions, and integrates with
Request and Response objects to handle client-server communication.
"""

from .request import Request
from .response import Response
from .dictionary import CaseInsensitiveDict

class HttpAdapter:
    """
    A mutable :class:`HTTP adapter <HTTP adapter>` for managing client connections
    and routing requests.

    The `HttpAdapter` class encapsulates the logic for receiving HTTP requests,
    dispatching them to appropriate route handlers, and constructing responses.
    It supports RESTful routing via hooks and integrates with :class:`Request <Request>` 
    and :class:`Response <Response>` objects for full request lifecycle management.

    Attributes:
        ip (str): IP address of the client.
        port (int): Port number of the client.
        conn (socket): Active socket connection.
        connaddr (tuple): Address of the connected client.
        routes (dict): Mapping of route paths to handler functions.
        request (Request): Request object for parsing incoming data.
        response (Response): Response object for building and sending replies.
    """

    __attrs__ = [
        "ip",
        "port",
        "conn",
        "connaddr",
        "routes",
        "request",
        "response",
    ]

    def __init__(self, ip, port, conn, connaddr, routes):
        """
        Initialize a new HttpAdapter instance.

        :param ip (str): IP address of the client.
        :param port (int): Port number of the client.
        :param conn (socket): Active socket connection.
        :param connaddr (tuple): Address of the connected client.
        :param routes (dict): Mapping of route paths to handler functions.
        """

        #: IP address.
        self.ip = ip
        #: Port.
        self.port = port
        #: Connection
        self.conn = conn
        #: Connection address
        self.connaddr = connaddr
        #: Routes
        self.routes = routes
        #: Request
        self.request = Request()
        #: Response
        self.response = Response()

    def extract_cookies(self, req):
        """
        Extract cookies from the :class:`Request <Request>` headers.

        :param req: (Request) The :class:`Request <Request>` object.
        :rtype: dict - A dictionary of cookie key-value pairs.
        """
        cookies = {}
        
        # Get Cookie header from request (lowercase key)
        cookie_header = req.headers.get('cookie', '')
        
        if cookie_header:
            # Parse cookie string: "key1=value1; key2=value2"
            for pair in cookie_header.split(";"):
                pair = pair.strip()
                if '=' in pair:
                    key, value = pair.split("=", 1)
                    cookies[key.strip()] = value.strip()
        
        return cookies

    def parse_post_body(self, body):
        """
        Parse POST request body (application/x-www-form-urlencoded).
        
        :param body: (str) The request body.
        :rtype: dict - Dictionary of form parameters.
        """
        params = {}
        if body:
            for pair in body.split("&"):
                if '=' in pair:
                    key, value = pair.split("=", 1)
                    params[key] = value
        return params

    def handle_client(self, conn, addr, routes):
        self.conn, self.connaddr = conn, addr
        req, resp = self.request, self.response
        try:
            msg = conn.recv(4096).decode('utf-8')
            if not msg: conn.close(); return

            req.prepare(msg, routes)

            # reset response state
            resp.headers.clear(); resp.cookies.clear()
            resp.status_code = 200; resp.reason = "OK"; resp._content = b""

            if not getattr(req, 'method', None) or not getattr(req, 'path', None):
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n"); conn.close(); return

            # extract
            cookies = self.extract_cookies  
            body = getattr(req, 'body', b'') or b''
            form_data = self.parse_form_data(body)

            path = req.path
            if len(path) > 1 and path.endswith('/'): path = path[:-1]
            path = path.split('?', 1)[0]
            method = req.method

            # find hook
            hook = req.hook or (routes.get((method, path)) if routes else None)

            if hook:
                result = hook(method=method, path=path, headers=req.headers,
                            cookies=cookies, body=body, form_data=form_data)

                if isinstance(result, dict):
                    resp.status_code = result.get('status', 200)
                    resp.reason = result.get('reason', 'OK')

                    for k, v in result.get('headers', {}).items(): resp.headers[k] = v
                    for k, v in result.get('cookies', {}).items(): resp.cookies[k] = v

                    content = result.get('body', b'')
                    resp._content = content.encode('utf-8') if isinstance(content, str) else \
                                    (content if isinstance(content, bytes) else str(content).encode('utf-8'))

                    if 'Content-Type' not in resp.headers:
                        resp.headers['Content-Type'] = 'text/html; charset=utf-8'

                    response_bytes = resp.build_response_header(req) + resp._content
                else:
                    response_bytes = resp.build_response(req)
            else:
                response_bytes = resp.build_response(req)

            conn.sendall(response_bytes)
        except Exception:
            try: conn.sendall(b"HTTP/1.1 500 Internal Server Error\r\n\r\nInternal Server Error")
            except: pass
        finally:
            try: conn.close()
            except: pass


    def add_headers(self, request):
        """
        Add headers to the request.

        This method is intended to be overridden by subclasses to inject
        custom headers. It does nothing by default.
        
        :param request: :class:`Request <Request>` to add headers to.
        """
        pass

    def build_proxy_headers(self, proxy):
        """
        Returns a dictionary of the headers to add to any request sent
        through a proxy. 

        :class:`HttpAdapter <HttpAdapter>`.

        :param proxy: The url of the proxy being used for this request.
        :rtype: dict
        """
        headers = {}
        #
        # TODO: build your authentication here
        #       username, password =...
        # we provide dummy auth here
        #
        username, password = ("user1", "password")

        if username:
            headers["Proxy-Authorization"] = (username, password)

        return headers