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
        """
        Handle incoming client connection with authentication and chat APIs.
        """
        import time
        
        # Initialize tracker storage
        if not hasattr(self.__class__, 'TRACKER'):
            self.__class__.TRACKER = {"peers": {}}
        
        self.conn = conn
        self.connaddr = addr
        req = self.request
        resp = self.response
        
        try:
            msg = conn.recv(4096).decode('utf-8')
            if not msg:
                conn.close()
                return
            
            req.prepare(msg, routes)
            cookies = self.extract_cookies(req)
            
            def get_body():
                body_start = msg.find('\r\n\r\n')
                return msg[body_start + 4:] if body_start != -1 else ""
            
            def parse_form(text):
                result = {}
                for pair in text.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        result[k] = v
                return result
            
            print("[HttpAdapter] {} {} from {}".format(req.method, req.path, addr))
            print("[HttpAdapter] Cookies: {}".format(cookies))
            
            path = req.path
            if len(path) > 1 and path.endswith('/'):
                path = path[:-1]
            
            # TASK 1A: POST /login
            if req.method == 'POST' and path == '/login':
                req.body = get_body()
                form_data = parse_form(req.body)
                username = form_data.get('username', '')
                password = form_data.get('password', '')
                
                print("[HttpAdapter] Login attempt: username={}".format(username))
                
                if username == 'admin' and password == 'password':
                    print("[HttpAdapter] [OK] Login successful - setting auth cookie")  # ← Fixed
                    resp.status_code = 200
                    resp.reason = "OK"
                    resp.cookies['auth'] = 'true'
                    
                    c_len, resp._content = resp.build_content('/index.html', 'www')
                    resp.headers['Content-Type'] = 'text/html'
                    resp.headers['Content-Length'] = str(c_len)
                else:
                    print("[HttpAdapter] [FAIL] Login failed - invalid credentials")  # ← Fixed
                    resp.status_code = 401
                    resp.reason = "Unauthorized"
                    
                    c_len, resp._content = resp.build_content('/401.html', 'www')
                    resp.headers['Content-Type'] = 'text/html'
                    resp.headers['Content-Length'] = str(c_len)
                
                response_bytes = resp.build_response_header(req) + resp._content
            
            # TASK 1B: GET /
            elif req.method == 'GET' and (path == '/' or path == '/index.html' or path == '/index'):
                if cookies.get('auth') == 'true':
                    print("[HttpAdapter] [AUTH] Authenticated user accessing /")  # ← Fixed
                    resp.status_code = 200
                    resp.reason = "OK"
                    
                    c_len, resp._content = resp.build_content('/index.html', 'www')
                    resp.headers['Content-Type'] = 'text/html'
                    resp.headers['Content-Length'] = str(c_len)
                else:
                    print("[HttpAdapter] [NOAUTH] Unauthenticated - returning 401")  # ← Fixed
                    resp.status_code = 401
                    resp.reason = "Unauthorized"
                    
                    c_len, resp._content = resp.build_content('/401.html', 'www')
                    resp.headers['Content-Type'] = 'text/html'
                    resp.headers['Content-Length'] = str(c_len)
                
                response_bytes = resp.build_response_header(req) + resp._content
            
            # TASK 2: POST /submit-info
            elif req.method == 'POST' and path == '/submit-info':
                req.body = get_body()
                form_data = parse_form(req.body)
                
                peer_ip = form_data.get('ip', '')
                peer_port = form_data.get('port', '')
                peer_nick = form_data.get('nick', '')
                
                if peer_ip and peer_port:
                    key = "{}:{}".format(peer_ip, peer_port)
                    self.__class__.TRACKER["peers"][key] = {
                        "ip": peer_ip,
                        "port": int(peer_port),
                        "nick": peer_nick,
                        "last_seen": time.time()
                    }
                    print("[HttpAdapter] [REGISTER] Peer registered: {}".format(key))  # ← Fixed
                
                resp.status_code = 200
                resp.reason = "OK"
                resp.headers['Content-Type'] = 'application/json'
                resp._content = b'{"status":"ok"}'
                resp.headers['Content-Length'] = str(len(resp._content))
                response_bytes = resp.build_response_header(req) + resp._content
            
            # TASK 2: GET /get-list
            elif req.method == 'GET' and path == '/get-list':
                now = time.time()
                active_peers = [
                    p for p in self.__class__.TRACKER["peers"].values()
                    if now - p["last_seen"] < 60
                ]
                
                peer_list = []
                for p in active_peers:
                    peer_list.append(
                        '{{"ip":"{}","port":{},"nick":"{}"}}'.format(
                            p["ip"], p["port"], p.get("nick", "")
                        )
                    )
                
                body = ('{"peers":[' + ",".join(peer_list) + "]}").encode('utf-8')
                
                resp.status_code = 200
                resp.reason = "OK"
                resp.headers['Content-Type'] = 'application/json'
                resp._content = body
                resp.headers['Content-Length'] = str(len(resp._content))
                
                print("[HttpAdapter] [LIST] Returned {} active peers".format(len(active_peers)))  # ← Fixed
                response_bytes = resp.build_response_header(req) + resp._content
            
            # TASK 2: POST /add-list
            elif req.method == 'POST' and path == '/add-list':
                req.body = get_body()
                form_data = parse_form(req.body)
                
                added = 0
                peers_str = form_data.get('peers', '')
                
                if peers_str:
                    for item in peers_str.split(','):
                        parts = item.split(':')
                        if len(parts) >= 2:
                            ip, port = parts[0], parts[1]
                            nick = parts[2] if len(parts) >= 3 else ''
                            key = "{}:{}".format(ip, port)
                            
                            self.__class__.TRACKER["peers"][key] = {
                                "ip": ip,
                                "port": int(port),
                                "nick": nick,
                                "last_seen": time.time()
                            }
                            added += 1
                
                resp.status_code = 200
                resp.reason = "OK"
                resp.headers['Content-Type'] = 'application/json'
                resp._content = '{{"status":"ok","added":{}}}'.format(added).encode('utf-8')
                resp.headers['Content-Length'] = str(len(resp._content))
                
                print("[HttpAdapter] [ADD] Added {} peers".format(added))  # ← Fixed
                response_bytes = resp.build_response_header(req) + resp._content
            
            # TASK 2: Hook Handler
            elif req.hook:
                print("[HttpAdapter] [HOOK] Hook for {} {}".format(  # ← Fixed
                    req.hook._route_methods, req.hook._route_path))
                
                req.body = get_body()
                
                try:
                    result = req.hook(headers=req.headers, body=req.body)
                    
                    if result:
                        resp.status_code = 200
                        resp.reason = "OK"
                        
                        if isinstance(result, str):
                            resp._content = result.encode('utf-8')
                        elif isinstance(result, bytes):
                            resp._content = result
                        else:
                            resp._content = str(result).encode('utf-8')
                        
                        resp.headers['Content-Type'] = 'application/json'
                        resp.headers['Content-Length'] = str(len(resp._content))
                        response_bytes = resp.build_response_header(req) + resp._content
                    else:
                        response_bytes = resp.build_response(req)
                
                except Exception as e:
                    print("[HttpAdapter] [ERROR] Hook error: {}".format(e))  # ← Fixed
                    import traceback
                    traceback.print_exc()
                    
                    resp.status_code = 500
                    resp.reason = "Internal Server Error"
                    resp._content = b"Internal Server Error"
                    resp.headers['Content-Type'] = 'text/plain'
                    resp.headers['Content-Length'] = str(len(resp._content))
                    response_bytes = resp.build_response_header(req) + resp._content
            
            # Normal file serving
            else:
                print("[HttpAdapter] [FILE] File serving: {}".format(req.path))  # ← Fixed
                response_bytes = resp.build_response(req)
            
            conn.sendall(response_bytes)
        
        except Exception as e:
            print("[HttpAdapter] [ERROR] Error: {}".format(e))  # ← Fixed
            import traceback
            traceback.print_exc()
            
            try:
                conn.sendall(b"HTTP/1.1 500 Internal Server Error\r\n\r\nError")
            except:
                pass
        
        finally:
            conn.close()

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