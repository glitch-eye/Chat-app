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
import os

from .request import Request
from .response import Response
from .dictionary import CaseInsensitiveDict
import base64



def get_base_dir():
    return os.path.dirname(os.path.abspath(__file__))

# Giữ lại _parse_body_params để các Route Handler có thể gọi
def parse_body_params(body_bytes):
    """Phân tích body POST (x-www-form-urlencoded) từ bytes."""
    params = {}
    if not body_bytes: return params
    try:
        body_str = body_bytes.decode('utf-8')
        for pair in body_str.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                params[k.strip()] = v.strip() 
    except:
        pass
    return params

def get_encoding_from_headers(headers):
    """Giả lập hàm tìm kiếm encoding từ Content-Type header."""
    content_type = headers.get('Content-Type', '')
    if 'charset=' in content_type:
        return content_type.split('charset=')[-1].strip()
    return 'utf-8'
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
        #: Conndection address
        self.connaddr = connaddr
        #: Routes
        self.routes = routes
        #: Request
        self.request = Request()
        #: Response
        self.response = Response()
        # 🟢 FIX: Load nội dung trang từ thư mục www khi khởi tạo
        self.INDEX_PAGE = self._load_page_content("index.html")
        self.LOGIN_PAGE = self._load_page_content("login.html")
        self.UNAUTHORIZED_PAGE = self._load_page_content("unauthorize.html")

    def _load_page_content(self, filename):
        """Đọc nội dung file HTML từ thư mục www."""
        # FIX: Đường dẫn trỏ đến thư mục www
        filepath = os.path.join(get_base_dir(), "www", filename)
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
                return content
        except FileNotFoundError:
            return None
        except Exception as e:
            return None
       
    
    def handle_client(self, conn, addr, routes):
        """
        Handle an incoming client connection.

        This method reads the request from the socket, prepares the request object,
        invokes the appropriate route handler if available, builds the response,
        and sends it back to the client.

        :param conn (socket): The client socket connection.
        :param addr (tuple): The client's address.
        :param routes (dict): The route mapping for dispatching requests.
        """

        # Connection handler.
        self.conn = conn        
        # Connection address.
        self.connaddr = addr
        # Request handler
        req = self.request
        # Response handler
        resp = self.response

        # Handle the request
        try :
            msg = conn.recv(1024).decode('utf-8')
        except UnicodeDecodeError:
            # Xử lý nếu client gửi dữ liệu không phải utf-8
            print("[HttpAdapter] Error decoding request.")
            return

        if not msg:
            conn.close()
            return
        
        req.prepare(msg, routes)

        resp.status_code = 404
        resp.body = b"<h1>404 Not Found</h1>" 
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        
        is_handled = False

        # 3. 🟢 GỌI HOOK (Route Handler) NẾU TÌM THẤY
        if req.hook:
            print("[HttpAdapter] hook in route-path METHOD {} PATH {}".format(req.hook._route_path,req.hook._route_methods))
            try:
                # req.hook là hàm handler (ví dụ: home_route, login_route)
                # Handler sẽ cập nhật trực tiếp resp
                req.hook(request=req, response=resp, adapter=self) 
                
                if resp.status_code is None: resp.status_code = 200
                if resp.body is None: resp.body = b""
            except Exception as e:
                print(f"[Adapter] Error executing handler for {req.url}: {e}")
                resp.status_code = 500
                resp.body = b"Internal Server Error"
            
            is_handled = True
            
        # 4. Xây dựng Response và gửi (Dù là Hook hay 404)
        resp.headers['Content-Length'] = str(len(resp.body))
        
        response_data = resp.build_response(req)

        #print(response)
        conn.sendall(response_data)
        conn.close()

    @property
    # def extract_cookies(self, req, resp):
    def extract_cookies(self, headers):
        """
        Build cookies from the :class:`Request <Request>` headers.

        :param req:(Request) The :class:`Request <Request>` object.
        :param resp: (Response) The res:class:`Response <Response>` object.
        :rtype: cookies - A dictionary of cookie key-value pairs.
        """
        cookies = {}
        for header in headers:
            if header.startswith("Cookie:"):
                cookie_str = header.split(":", 1)[1].strip()
                for pair in cookie_str.split(";"):
                    key, value = pair.strip().split("=")
                    cookies[key] = value
        return cookies

    def build_response(self, req, resp = None):
        """Builds a :class:`Response <Response>` object 

        :param req: The :class:`Request <Request>` used to generate the response.
        :param resp: The  response object.
        :rtype: Response
        """
        response = Response()

        # Set encoding.
        response.encoding = get_encoding_from_headers(response.headers)
        # response.raw = resp
        response.reason = response.raw.reason

        if isinstance(req.url, bytes):
            response.url = req.url.decode("utf-8")
        else:
            response.url = req.url

        # Add new cookies from the server.
        response.cookies = self.extract_cookies(req.headers)

        # Give the Response some context.
        response.request = req
        response.connection = self

        return response

    # def get_connection(self, url, proxies=None):
        # """Returns a url connection for the given URL. 

        # :param url: The URL to connect to.
        # :param proxies: (optional) A Requests-style dictionary of proxies used on this request.
        # :rtype: int
        # """

        # proxy = select_proxy(url, proxies)

        # if proxy:
            # proxy = prepend_scheme_if_needed(proxy, "http")
            # proxy_url = parse_url(proxy)
            # if not proxy_url.host:
                # raise InvalidProxyURL(
                    # "Please check proxy URL. It is malformed "
                    # "and could be missing the host."
                # )
            # proxy_manager = self.proxy_manager_for(proxy)
            # conn = proxy_manager.connection_from_url(url)
        # else:
            # # Only scheme should be lower case
            # parsed = urlparse(url)
            # url = parsed.geturl()
            # conn = self.poolmanager.connection_from_url(url)

        # return conn


    def add_headers(self, request):
        """
        Add headers to the request.

        This method is intended to be overridden by subclasses to inject
        custom headers. It does nothing by default.

        
        :param request: :class:`Request <Request>` to add headers to.
        """
        pass

    def build_proxy_headers(self, proxy):
        """Returns a dictionary of the headers to add to any request sent
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
        
        username, password = ("admin", "password")

        if username:
            headers["Proxy-Authorization"] = (username, password)

        return headers