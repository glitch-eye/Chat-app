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
daemon.request
~~~~~~~~~~~~~~~~~

This module provides a Request object to manage and persist 
request settings (cookies, auth, proxies).
"""
from .dictionary import CaseInsensitiveDict
import urllib.parse

class Request():
    """The fully mutable "class" `Request <Request>` object,
    containing the exact bytes that will be sent to the server.

    Instances are generated from a "class" `Request <Request>` object, and
    should not be instantiated manually; doing so may produce undesirable
    effects.
    """
    __attrs__ = [
        "method",
        "url",
        "headers",
        "body",
        "reason",
        "cookie",
        "body",
        "routes",
        "hook",
        "params", # Thêm params vào danh sách thuộc tính
    ]

    def __init__(self):
        #: HTTP verb to send to the server.
        self.method = None
        #: HTTP URL to send the request to.
        self.url = None
        #: dictionary of HTTP headers.
        self.headers = None
        #: HTTP path
        self.path = None        
        # The cookies set used to create Cookie header
        self.cookies = None # 🎯 Sửa: Khởi tạo self.cookies là Dict
        #: request body to send to the server.
        self.body = None
        #: URL Query parameters (từ chuỗi ?key=value)
        self.params = {} # 🎯 Mới: Thêm thuộc tính params
        #: Routes
        self.routes = {}
        #: Hook point for routed mapped-path
        self.hook = None
        self.auth = False

    def _parse_cookies(self):
        """Phân tích raw 'Cookie' header và lưu vào self.cookies."""
        cookies_header = self.headers.get('cookie', '') 
        
        if cookies_header:
            for pair in cookies_header.split(';'):
                pair = pair.strip()
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    # Lưu vào CaseInsensitiveDict của cookies
                    self.cookies[key.strip()] = value.strip()
        return

    def extract_request_line(self, request):
        """
        Trích xuất method, path (không có Query String) và version.
        """
        try:
            lines = request.splitlines()
            first_line = lines[0]
            method, path, version = first_line.split()
            
            # --- BỔ SUNG: XỬ LÝ QUERY STRING TRONG PATH ---
            # Tách path thành hai phần tại dấu '?'
            if '?' in path:
                # Chỉ lấy phần path trước dấu '?'
                path = path.split('?', 1)[0] 
            
            # ----------------------------------------------
            
            """bỏ chuyển hướng theo logic chuyển hướng khi authorize"""
        except Exception:
            return None, None, None

        return method, path, version

    def parse_query_params(self, request):
        """
        Phân tích Query String từ HTTP request thô.

        :param request (str): Chuỗi HTTP request thô nhận được qua socket.
        :return: dict - Dictionary chứa các tham số Query String (ví dụ: {'ip': '...', 'port': '...'}).
        """
        try:
            lines = request.splitlines()
            first_line = lines[0] # Ví dụ: GET /chat/?ip=... HTTP/1.1
            
            # Đảm bảo request_line có 3 phần
            if len(first_line.split(' ', 2)) != 3:
                 return {}
                 
            _, full_path, _ = first_line.split(' ', 2)
            
            if '?' not in full_path:
                return {}

            # Tách Query String (phần sau dấu '?')
            query_string = full_path.split('?', 1)[1]
            
            # Sử dụng thư viện chuẩn để phân tích tham số
            params = urllib.parse.parse_qs(query_string)
            
            # Chuyển đổi list (giá trị mặc định của parse_qs) thành string đơn
            result = {k: v[0] for k, v in params.items()}
            
            return result
        
        except Exception as e:
            # print(f"Lỗi khi parse Query String: {e}")
            return {}   

    def prepare_headers(self, request):
        """Prepares the given HTTP headers."""
        lines = request.split('\r\n')
        headers = CaseInsensitiveDict()
        for line in lines[1:]:
            if ': ' in line:
                key, val = line.split(': ', 1)
                headers[key] = val
        return headers

    def prepare(self, request, routes=None):
        """Prepares the entire request with the given parameters."""

        # 1. PHÂN TÍCH REQUEST LINE VÀ QUERY PARAMS
        self.method, self.path, self.version = self.extract_request_line(request)
        self.params = self.parse_query_params(request) # 🎯 Mới: Lấy tham số
        
        if self.method is None:
            # Yêu cầu không hợp lệ
            return
            
        print("[Request] {} path {} version {}".format(self.method, self.path, self.version))

        self.url = self.path.split("/")[-1]

        # 2. XỬ LÝ ROUTES VÀ HOOKS
        if routes: # Sửa từ `if not routes == {}:`
            self.routes = routes
            # Ví dụ: path /chat/ sẽ trả về /chat
            main_route = f"/{self.path.strip('/')}" 
            self.hook = routes.get((self.method, main_route))
        
        # 3. PHÂN TÍCH BODY
        head, raw_body_str = request.split('\r\n\r\n', 1)
        raw_body_bytes = raw_body_str.encode('utf-8')

        self.body = raw_body_bytes

        # 4. PHÂN TÍCH HEADERS VÀ COOKIES
        self.headers = self.prepare_headers(request)
        # 🎯 Sửa: Thay vì nhận cookies từ tham số, ta gọi hàm nội bộ
        self.cookies = self.headers.get("cookie") 
        return

    # Các hàm còn lại giữ nguyên, chỉ chỉnh sửa để dùng thuộc tính (self.body)
    def prepare_body(self, data, files, json=None):
        self.prepare_content_length(self.body)
        #
        # TODO prepare the request authentication
        #
        return

    def prepare_content_length(self, body):
        self.headers["Content-Length"] = len(body)
        #
        # TODO prepare the request authentication
        #
        return

    def prepare_auth(self, auth, url=""):
        #
        # TODO prepare the request authentication
        #
        self.auth = auth
        self.url = url
        return

    def prepare_cookies(self, cookies):
        # Hàm này không nên được gọi từ bên ngoài để parse cookies, 
        # nhưng nếu nó dùng để SET cookie cho phản hồi thì cần được giữ lại.
        self.headers["cookie"] = cookies
        self.cookies = cookies