import mitmproxy.http
from mitmproxy import http
from mitmproxy import flowfilter

class MyAddon:
    def __init__(self):
        # 初始化 Addon
        self.filter = flowfilter.parse("~u .*")

    def request(self, flow: http.HTTPFlow) -> None:
        # 修改请求头
        # flow.request.headers["X-My-Header"] = "MyCustomValue"
        
        # print(f"Request intercepted and modified: {flow.request.url}")
        pass

    def response(self, flow: http.HTTPFlow) -> None:
        # # 修改响应体
        # if flow.response.status_code == 200:
        #     flow.response.content = b"Modified Response Body"
        #     print("Response modified")
        try:
            # 尝试以字符串形式输出（对于文本内容）
            body = flow.response.content.decode("utf-8")
            print(f"Response Body (Text): {body}")
        except UnicodeDecodeError:
            # 如果响应体无法解码为UTF-8，输出原始字节内容
            print(f"Response Body (Raw Bytes): {flow.response.content}")

addons = [
    MyAddon()
]
