pip install mitmproxy



mitmproxy --listen-port 8080



mitmdump -s selfaddon.py

<!--手机 http://mitm.it  安装证书 并信任 -->

tshark -i en0 -Y "http" -o "tls.keylog_file:/Users/shemingdong/.mitmproxy/mitmproxy-ca-cert.pem" -f "tcp port 8080" -V


