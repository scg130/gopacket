tshark -i en0   -o tls.keylog_file:"/Users/shemingdong/Documents/sshkey.log" -Y "http" -T fields -e http.host -e http.request.uri -e http.file_data


tshark -i en0 -o tls.keylog_file:/Users/shemingdong/Documents/sshkey.log -Y "http.response" -V
