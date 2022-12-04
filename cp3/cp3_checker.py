
from socket import *
import sys,os,time,signal,errno

def handle_timeout(signum, frame):
    raise TimeoutError(os.strerror(errno.ETIME))

if len(sys.argv) < 4:
    sys.stderr.write('Usage: %s <ip> <port> <request>\n' % (sys.argv[0]))
    sys.exit(1)

os.system('tmux new -s checker -d "./liso_server"')
time.sleep(2)

serverHost = gethostbyname(sys.argv[1])
serverPort = int(sys.argv[2])
s = socket(AF_INET, SOCK_STREAM); s.connect((serverHost, serverPort))

request_file = open(sys.argv[3],"rb+")
msg = request_file.read()
request_file.close()

RESPONSE = [
    'HTTP/1.1 200 OK',
    'HTTP/1.1 501 Not Implemented',
    'HTTP/1.1 200 OK',
    'HTTP/1.1 200 OK',
    'HTTP/1.1 505 HTTP Version not supported',
    'HTTP/1.1 200 OK',
    'HTTP/1.1 200 OK',
    'HTTP/1.1 501 Not Implemented',
    'HTTP/1.1 200 OK',
    'HTTP/1.1 505 HTTP Version not supported',
    'HTTP/1.1 200 OK',
    'HTTP/1.1 400 Bad request',
    'HTTP/1.1 200 OK',
    'HTTP/1.1 200 OK',
    'HTTP/1.1 505 HTTP Version not supported',
    'HTTP/1.1 501 Not Implemented',
    'HTTP/1.1 501 Not Implemented',
    'HTTP/1.1 501 Not Implemented',
    'HTTP/1.1 200 OK',
    'HTTP/1.1 505 HTTP Version not supported',
    'HTTP/1.1 200 OK',
    'HTTP/1.1 200 OK',
    'HTTP/1.1 200 OK',
    'HTTP/1.1 200 OK',
    'HTTP/1.1 505 HTTP Version not supported',
    'HTTP/1.1 200 OK',
    'HTTP/1.1 501 Not Implemented',
    'HTTP/1.1 400 Bad request',
    'HTTP/1.1 400 Bad request',
]

def test_week3(requests):
    TIMEOUT=5
    signal.signal(signal.SIGALRM, handle_timeout)
    signal.alarm(TIMEOUT)

    cnt_success = 0
    cnt_recv = 0
    substr = 'HTTP/1.1'
    try:
        buf_size = 2048
        s.send(msg)
        recv_strings = s.recv(buf_size).decode('utf-8', errors='ignore')
        
        while cnt_recv<27:
            recv_string = s.recv(buf_size).decode('utf-8', errors='ignore')
            if not recv_string: recv_string = ""
            else: recv_strings += recv_string
            cnt_recv += recv_string.count(substr)
            # print(cnt_recv)          
    except TimeoutError:
        print("Timeout reached")
        # return 0
    signal.alarm(0)
    # 统计成功数量    
    responses = [res for res in recv_strings.split(substr)]    
    for (i,res) in zip(range(len(responses)),responses):
        responses[i] = substr+res    
    
    for i in range(min(len(responses)-1,len(RESPONSE))):
        if (responses[i+1].lower()).find(RESPONSE[i].lower())<0: 
            # print('response%d error!'%(i+1))
            # print('    recv:\n    %s\n'%responses[i+1])
            # print('    except:\n    %s\n'%RESPONSE[i])
            continue
        cnt_success += 1
    return cnt_success

cnt_request = test_week3(msg)
bound = [i for i in range(19,0,-4)]
scores = 0
for cnt in bound:
    if cnt_request>cnt:
        scores = 5 * (cnt+1)
        break
print("success number: %d"%cnt_request)
s.close()
os.system('tmux kill-session -t checker')
print("{\"scores\": {\"lab3\": %.2f}}"%scores)
