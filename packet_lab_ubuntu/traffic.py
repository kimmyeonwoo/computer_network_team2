"""Real loopback test servers. No external mail or DNS requests are sent."""
import http.client
import http.server
import smtplib
import socket
import socketserver
import struct
import threading

from analyzer import dns_name
from runtime import require_ubuntu


class HTTPHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        body = b'Packet Lab HTTP response\n'
        self.send_response(200)
        self.send_header('Content-Type','text/plain')
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Connection','close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, *args):
        pass


class SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        self.wfile.write(b'220 localhost Packet Lab test SMTP\r\n')
        data_mode = False
        for _ in range(200):
            line = self.rfile.readline(8192)
            if not line:
                break
            command = line.upper().strip()
            if data_mode:
                if line == b'.\r\n':
                    data_mode = False
                    self.wfile.write(b'250 Message accepted for local test only\r\n')
                continue
            if command.startswith((b'EHLO', b'HELO')):
                self.wfile.write(b'250 localhost\r\n')
            elif command.startswith((b'MAIL FROM:', b'RCPT TO:')) or command == b'RSET':
                self.wfile.write(b'250 OK\r\n')
            elif command == b'DATA':
                data_mode = True
                self.wfile.write(b'354 End with a dot on its own line\r\n')
            elif command == b'QUIT':
                self.wfile.write(b'221 Bye\r\n')
                break
            else:
                self.wfile.write(b'502 Not implemented\r\n')


def dns_test_response(query):
    if len(query) < 12:
        return None
    ident, flags, qd, _, _, _ = struct.unpack('!6H', query[:12])
    if flags & 0x8000 or qd != 1:
        return None
    try:
        name, end = dns_name(query, 12)
        record_type, record_class = struct.unpack_from('!HH', query, end)
    except (ValueError, struct.error):
        return None
    # Rebuild only the question. dig may append an EDNS OPT additional record.
    labels = [] if name == '.' else name.split('.')
    question = b''.join(bytes([len(label.encode('ascii'))]) + label.encode('ascii') for label in labels)
    question += b'\x00' + struct.pack('!HH', record_type, record_class)
    response_code = 0 if name.lower() == 'lab.test' else 3
    if flags & 0x7800 or record_class != 1:
        response_code = 4
    has_answer = response_code == 0 and record_type == 1
    response_flags = 0x8400 | (flags & 0x0100) | response_code
    response = struct.pack('!6H', ident, response_flags, 1, int(has_answer), 0, 0) + question
    if has_answer:
        response += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('192.0.2.10')
    return response


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        response = dns_test_response(query)
        if response is not None:
            sock.sendto(response, self.client_address)


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class TrafficLab:
    def __init__(self):
        self.servers = []

    def start(self):
        if self.servers:
            return
        specs = [(http.server.ThreadingHTTPServer,8080,HTTPHandler),
                 (UDPServer,1053,DNSHandler),(TCPServer,2525,SMTPHandler)]
        try:
            for server_type, port, handler in specs:
                server = server_type(('127.0.0.1',port), handler)
                self.servers.append(server)
                threading.Thread(target=server.serve_forever,daemon=True).start()
        except Exception:
            self.close()
            raise

    def run(self):
        self.start()
        results = []
        connection = http.client.HTTPConnection('127.0.0.1',8080,timeout=5)
        try:
            connection.request('GET','/index.html',headers={'Connection':'close'})
            response = connection.getresponse()
            response.read()
            results.append('HTTP: 상태 코드 {}'.format(response.status))
        finally:
            connection.close()
        question = b'\x03lab\x04test\x00\x00\x01\x00\x01'
        ident = 0x1234
        query = struct.pack('!6H',ident,0x100,1,0,0,0) + question
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            client.sendto(query,('127.0.0.1',1053))
            response, _ = client.recvfrom(4096)
            if response[:2] != query[:2]:
                raise ValueError('DNS transaction ID 불일치')
            results.append('DNS: lab.test A → 192.0.2.10 (로컬 테스트 응답)')
        with smtplib.SMTP('127.0.0.1',2525,timeout=5) as client:
            client.sendmail('sender@lab.test',['receiver@lab.test'],
                            'Subject: Packet Lab\r\n\r\nLocal SMTP test.\r\n')
        results.append('SMTP: 로컬 테스트 서버 수신 완료 (외부 발송 없음)')
        return results

    def close(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        self.servers.clear()


if __name__ == '__main__':
    try:
        require_ubuntu()
    except RuntimeError as exc:
        raise SystemExit(str(exc))
    lab = TrafficLab()
    try:
        lab.start()
        print('로컬 테스트 서버 준비 완료', flush=True)
        print('HTTP 127.0.0.1:8080 / DNS 127.0.0.1:1053 / SMTP 127.0.0.1:2525', flush=True)
        print('요청은 다른 터미널에서 보내세요. 종료: Control+C', flush=True)
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        print('서버 시작 실패: {}. 기존 로컬 테스트가 실행 중이면 중지한 뒤 다시 실행하세요.'.format(exc), flush=True)
        raise SystemExit(1)
    finally:
        lab.close()
