#!/usr/bin/env python3
"""Local browser GUI for the packet analyzer. Run: python3 app.py"""
import argparse
import collections
import http.server
import json
import socket
import struct
import sys
import threading
import time
import urllib.parse
import webbrowser
from pathlib import Path

from analyzer import Analyzer
from capture import open_capture
from runtime import require_ubuntu
from external import SMTP_PUBLIC_HOST, SMTP_PUBLIC_PORT, default_interface, dns_experiment, http_experiment, smtp_experiment


class LabState:
    def __init__(self):
        self.lock = threading.Lock()
        self.control = threading.Lock()
        self.packets = collections.deque(maxlen=1500)
        self.next_id = 1
        self.thread = None
        self.stop_event = threading.Event()
        self.error = ''
        self.backend_name = ''
        self.interface = ''
        self.linktype = 1
        self.running = False
        self.ignored = 0
        self.decode_errors = 0
        self.test_running = False
        self.test_result = []

    def stop(self):
        with self.control:
            self._stop()

    def _stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3)
            if self.thread.is_alive():
                raise RuntimeError('캡처 중지를 기다리는 중입니다. 다시 시도하세요.')
        self.thread = None

    def start(self, interface):
        with self.control:
            self._stop()
            backend = open_capture(interface)
            local_ip = None
            self.stop_event = threading.Event()
            event = self.stop_event
            with self.lock:
                self.packets.clear()
                self.error = ''
                self.decode_errors = self.ignored = 0
                self.interface = interface
                self.linktype = backend.linktype
                self.backend_name = backend.name
                self.running = True
            self.thread = threading.Thread(target=self._capture,args=(backend,event,local_ip),daemon=True)
            self.thread.start()

    def _capture(self, backend, stop_event, local_ip):
        analyzer = Analyzer()
        try:
            while not stop_event.is_set():
                for timestamp, frame, direction in backend.read():
                    try:
                        packet = analyzer.decode(frame,backend.linktype,timestamp,direction,local_ip)
                    except (ValueError,struct.error,IndexError) as exc:
                        with self.lock:
                            self.decode_errors += 1
                        continue
                    if packet is None:
                        with self.lock:
                            self.ignored += 1
                        continue
                    with self.lock:
                        packet['id'] = self.next_id
                        self.next_id += 1
                        self.packets.append((packet,frame))
        except Exception as exc:
            with self.lock:
                self.error = str(exc)
        finally:
            backend.close()
            with self.lock:
                self.running = False

    def snapshot(self, after=0):
        with self.lock:
            return {'running':self.running,'error':self.error,'backend':self.backend_name,
                    'interface':self.interface,'packets':[p for p,_ in self.packets if p['id'] > after],
                    'stored':len(self.packets),'ignored':self.ignored,'decode_errors':self.decode_errors,
                    'test_running':self.test_running,'test_result':self.test_result,
                    'platform':sys.platform}

    def run_tests(self, settings):
        protocol = settings.get('protocol')
        if protocol not in ('HTTP', 'DNS', 'SMTP'):
            raise ValueError('HTTP, DNS, SMTP 중 하나를 선택하세요.')
        with self.lock:
            if self.test_running:
                raise ValueError('실험 실행 중입니다.')
            if not self.running:
                raise ValueError('캡처를 먼저 시작하세요.')
            if self.interface == 'lo':
                raise ValueError('외부 실험은 인터넷에 연결된 인터페이스를 선택하세요. lo는 내부 통신용입니다.')
            self.test_running = True
            self.test_result = []
        def worker():
            try:
                if protocol == 'HTTP':
                    result = http_experiment(settings.get('url', 'http://example.com/'), settings.get('version', '1.1'))
                elif protocol == 'DNS':
                    result = dns_experiment(settings.get('domain', 'example.com'), settings.get('resolver', '1.1.1.1'), settings.get('type', 'A'))
                else:
                    mode = settings.get('mode', 'probe')
                    if mode not in ('probe', 'public-send'):
                        raise ValueError('화면에서는 연결 확인 또는 공개 테스트 메일 전송을 선택하세요.')
                    result = smtp_experiment(settings.get('host', SMTP_PUBLIC_HOST), int(settings.get('port', SMTP_PUBLIC_PORT)), mode)
                result = [json.dumps(result, ensure_ascii=False, indent=2)]
            except Exception as exc:
                result = ['{} 실험 실패: {}'.format(protocol, exc)]
            with self.lock:
                self.test_result = result
                self.test_running = False
        threading.Thread(target=worker, daemon=True).start()

    def pcap(self):
        with self.lock:
            records = list(self.packets)
            linktype = self.linktype
        data = bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,262144,linktype))
        for packet,frame in records:
            seconds = int(packet['time'])
            microseconds = int((packet['time'] - seconds) * 1e6)
            data.extend(struct.pack('<IIII',seconds,microseconds,len(frame),len(frame)))
            data.extend(frame)
        return bytes(data)


STATE = LabState()


class Handler(http.server.BaseHTTPRequestHandler):
    def valid_host(self):
        return self.headers.get('Host') in ('127.0.0.1:{}'.format(self.server.server_port),
                                          'localhost:{}'.format(self.server.server_port))

    def reply(self, body, content_type='application/json; charset=utf-8', status=200):
        if not isinstance(body,bytes):
            body = json.dumps(body,ensure_ascii=False).encode('utf8')
        self.send_response(status)
        self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.valid_host():
            return self.reply({'error':'허용되지 않은 Host'},status=403)
        path = urllib.parse.urlsplit(self.path)
        try:
            if path.path == '/':
                self.reply(Path(__file__).with_name('ui.html').read_bytes(),'text/html; charset=utf-8')
            elif path.path == '/api/interfaces':
                self.reply({'interfaces':[name for _,name in socket.if_nameindex()],
                            'default':default_interface()})
            elif path.path == '/api/state':
                after = int(urllib.parse.parse_qs(path.query).get('after',['0'])[0])
                self.reply(STATE.snapshot(after))
            elif path.path == '/api/export.pcap':
                self.reply(STATE.pcap(),'application/vnd.tcpdump.pcap')
            else:
                self.reply({'error':'찾을 수 없습니다'},status=404)
        except (ValueError,OSError) as exc:
            self.reply({'error':str(exc)},status=400)

    def do_POST(self):
        if not self.valid_host():
            return self.reply({'error':'허용되지 않은 Host'},status=403)
        origin = self.headers.get('Origin')
        if origin and origin != 'http://' + self.headers.get('Host',''):
            return self.reply({'error':'다른 사이트의 요청은 허용되지 않습니다'},status=403)
        if not self.headers.get('Content-Type','').startswith('application/json'):
            return self.reply({'error':'JSON 요청이 필요합니다'},status=415)
        try:
            size = int(self.headers.get('Content-Length','0'))
            if size < 0 or size > 4096:
                raise ValueError('요청 크기 초과')
            body = json.loads(self.rfile.read(size) or b'{}')
            if self.path == '/api/start':
                STATE.start(body.get('interface',''))
            elif self.path == '/api/stop':
                STATE.stop()
            elif self.path == '/api/test':
                STATE.run_tests(body)
            else:
                return self.reply({'error':'알 수 없는 명령'},status=404)
            self.reply({'ok':True})
        except (OSError,ValueError,RuntimeError,TypeError,AttributeError) as exc:
            self.reply({'error':str(exc)},status=400)

    def log_message(self,*args):
        pass


def main():
    parser = argparse.ArgumentParser(description='HTTP·DNS·SMTP 패킷 분석 GUI')
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--no-browser',action='store_true')
    args = parser.parse_args()
    try:
        require_ubuntu()
    except RuntimeError as exc:
        parser.exit(1, '{}\n'.format(exc))
    server = http.server.ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    url = 'http://127.0.0.1:{}/'.format(server.server_port)
    print('패킷 분석 화면: '+url,flush=True)
    print('종료: Control+C. 캡처는 화면에서 시작합니다.',flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        pass
    finally:
        STATE.stop()
        server.server_close()


if __name__ == '__main__':
    main()
