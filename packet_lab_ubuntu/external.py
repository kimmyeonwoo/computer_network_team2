"""External experiment clients. No local server is started by this module."""
import argparse
import http.client
import ipaddress
import json
import os
import secrets
import smtplib
import socket
import ssl
import struct
import urllib.parse

from analyzer import decode_dns
from runtime import require_ubuntu

TIMEOUT = 8
SMTP_SANDBOX = 'sandbox.smtp.mailtrap.io'
SMTP_PUBLIC_HOST = '146.59.115.14'
SMTP_PUBLIC_PORT = 1125


def default_interface():
    """Ask the routing table for an outbound IPv4 address, without sending a packet."""
    from capture import interface_ip
    names = [name for _, name in socket.if_nameindex()]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(('1.1.1.1', 53))
            address = sock.getsockname()[0]
        for name in names:
            if interface_ip(name) == address:
                return name
    except OSError:
        pass
    return next((name for name in names if name != 'lo'), names[0] if names else '')


def ipv4_connection(host, port, timeout=TIMEOUT, source_address=None):
    """The analyzer supports IPv4, so experiment traffic also uses IPv4."""
    last_error = None
    for family, kind, protocol, _, address in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM):
        sock = socket.socket(family, kind, protocol)
        try:
            sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(address)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise last_error or OSError('IPv4 서버 주소를 찾지 못했습니다.')


class HTTPConnectionIPv4(http.client.HTTPConnection):
    def connect(self):
        self.sock = ipv4_connection(self.host, self.port, self.timeout, self.source_address)


class SMTPIPv4(smtplib.SMTP):
    def _get_socket(self, host, port, timeout):
        return ipv4_connection(host, port, timeout, self.source_address)


def http_experiment(url, version='1.1'):
    target = urllib.parse.urlsplit(url)
    if target.scheme != 'http' or not target.hostname or target.username or target.password:
        raise ValueError('평문 HTTP 주소를 입력하세요. 예: http://example.com/')
    if version not in ('1.0', '1.1'):
        raise ValueError('HTTP 버전은 1.0 또는 1.1을 선택하세요.')
    port = target.port or 80
    if port not in (80, 8080):
        raise ValueError('현재 HTTP 분석 포트는 80 또는 8080입니다.')
    path = urllib.parse.urlunsplit(('', '', target.path or '/', target.query, ''))
    connection = HTTPConnectionIPv4(target.hostname, port, timeout=TIMEOUT)
    # http.client exposes no public request-version selector.
    connection._http_vsn = 10 if version == '1.0' else 11
    connection._http_vsn_str = 'HTTP/' + version
    try:
        connection.request('GET', path, headers={'Host': target.netloc,
                           'User-Agent': 'PacketLab/1.0', 'Connection': 'close'})
        server_ip = connection.sock.getpeername()[0]
        response = connection.getresponse()
        headers = dict(response.getheaders())
        response.read(65536)
        return {'protocol': 'HTTP', 'target': url, 'server': str(server_ip),
                'request': 'GET {} HTTP/{}'.format(path, version),
                'response': 'HTTP/{} {} {}'.format({10:'1.0',11:'1.1'}.get(response.version,str(response.version)),response.status,response.reason),
                'headers': headers,
                'note': '리다이렉트는 자동 추적하지 않습니다. 1.1도 테스트에서는 Connection: close로 종료합니다.'}
    finally:
        connection.close()


def dns_experiment(domain, resolver='1.1.1.1', record_type='A'):
    address = str(ipaddress.IPv4Address(resolver))
    if record_type not in ('A','AAAA','MX'):
        raise ValueError('DNS 유형은 A, AAAA, MX 중에서 선택하세요.')
    encoded = domain.rstrip('.').encode('idna')
    labels = encoded.split(b'.')
    if not encoded or len(encoded) > 253 or any(not label or len(label) > 63 for label in labels):
        raise ValueError('유효한 도메인 이름을 입력하세요.')
    question = b''.join(bytes([len(label)])+label for label in labels) + b'\x00'
    question += struct.pack('!HH', {'A':1,'AAAA':28,'MX':15}[record_type],1)
    ident = secrets.randbelow(65536)
    query = struct.pack('!6H',ident,0x100,1,0,0,0) + question
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        client.settimeout(TIMEOUT)
        client.connect((address,53))
        client.send(query)
        response = client.recv(65535)
    result = decode_dns(response)
    expected_name = encoded.decode('ascii').lower()
    expected_question = result['questions'][0] if result['questions'] else {}
    if result['transaction_id'] != hex(ident) or result['kind'] != '응답' or expected_question.get('name','').lower() != expected_name or expected_question.get('type') != record_type:
        raise ValueError('DNS 응답이 보낸 질의와 일치하지 않습니다.')
    return {'protocol':'DNS','target':address+':53','result':result,
            'note':'실제 DNS 응답입니다. truncated가 true면 UDP 응답이 잘린 상태입니다.'}


def smtp_experiment(host=None, port=None, mode='probe'):
    if mode not in ('probe', 'public-send', 'tls-send', 'plain-cram-send'):
        raise ValueError('잘못된 SMTP 실험 모드')
    account_mode = mode in ('tls-send', 'plain-cram-send')
    host = host or (SMTP_SANDBOX if account_mode else SMTP_PUBLIC_HOST)
    port = port if port is not None else (2525 if account_mode else SMTP_PUBLIC_PORT)
    if port not in (25, 2525, 587, 1125):
        raise ValueError('SMTP 포트는 25, 2525, 587, 1125를 지원합니다.')
    if account_mode and host != SMTP_SANDBOX:
        raise ValueError('계정 인증 전송은 Mailtrap Sandbox 호스트만 지원합니다.')
    if mode == 'public-send' and (host != SMTP_PUBLIC_HOST or port != SMTP_PUBLIC_PORT):
        raise ValueError('공개 테스트 메일은 MailMock의 146.59.115.14:1125로만 보냅니다.')
    username, password = '', ''
    if account_mode:
        username = os.environ.get('MAILTRAP_USERNAME', '')
        password = os.environ.get('MAILTRAP_PASSWORD', '')
        if not username or not password:
            raise ValueError('MAILTRAP_USERNAME과 MAILTRAP_PASSWORD 환경 변수를 먼저 설정하세요.')

    transcript = []
    step = '서버 연결'
    accepted = False
    client = SMTPIPv4(timeout=TIMEOUT, local_hostname='packet-lab.invalid')

    def record(name, response, expected):
        code, reply = response
        transcript.append({'step': name, 'code': code, 'reply': reply.decode('utf8', 'replace')})
        if code not in expected:
            raise smtplib.SMTPResponseException(code, reply)

    notes = {
        'probe': '기본 연결·명령만 확인했습니다. 메일 전송은 실행하지 않았습니다.',
        'public-send': '가짜 주소와 고정된 테스트 본문을 공개 테스트함으로 보냅니다. 전송은 자동 재시도하지 않습니다.',
        'tls-send': 'STARTTLS 이후 메일 명령은 암호화됩니다. 캡처 분석기는 이를 복호화하지 않습니다.',
        'plain-cram-send': '평문 SMTP 실험입니다. 전용 Sandbox 계정만 사용하세요. 인증 교환도 PCAP에 포함될 수 있습니다.'
    }
    result = {'protocol': 'SMTP', 'target': '{}:{}'.format(host, port), 'mode': mode,
              'transcript': transcript, 'note': notes[mode]}
    try:
        step = '서버 인사'
        record(step, client.connect(host, port), (220,))
        step = 'EHLO'
        record(step, client.ehlo(), (250,))
        if mode == 'probe':
            step = 'NOOP'
            record(step, client.noop(), (250,))
        else:
            if mode == 'tls-send':
                step = 'STARTTLS'
                record(step, client.starttls(context=ssl.create_default_context()), (220,))
                step = 'TLS 이후 EHLO'
                record(step, client.ehlo(), (250,))
                step = 'SMTP 인증'
                record(step, client.login(username, password), (235, 503))
            elif mode == 'plain-cram-send':
                mechanisms = client.esmtp_features.get('auth', '').upper().split()
                if 'CRAM-MD5' not in mechanisms:
                    raise ValueError('서버가 CRAM-MD5를 제공하지 않아 전송을 중단했습니다.')
                client.user, client.password = username, password
                step = 'CRAM-MD5 인증'
                record(step, client.auth('CRAM-MD5', client.auth_cram_md5), (235,))
            step = 'MAIL FROM'
            record(step, client.mail('sender@example.test'), (250,))
            step = 'RCPT TO'
            record(step, client.rcpt('receiver@example.test'), (250, 251))
            step = 'DATA / 본문 전송'
            body = 'From: sender@example.test\r\nTo: receiver@example.test\r\nSubject: Packet Lab SMTP test\r\n\r\nSMTP packet capture test.\r\n'
            record(step, client.data(body), (250,))
            accepted = True
        step = 'QUIT'
        record(step, client.quit(), (221,))
        result['success'] = True
    except (OSError, ValueError, smtplib.SMTPException) as exc:
        result.update(success=False, failed_step=step,
                      error=str(exc))
        if isinstance(exc, smtplib.SMTPResponseException):
            code, reply = exc.smtp_code, exc.smtp_error.decode('utf8', 'replace')
            if not transcript or transcript[-1]['step'] != step or transcript[-1]['code'] != code:
                transcript.append({'step': step, 'code': code, 'reply': reply})
            result['smtp_code'] = code
            result['server_reply'] = reply
            if 400 <= code < 500:
                result['error_hint'] = '서버가 일시적 실패를 반환했습니다. 실패 단계와 서버 문구를 확인하세요. 자동 재전송은 하지 않습니다.'
    finally:
        client.close()
    result['mail_accepted'] = accepted
    return result


def main():
    parser = argparse.ArgumentParser(description='외부 HTTP/DNS/SMTP 실험 요청')
    sub = parser.add_subparsers(dest='protocol',required=True)
    http_parser = sub.add_parser('http')
    http_parser.add_argument('--url',default='http://example.com/')
    http_parser.add_argument('--version',choices=['1.0','1.1'],default='1.1')
    dns = sub.add_parser('dns')
    dns.add_argument('--domain',default='example.com')
    dns.add_argument('--resolver',default='1.1.1.1')
    dns.add_argument('--type',choices=['A','AAAA','MX'],default='A')
    smtp = sub.add_parser('smtp')
    smtp.add_argument('--host')
    smtp.add_argument('--port',type=int)
    smtp.add_argument('--mode',choices=['probe','public-send','tls-send','plain-cram-send'],default='probe')
    args = parser.parse_args()
    try:
        require_ubuntu()
    except RuntimeError as exc:
        parser.exit(1, '{}\n'.format(exc))
    try:
        if args.protocol == 'http':
            result = http_experiment(args.url,args.version)
        elif args.protocol == 'dns':
            result = dns_experiment(args.domain,args.resolver,args.type)
        else:
            result = smtp_experiment(args.host,args.port,args.mode)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        if result.get('success') is False:
            parser.exit(1)
    except (OSError, ValueError, http.client.HTTPException, smtplib.SMTPException) as exc:
        parser.exit(1,'실험 실패: {}\n'.format(exc))


if __name__ == '__main__':
    main()
