"""IPv4 packet decoding and bounded TCP stream reconstruction. Standard library only."""
import collections
import ipaddress
import re
import socket
import struct
import time

MAX_STREAM = 262144


def dns_name(data, offset):
    labels, visited = [], set()
    end = None
    for _ in range(128):
        if offset >= len(data) or offset in visited:
            raise ValueError('잘못된 DNS 이름 또는 압축 포인터')
        visited.add(offset)
        size = data[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError('잘린 DNS 포인터')
            if end is None:
                end = offset + 2
            offset = ((size & 63) << 8) | data[offset + 1]
            continue
        if size & 0xC0:
            raise ValueError('지원하지 않는 DNS 라벨')
        offset += 1
        if size == 0:
            return '.'.join(labels) or '.', end if end is not None else offset
        if offset + size > len(data):
            raise ValueError('잘린 DNS 이름')
        labels.append(data[offset:offset + size].decode('ascii', 'replace'))
        offset += size
    raise ValueError('DNS 이름이 너무 깁니다')


DNS_TYPES = {1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX', 2: 'NS', 12: 'PTR', 16: 'TXT', 6: 'SOA'}


def decode_dns(data):
    if len(data) < 12:
        raise ValueError('잘린 DNS 헤더')
    ident, flags, qd, an, ns, ar = struct.unpack('!6H', data[:12])
    if qd + an + ns + ar > 512:
        raise ValueError('DNS 레코드 수 제한 초과')
    result = {'transaction_id': hex(ident), 'kind': '응답' if flags & 0x8000 else '질의',
              'response_code': {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED'}.get(flags & 15, str(flags & 15)),
              'truncated': bool(flags & 0x200), 'questions': [], 'records': []}
    offset = 12
    for _ in range(qd):
        name, offset = dns_name(data, offset)
        typ, cls = struct.unpack_from('!HH', data, offset)
        offset += 4
        result['questions'].append({'name': name, 'type': DNS_TYPES.get(typ, str(typ)), 'class': cls})
    for section, count in [('answer', an), ('authority', ns), ('additional', ar)]:
        for _ in range(count):
            name, offset = dns_name(data, offset)
            typ, cls, ttl, size = struct.unpack_from('!HHIH', data, offset)
            offset += 10
            end = offset + size
            if end > len(data):
                raise ValueError('잘린 DNS 레코드')
            raw = data[offset:end]
            value = raw.hex()
            if typ in (1, 28) and size == (4 if typ == 1 else 16):
                value = str(ipaddress.ip_address(raw))
            elif typ in (2, 5, 12):
                value, _ = dns_name(data, offset)
            elif typ == 15 and size >= 3:
                host, _ = dns_name(data, offset + 2)
                value = '{} {}'.format(struct.unpack('!H', raw[:2])[0], host)
            elif typ == 16:
                chunks, pos = [], 0
                while pos < len(raw):
                    length = raw[pos]
                    pos += 1
                    if pos + length > len(raw):
                        raise ValueError('잘린 TXT 레코드')
                    chunks.append(raw[pos:pos + length].decode('utf8', 'replace'))
                    pos += length
                value = ' '.join(chunks)
            result['records'].append({'section': section, 'name': name, 'type': DNS_TYPES.get(typ, str(typ)),
                                      'class': cls, 'ttl': ttl, 'value': value})
            offset = end
    return result


class TCPStream:
    def __init__(self, start):
        self.next_seq = start
        self.pending = []
        self.buffer = bytearray()
        self.remaining_body = 0
        self.chunked = False
        self.smtp_data = False
        self.disabled = False
        self.received = 0

    def feed(self, seq, payload):
        if self.disabled or not payload:
            return b''
        delta = (seq - self.next_seq + 2**31) % 2**32 - 2**31
        if delta < 0:
            payload = payload[-delta:]
            seq = self.next_seq
            delta = 0
        if not payload:
            return b''
        if delta > MAX_STREAM or self.received + len(payload) > MAX_STREAM:
            self.disabled = True
            return b''
        if any(s == seq and d == payload for s, d in self.pending):
            return b''
        self.received += len(payload)
        self.pending.append((seq, payload))
        output = bytearray()
        while self.pending:
            self.pending.sort(key=lambda x: (x[0] - self.next_seq + 2**31) % 2**32 - 2**31)
            first_seq, part = self.pending[0]
            gap = (first_seq - self.next_seq + 2**31) % 2**32 - 2**31
            if gap > 0:
                break
            self.pending.pop(0)
            part = part[-gap:] if gap < 0 else part
            output.extend(part)
            self.next_seq = (self.next_seq + len(part)) % 2**32
        return bytes(output)

    def messages(self, protocol, new_data):
        self.buffer.extend(new_data)
        results = []
        if protocol == 'DNS':
            while len(self.buffer) >= 2:
                size = struct.unpack('!H', self.buffer[:2])[0]
                if len(self.buffer) < 2 + size:
                    break
                results.append(decode_dns(bytes(self.buffer[2:2 + size])))
                del self.buffer[:2 + size]
            return results
        if protocol == 'SMTP':
            while b'\r\n' in self.buffer:
                line, _, rest = self.buffer.partition(b'\r\n')
                self.buffer = bytearray(rest)
                if self.smtp_data:
                    if line == b'.':
                        self.smtp_data = False
                        results.append({'smtp': '메일 DATA 전송 종료'})
                    continue
                decoded = line.decode('utf8', 'replace')
                if re.match(r'^(EHLO|HELO|MAIL FROM:|RCPT TO:|DATA|QUIT|RSET|NOOP|STARTTLS|AUTH|[0-9]{3}[ -])', decoded, re.I):
                    results.append({'smtp': decoded})
                if line.upper() == b'DATA':
                    self.smtp_data = True
            return results
        while self.buffer:
            if self.remaining_body:
                length = min(len(self.buffer), self.remaining_body)
                del self.buffer[:length]
                self.remaining_body -= length
                if self.remaining_body:
                    break
            if self.chunked:
                # Parse complete chunked bodies before interpreting another header.
                pos = 0
                while True:
                    end = self.buffer.find(b'\r\n', pos)
                    if end < 0:
                        return results
                    size = int(self.buffer[pos:end].split(b';')[0], 16)
                    if size == 0:
                        if self.buffer[end + 2:end + 4] == b'\r\n':
                            pos = end + 4
                        else:
                            trailer_end = self.buffer.find(b'\r\n\r\n', end + 2)
                            if trailer_end < 0:
                                return results
                            pos = trailer_end + 4
                        del self.buffer[:pos]
                        self.chunked = False
                        break
                    if len(self.buffer) < end + 2 + size + 2:
                        return results
                    if self.buffer[end + 2 + size:end + 4 + size] != b'\r\n':
                        raise ValueError('잘못된 HTTP chunk')
                    pos = end + 4 + size
            boundary = self.buffer.find(b'\r\n\r\n')
            if boundary < 0:
                break
            header = bytes(self.buffer[:boundary]).decode('iso8859-1')
            del self.buffer[:boundary + 4]
            lines = header.split('\r\n')
            if not re.match(r'^(HTTP/1\.[01] |[A-Z]+ \S+ HTTP/1\.[01]$)', lines[0]):
                self.disabled = True
                self.buffer.clear()
                break
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.lower()] = value.strip()
            message = {'start_line': lines[0], 'headers': headers}
            parts = lines[0].split(' ', 2)
            if lines[0].startswith('HTTP/'):
                message.update(version=parts[0], status_code=int(parts[1]))
            else:
                message.update(method=parts[0], path=parts[1], version=parts[2])
            results.append(message)
            self.chunked = 'chunked' in headers.get('transfer-encoding', '').lower()
            self.remaining_body = max(0, int(headers.get('content-length', '0')))
            if self.chunked:
                self.remaining_body = 0
            elif lines[0].startswith('HTTP/') and 'content-length' not in headers:
                code = int(lines[0].split()[1])
                if code >= 200 and code not in (204, 304):
                    self.disabled = True  # Body delimited by connection close.
                    self.buffer.clear()
                    break
        return results


class Analyzer:
    def __init__(self):
        self.streams = collections.OrderedDict()
        self.tls_connections = collections.OrderedDict()

    def decode(self, frame, linktype, timestamp=None, direction='미확인', local_ip=None):
        offset = 0
        if linktype == 1:
            if len(frame) < 14:
                return None
            ether_type = struct.unpack_from('!H', frame, 12)[0]
            offset = 14
            while ether_type in (0x8100, 0x88a8):
                ether_type = struct.unpack_from('!H', frame, offset + 2)[0]
                offset += 4
            if ether_type != 0x0800:
                return None
        elif linktype in (0, 108):
            if len(frame) < 4:
                return None
            family = struct.unpack('<I' if linktype == 0 else '!I', frame[:4])[0]
            if family != socket.AF_INET:
                return None
            offset = 4
        elif linktype in (12, 101):
            offset = 0
        else:
            raise ValueError('지원하지 않는 링크 유형: {}'.format(linktype))
        ip = frame[offset:]
        if len(ip) < 20 or ip[0] >> 4 != 4:
            return None
        ihl = (ip[0] & 15) * 4
        total = struct.unpack_from('!H', ip, 2)[0]
        if ihl < 20 or total < ihl or len(ip) < total:
            raise ValueError('잘리거나 잘못된 IPv4 패킷')
        src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        if local_ip:
            if src == local_ip and dst == local_ip:
                direction = '로컬 왕복'
            elif src == local_ip:
                direction = '송신'
            elif dst == local_ip:
                direction = '수신'
            else:
                direction = '기타'
        packet = {'time': timestamp if timestamp is not None else time.time(), 'direction': direction,
                  'src': src, 'dst': dst, 'ttl': ip[8], 'ip_header_length': ihl, 'ip_length': total,
                  'length': len(frame), 'protocol': 'IPv4', 'transport': '', 'sport': '', 'dport': '',
                  'seq': None, 'ack': None, 'flags': '', 'messages': [], 'summary': '', 'notes': []}
        if struct.unpack_from('!H', ip, 6)[0] & 0x3fff:
            packet['notes'].append('IPv4 분할 패킷: IP 재조립은 지원 범위 밖입니다.')
            return packet
        segment = ip[ihl:total]
        if ip[9] not in (6, 17):
            return None
        minimum = 20 if ip[9] == 6 else 8
        if len(segment) < minimum:
            raise ValueError('잘린 전송 계층 헤더')
        sport, dport = struct.unpack_from('!HH', segment)
        packet.update(sport=sport, dport=dport, transport='TCP' if ip[9] == 6 else 'UDP')
        ports = {sport, dport}
        protocol = 'DNS' if ports & {53, 1053} else 'HTTP' if ip[9] == 6 and ports & {80, 8080} else 'SMTP' if ip[9] == 6 and ports & {25, 2525, 587, 1125} else None
        if not protocol:
            return None
        packet['protocol'] = protocol
        if ip[9] == 17:
            udp_len = struct.unpack_from('!H', segment, 4)[0]
            if udp_len < 8 or udp_len > len(segment):
                raise ValueError('잘린 UDP 데이터')
            payload = segment[8:udp_len]
            if protocol == 'DNS':
                packet['messages'] = [decode_dns(payload)]
        else:
            seq, ack = struct.unpack_from('!II', segment, 4)
            header_len = (segment[12] >> 4) * 4
            if header_len < 20 or header_len > len(segment):
                raise ValueError('잘못된 TCP 헤더 길이')
            flags = segment[13]
            packet['connection_stage'] = '연결 중단 (RST)' if flags & 4 else '전송 종료 요청 (FIN)' if flags & 1 else '연결 응답 (SYN+ACK)' if flags & 2 and flags & 16 else '연결 시작 (SYN)' if flags & 2 else '데이터 전송' if len(segment) > header_len else '확인 응답 / 제어'
            packet.update(seq=seq, ack=ack if flags & 16 else None,
                          flags=' '.join(name for bit, name in [(1,'FIN'),(2,'SYN'),(4,'RST'),(8,'PSH'),(16,'ACK'),(32,'URG'),(64,'ECE'),(128,'CWR')] if flags & bit))
            payload = segment[header_len:]
            key = (src, sport, dst, dport)
            reverse = (dst, dport, src, sport)
            connection = tuple(sorted(((src, sport), (dst, dport))))
            if flags & 2 and not flags & 16:
                self.streams.pop(key, None)
                self.streams.pop(reverse, None)
                self.tls_connections.pop(connection, None)
            stream = self.streams.get(key)
            if stream is None:
                stream = TCPStream((seq + bool(flags & 2)) % 2**32)
                self.streams[key] = stream
                if not flags & 2:
                    packet['notes'].append('연결 중간부터 캡처: 첫 관측 데이터부터 재조립합니다.')
            self.streams.move_to_end(key)
            while len(self.streams) > 256:
                self.streams.popitem(last=False)
            tls_state = self.tls_connections.get(connection)
            if protocol == 'SMTP' and tls_state == 'encrypted':
                packet['notes'].append('STARTTLS 이후 암호화된 SMTP입니다. TCP 헤더만 분석합니다.')
                packet['tls'] = True
            else:
                contiguous = stream.feed((seq + bool(flags & 2)) % 2**32, payload)
                packet['messages'] = stream.messages(protocol, contiguous) if not stream.disabled else []
                if protocol == 'SMTP':
                    for message in packet['messages']:
                        line = message.get('smtp', '')
                        if line.upper() == 'STARTTLS':
                            self.tls_connections[connection] = ('pending', (src, sport))
                        elif line.startswith('220') and isinstance(tls_state, tuple) and (src, sport) != tls_state[1]:
                            self.tls_connections[connection] = 'encrypted'
                            packet['notes'].append('STARTTLS 승인. 이후 응용 데이터는 암호화됩니다.')
                            stream.buffer.clear()
                    while len(self.tls_connections) > 256:
                        self.tls_connections.popitem(last=False)
            if stream.disabled:
                packet['notes'].append('스트림 분석 종료 또는 256 KiB 제한. 개별 헤더는 계속 표시합니다.')
            if flags & 4:
                self.streams.pop(key, None)
                self.streams.pop(reverse, None)
                self.tls_connections.pop(connection, None)
        packet['payload_preview'] = payload[:2048].decode('utf8', 'replace')
        packet['hex'] = frame[:4096].hex(' ')
        packet['summary'] = packet['flags']
        if packet['messages']:
            message = packet['messages'][-1]
            if protocol == 'DNS':
                question = message['questions'][0] if message['questions'] else {}
                packet['summary'] = '{} {} {} {}'.format(message['kind'], question.get('name',''), question.get('type',''), message['response_code'])
            else:
                packet['summary'] = message.get('start_line', message.get('smtp',''))
        return packet
