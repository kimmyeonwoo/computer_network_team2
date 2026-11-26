"""Regression checks for header parsing, DNS compression and TCP reconstruction.
Run with python3 verify.py. No packet capture privileges are required.
"""
import socket
import struct
import unittest
from unittest import mock

import external

from analyzer import Analyzer, TCPStream, decode_dns
from traffic import dns_test_response


def frame(payload, src='10.0.0.1', dst='10.0.0.2', sport=51000, dport=80,
          seq=1001, ack=9001, flags=0x18, udp=False, ip_options=b''):
    if udp:
        transport = struct.pack('!4H',sport,dport,len(payload)+8,0) + payload
    else:
        transport = struct.pack('!HHIIBBHHH',sport,dport,seq,ack,0x50,flags,4096,0,0) + payload
    ihl = 20 + len(ip_options)
    ip = struct.pack('!BBHHHBBH4s4s',0x40+ihl//4,0,ihl+len(transport),123,0,64,17 if udp else 6,0,
                     socket.inet_aton(src),socket.inet_aton(dst)) + ip_options
    return bytes(12) + b'\x08\x00' + ip + transport


class PacketTests(unittest.TestCase):
    def test_tcp_headers_with_ipv4_options(self):
        packet = Analyzer().decode(frame(b'GET / HTTP/1.1\r\nHost: lab.test\r\n\r\n',ip_options=bytes(4)),1)
        self.assertEqual((packet['ttl'],packet['seq'],packet['ack']),(64,1001,9001))
        self.assertEqual(packet['messages'][0]['start_line'],'GET / HTTP/1.1')
        self.assertEqual(packet['ip_header_length'],24)

    def test_ack_flag_validity(self):
        packet=Analyzer().decode(frame(b'',flags=2),1)
        self.assertIsNone(packet['ack'])
        self.assertEqual(packet['flags'],'SYN')

    def test_reassembly_out_of_order_and_retransmission(self):
        analyzer=Analyzer()
        analyzer.decode(frame(b'',seq=100,flags=2),1)
        self.assertEqual(analyzer.decode(frame(b'HTTP/1.1\r\nHost: lab\r\n\r\n',seq=107),1)['messages'],[])
        result=analyzer.decode(frame(b'GET / ',seq=101),1)
        self.assertEqual(result['messages'][0]['start_line'],'GET / HTTP/1.1')
        repeated=analyzer.decode(frame(b'GET / ',seq=101),1)
        self.assertEqual(repeated['messages'],[])

    def test_sequence_wrap(self):
        stream=TCPStream(0xfffffffe)
        self.assertEqual(stream.feed(0xfffffffe,b'abcd'),b'abcd')
        self.assertEqual(stream.feed(2,b'ef'),b'ef')

    def test_http_body_and_second_response(self):
        stream=TCPStream(1)
        payload=b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbodyHTTP/1.1 204 No Content\r\n\r\n'
        messages=stream.messages('HTTP',payload)
        self.assertEqual(len(messages),2)

    def test_chunked_response(self):
        stream=TCPStream(1)
        first=b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbo'
        self.assertEqual(len(stream.messages('HTTP',first)),1)
        second=b'dy\r\n0\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n'
        self.assertEqual(len(stream.messages('HTTP',second)),1)

    def test_dns_compression_and_answer(self):
        question=b'\x03lab\x04test\x00\x00\x01\x00\x01'
        payload=struct.pack('!6H',0x1234,0x8180,1,1,0,0)+question
        payload+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton('192.0.2.10')
        packet=Analyzer().decode(frame(payload,sport=1053,dport=50000,udp=True),1)
        self.assertEqual(packet['messages'][0]['records'][0]['value'],'192.0.2.10')
        self.assertEqual(packet['messages'][0]['questions'][0]['name'],'lab.test')

    def test_dns_query_with_edns(self):
        question = b'\x03lab\x04test\x00\x00\x01\x00\x01'
        opt = b'\x00' + struct.pack('!HHIH', 41, 1232, 0, 0)
        query = struct.pack('!6H', 0x1234, 0x100, 1, 0, 0, 1) + question + opt
        result = decode_dns(dns_test_response(query))
        self.assertEqual(result['records'][0]['value'], '192.0.2.10')
        self.assertEqual(result['response_code'], 'NOERROR')

    def test_dns_pointer_cycle(self):
        with self.assertRaises(ValueError):
            decode_dns(struct.pack('!6H',1,0,1,0,0,0)+b'\xc0\x0c\x00\x01\x00\x01')

    def test_smtp_split_lines_and_data(self):
        stream=TCPStream(1)
        self.assertEqual(stream.messages('SMTP',b'MAIL FR'),[])
        messages=stream.messages('SMTP',b'OM:<a@lab.test>\r\nDATA\r\nmail body\r\n.\r\nQUIT\r\n')
        self.assertEqual(len(messages),4)
        self.assertEqual(messages[-1]['smtp'],'QUIT')

    def test_null_loopback_link(self):
        ethernet=frame(b'GET / HTTP/1.0\r\n\r\n')
        packet=Analyzer().decode(struct.pack('<I',socket.AF_INET)+ethernet[14:],0,local_ip='10.0.0.1')
        self.assertEqual(packet['direction'],'송신')

    def test_http_version_fields(self):
        for version in ('1.0', '1.1'):
            packet = Analyzer().decode(frame(('GET /test HTTP/' + version + '\r\nHost: example.com\r\n\r\n').encode()), 1)
            message = packet['messages'][0]
            self.assertEqual(message['version'], 'HTTP/' + version)
            self.assertEqual(message['method'], 'GET')
            self.assertEqual(message['path'], '/test')

    def test_starttls_disables_plaintext_parsing_both_directions(self):
        analyzer = Analyzer()
        analyzer.decode(frame(b'', seq=100, flags=2, dport=587), 1)
        command = b'STARTTLS\r\n'
        analyzer.decode(frame(command, seq=101, dport=587), 1)
        reply = analyzer.decode(frame(b'220 Ready\r\n', src='10.0.0.2', dst='10.0.0.1',
                                      sport=587, dport=51000, seq=9001), 1)
        self.assertTrue(any('STARTTLS' in note for note in reply['notes']))
        encrypted = analyzer.decode(frame(b'\x16\x03\x01encrypted', seq=101+len(command), dport=587), 1)
        self.assertTrue(encrypted['tls'])
        self.assertEqual(encrypted['messages'], [])

    def test_tcp_stage(self):
        packet = Analyzer().decode(frame(b'', flags=1 | 16), 1)
        self.assertEqual(packet['connection_stage'], '전송 종료 요청 (FIN)')

    def test_external_http_request_versions_and_response(self):
        for version in ('1.0', '1.1'):
            with mock.patch('external.HTTPConnectionIPv4') as factory:
                connection = factory.return_value
                connection.sock.getpeername.return_value = ('192.0.2.1', 80)
                response = connection.getresponse.return_value
                response.status, response.reason, response.version = 200, 'OK', 11
                response.getheaders.return_value = [('Content-Type', 'text/html')]
                result = external.http_experiment('http://example.com/test', version)
                self.assertIn('HTTP/' + version, result['request'])
                self.assertEqual(result['server'], '192.0.2.1')
                self.assertEqual(connection._http_vsn_str, 'HTTP/' + version)
                connection.close.assert_called_once()

    def test_external_http_rejects_https(self):
        with self.assertRaises(ValueError):
            external.http_experiment('https://example.com/')

    def test_smtp_probe_does_not_send_or_authenticate(self):
        with mock.patch('external.SMTPIPv4') as factory:
            client = factory.return_value
            client.connect.return_value = (220, b'ready')
            client.ehlo.return_value = (250, b'localhost')
            client.noop.return_value = (250, b'OK')
            client.quit.return_value = (221, b'bye')
            result = external.smtp_experiment()
            self.assertEqual(result['mode'], 'probe')
            client.sendmail.assert_not_called()
            client.mail.assert_not_called()
            client.rcpt.assert_not_called()
            client.data.assert_not_called()
            client.login.assert_not_called()
            client.auth.assert_not_called()
            client.close.assert_called_once()

    def test_smtp_send_requires_sandbox_credentials(self):
        with mock.patch.dict('os.environ', {}, clear=True):
            with self.assertRaises(ValueError):
                external.smtp_experiment(mode='plain-cram-send')
        with self.assertRaises(ValueError):
            external.smtp_experiment('smtp.other.test', mode='tls-send')

    def test_public_send_and_acceptance(self):
        with mock.patch('external.SMTPIPv4') as factory:
            client = factory.return_value
            client.connect.return_value = (220, b'ready')
            client.ehlo.return_value = (250, b'hello')
            client.mail.return_value = (250, b'OK')
            client.rcpt.return_value = (250, b'OK')
            client.data.return_value = (250, b'accepted')
            client.quit.return_value = (221, b'bye')
            result = external.smtp_experiment(mode='public-send')
            self.assertTrue(result['success'])
            self.assertTrue(result['mail_accepted'])
            client.connect.assert_called_once_with(external.SMTP_PUBLIC_HOST, 1125)
            client.login.assert_not_called()
            client.data.assert_called_once()

    def test_smtp_451_preserves_step_and_reply(self):
        with mock.patch('external.SMTPIPv4') as factory:
            client = factory.return_value
            client.connect.return_value = (220, b'ready')
            client.ehlo.return_value = (250, b'hello')
            client.mail.return_value = (451, b'Temporary test error')
            result = external.smtp_experiment(mode='public-send')
            self.assertFalse(result['success'])
            self.assertFalse(result['mail_accepted'])
            self.assertEqual(result['failed_step'], 'MAIL FROM')
            self.assertEqual(result['smtp_code'], 451)
            self.assertEqual(result['server_reply'], 'Temporary test error')
            client.mail.assert_called_once()
            client.rcpt.assert_not_called()
            client.data.assert_not_called()

    def test_public_send_target_is_explicit(self):
        with self.assertRaises(ValueError):
            external.smtp_experiment('smtp.other.test', 1125, 'public-send')
        with self.assertRaises(ValueError):
            external.smtp_experiment(external.SMTP_PUBLIC_HOST, 25, 'public-send')

    def test_public_smtp_port_both_directions(self):
        analyzer = Analyzer()
        command = analyzer.decode(frame(b'EHLO packet-lab.invalid\r\n', dport=1125), 1)
        reply = analyzer.decode(frame(b'250 OK\r\n', src='10.0.0.2', dst='10.0.0.1',
                                      sport=1125, dport=51000), 1)
        self.assertEqual(command['protocol'], 'SMTP')
        self.assertEqual(command['messages'][0]['smtp'], 'EHLO packet-lab.invalid')
        self.assertEqual(reply['protocol'], 'SMTP')
        self.assertEqual(reply['messages'][0]['smtp'], '250 OK')

    def test_reject_truncated_frames(self):
        original=frame(b'GET / HTTP/1.0\r\n\r\n')
        with self.assertRaises(ValueError):
            Analyzer().decode(original[:-3],1)


if __name__=='__main__':
    unittest.main()
