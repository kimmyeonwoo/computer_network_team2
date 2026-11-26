"""Ubuntu packet capture using AF_PACKET / SOCK_RAW only."""
import socket
import struct
import sys
import time
from runtime import require_ubuntu

if sys.platform.startswith('linux'):
    import fcntl
else:
    fcntl = None

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4


class LinuxCapture:
    name = 'Ubuntu Raw Socket · AF_PACKET / SOCK_RAW'

    def __init__(self, interface):
        require_ubuntu()
        try:
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except PermissionError as exc:
            raise PermissionError('패킷 캡처 권한이 필요합니다. sudo python3 app.py --no-browser로 실행하세요.') from exc
        try:
            self.socket.bind((interface, 0))
            self.socket.settimeout(0.3)
        except Exception:
            self.socket.close()
            raise
        self.linktype = 1

    def read(self):
        try:
            frame, address = self.socket.recvfrom(262144)
        except socket.timeout:
            return []
        direction = '송신' if address[2] == PACKET_OUTGOING else '수신'
        return [(time.time(), frame, direction)]

    def close(self):
        self.socket.close()



def open_capture(interface):
    require_ubuntu()
    if interface not in [name for _, name in socket.if_nameindex()]:
        raise ValueError('존재하지 않는 네트워크 인터페이스')
    return LinuxCapture(interface)


def interface_ip(interface):
    require_ubuntu()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            data = fcntl.ioctl(sock.fileno(), 0x8915, struct.pack('256s', interface.encode()[:15]))
            return socket.inet_ntoa(data[20:24])
        except OSError:
            return None
