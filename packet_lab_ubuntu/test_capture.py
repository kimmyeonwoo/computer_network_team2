"""Ubuntu guard and raw capture contract checks, using mock sockets."""
import socket
import unittest
from unittest import mock
import app
import capture
import runtime


class CaptureTests(unittest.TestCase):
    def test_ubuntu_environment(self):
        for release in ('ID=ubuntu\n', 'ID="ubuntu"\nVERSION_ID="24.04"\n'):
            with mock.patch.object(runtime.sys, 'platform', 'linux'), mock.patch.object(runtime.Path, 'read_text', return_value=release):
                runtime.require_ubuntu()

    def test_other_os_rejected_before_reading_release(self):
        for platform in ('darwin', 'win32'):
            with mock.patch.object(runtime.sys, 'platform', platform), mock.patch.object(runtime.Path, 'read_text') as read:
                with self.assertRaisesRegex(RuntimeError, 'Ubuntu'):
                    runtime.require_ubuntu()
                read.assert_not_called()

    def test_other_linux_rejected(self):
        with mock.patch.object(runtime.sys, 'platform', 'linux'), mock.patch.object(runtime.Path, 'read_text', return_value='ID=debian\nID_LIKE=ubuntu\n'):
            with self.assertRaises(RuntimeError):
                runtime.require_ubuntu()

    def test_bad_environment_does_not_open_web_port(self):
        with mock.patch('app.require_ubuntu', side_effect=RuntimeError('Ubuntu 전용')), mock.patch('sys.argv', ['app.py', '--no-browser']), mock.patch('app.http.server.ThreadingHTTPServer') as server:
            with self.assertRaises(SystemExit) as error:
                app.main()
            self.assertEqual(error.exception.code, 1)
            server.assert_not_called()

    def test_both_directions_and_timeout(self):
        with mock.patch('capture.require_ubuntu'), mock.patch.object(capture.socket, 'AF_PACKET', 17, create=True), mock.patch('capture.socket.socket') as factory:
            backend = capture.LinuxCapture('enp0s8')
            factory.assert_called_once_with(17, socket.SOCK_RAW, socket.htons(3))
            sock = factory.return_value
            sock.recvfrom.side_effect = [(b'out', ('enp0s8', 0x800, 4, 1, b'')), (b'in', ('enp0s8', 0x800, 0, 1, b'')), socket.timeout()]
            self.assertEqual(backend.read()[0][1:], (b'out', '송신'))
            self.assertEqual(backend.read()[0][1:], (b'in', '수신'))
            self.assertEqual(backend.read(), [])
            backend.close()
            sock.close.assert_called_once()

    def test_bind_failure_closes_socket(self):
        with mock.patch('capture.require_ubuntu'), mock.patch.object(capture.socket, 'AF_PACKET', 17, create=True), mock.patch('capture.socket.socket') as factory:
            factory.return_value.bind.side_effect = OSError('interface unavailable')
            with self.assertRaises(OSError):
                capture.LinuxCapture('bad0')
            factory.return_value.close.assert_called_once()

    def test_permission_error_explains_sudo(self):
        with mock.patch('capture.require_ubuntu'), mock.patch.object(capture.socket, 'AF_PACKET', 17, create=True), mock.patch('capture.socket.socket', side_effect=PermissionError()):
            with self.assertRaisesRegex(PermissionError, 'sudo python3'):
                capture.LinuxCapture('enp0s8')


if __name__ == '__main__':
    unittest.main()
