# Ubuntu용 HTTP·DNS·SMTP 패킷 분석

Ubuntu Linux에서 `AF_PACKET`·`SOCK_RAW`로 패킷을 수집합니다. macOS용 캡처 코드는 포함하지 않습니다. 실행 시 운영체제를 확인하며, Ubuntu가 아니면 서버나 캡처 소켓을 열기 전에 안내하고 종료합니다.

Python 3 표준 라이브러리만 사용합니다. libpcap·Scapy 설치가 필요하지 않습니다. 분석 대상은 IPv4와 평문 HTTP·SMTP, UDP DNS입니다. HTTPS 및 TLS로 암호화된 SMTP 본문은 해석하지 않습니다.

## 1. 실행

ZIP을 **우분투 안에서** 압축 해제한 뒤, `app.py`가 있는 폴더에서 터미널을 엽니다.

```bash
sudo python3 app.py --no-browser
```

우분투 브라우저에서 접속합니다.

```text
http://127.0.0.1:8765/
```

인터페이스를 선택하고 **캡처 시작**을 누릅니다. `enp0s8`은 한 가지 예이며 컴퓨터마다 이름이 다릅니다. 다음 결과의 `dev` 뒤 이름을 확인하세요.

```bash
ip route get 1.1.1.1
```

화면 하단의 `Ubuntu Raw Socket · AF_PACKET / SOCK_RAW`를 확인합니다. 기존 프로그램이 실행 중이면 먼저 그 터미널에서 Ctrl+C로 종료하세요. 종료하지 않고 같은 포트로 실행하면 주소 사용 중 오류가 발생합니다.

## 2. 요청 보내기

프로그램 실행 터미널은 그대로 두고, **새 우분투 터미널**에서 요청을 보냅니다.

### HTTP

```bash
curl -4 -v --http1.1 http://example.com/
curl -4 -v --http1.0 http://example.com/
```

각 명령은 별도 연결입니다. IP·포트, TCP Seq/Ack·플래그, GET 경로·버전·Host, 서버 응답·헤더를 확인합니다. 요청과 응답의 HTTP 버전은 각각 읽습니다.

### DNS

```bash
dig @1.1.1.1 example.com A
dig @1.1.1.1 example.com AAAA
dig @1.1.1.1 example.com MX
```

질의·응답의 Transaction ID와 이름·유형, 응답 코드·반환 레코드를 비교합니다. AAAA는 IPv6 주소를 묻는 유형이지만 위 명령의 DNS 서버 연결은 IPv4입니다.

curl·dig가 없다면:

```bash
sudo apt update
sudo apt install curl dnsutils
```

### SMTP

운영체제 변경과 별개로 기존 SMTP 실험 기능은 유지합니다. 화면의 기본값은 공개 MailMock 서버 `146.59.115.14:1125`이며, **연결 확인**은 EHLO·NOOP·QUIT, **테스트 메일 보내기**는 해당 공개 서버로 고정된 가짜 주소와 본문을 한 번 보냅니다. 공개 테스트함에 표시되므로 개인 정보를 넣지 않습니다. 공개 서버의 현재 가용성은 보장되지 않습니다.

```bash
python3 external.py smtp --host 146.59.115.14 --port 1125
```

직접 실행한 테스트 서버를 캡처할 때는 그 서버의 실제 주소·포트로 통신하세요. 아래 예시는 자신이 실행한 SMTP 테스트 서버가 `172.30.0.10:25`에서 대기하는 경우입니다. 메일 명령을 실행할 때 새 서버를 자동 생성하지는 않습니다.

```bash
printf 'From: sender@example.test\r\nTo: receiver@example.test\r\nSubject: SMTP test\r\n\r\nSMTP packet test.\r\n' | curl -4 -v smtp://172.30.0.10:25 --mail-from sender@example.test --mail-rcpt receiver@example.test --upload-file -
```

이 폴더의 기존 `traffic.py`는 `127.0.0.1`에서 HTTP 8080, DNS 1053, SMTP 2525 로컬 서버를 시작하는 별도 보조 도구입니다. 위의 `172.30.0.10:25` 환경을 만드는 코드는 아닙니다. 같은 우분투 안의 로컬 서버와 통신을 관찰하려면 `lo`를 선택합니다. GUI의 외부 실험 버튼은 `lo`에서 사용하지 않고 터미널로 요청합니다.

## 3. Wireshark와 비교

우분투 Wireshark와 프로그램에서 **같은 인터페이스**로 캡처를 시작한 뒤 요청을 한 번 보냅니다. 둘 다 중지하고 같은 연결·메시지를 비교합니다. 패킷 번호는 다를 수 있으므로 IP·포트·방향 및 원시 Seq/Ack 또는 DNS ID로 맞춥니다.

| 대상 | Wireshark 표시 필터 |
|---|---|
| HTTP | `tcp.port == 80` |
| DNS | `udp.port == 53 && ip.addr == 1.1.1.1` |
| 직접 실행한 SMTP 서버 | `tcp.port == 25` (실제 포트에 맞춰 변경) |

프로그램의 **PCAP 저장** 파일을 Wireshark로 열어 동일 바이트의 해석 결과를 비교하는 기능도 유지합니다. PCAP 파일 저장은 libpcap 라이브러리 사용과 별개입니다.

## 4. 파일과 검사

| 파일 | 역할 |
|---|---|
| app.py | GUI 서버, 캡처 제어, 결과 제공, PCAP 저장 |
| capture.py | AF_PACKET·SOCK_RAW 수집과 송수신 방향 구분 |
| runtime.py | Ubuntu 실행 환경 확인 |
| analyzer.py | IP·TCP/UDP 헤더, HTTP·DNS·SMTP 해석 및 TCP 재조립 |
| external.py | HTTP·DNS·SMTP 실험 요청 |
| traffic.py | 기존 로컬 보조 테스트 서버 |
| ui.html | 패킷 목록·필터·상세 화면 |
| verify.py | 기존 분석·클라이언트 회귀 검사 |
| test_capture.py | 실행 환경 제한, 송수신 수집, 오류 시 정리 검사 |

검사는 실제 외부 서버나 관리자 권한 없이 모의 소켓으로 실행합니다.

```bash
python3 -m unittest verify test_capture
```

테스트는 구문·동작 회귀를 검사합니다. 우분투에서 실제 송신·수신 캡처가 되는지는 위 실행 절차로 따로 확인하세요.
