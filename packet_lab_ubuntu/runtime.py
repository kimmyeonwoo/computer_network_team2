"""Execution environment shared by the Ubuntu command-line entry points."""
from pathlib import Path
import sys


def require_ubuntu():
    """Reject unsupported hosts before starting a server or a capture socket."""
    if not sys.platform.startswith('linux'):
        raise RuntimeError('이 버전은 Ubuntu Linux 전용입니다. 우분투 안에서 실행하세요.')
    try:
        release = Path('/etc/os-release').read_text(encoding='utf-8')
    except OSError as exc:
        raise RuntimeError('Ubuntu 실행 환경을 확인할 수 없습니다: /etc/os-release') from exc
    fields = {}
    for line in release.splitlines():
        key, separator, value = line.partition('=')
        if separator:
            fields[key] = value.strip().strip('\"\'')
    if fields.get('ID') != 'ubuntu':
        raise RuntimeError('이 버전의 실행 환경은 Ubuntu Linux입니다. 우분투 안에서 실행하세요.')
