import ipaddress
import logging
import os
import re
import socket
import subprocess

logger = logging.getLogger(__name__)

PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def is_admin() -> bool:
    try:
        return os.geteuid() == 0          # Linux / Mac
    except AttributeError:
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False


def get_network_interfaces() -> list:
    """Return [(iface_name, ip)] using the best available method."""
    # 1. netifaces (optional)
    try:
        import netifaces
        ifaces = []
        for name in netifaces.interfaces():
            addrs = netifaces.ifaddresses(name)
            for entry in addrs.get(netifaces.AF_INET, []):
                ip = entry.get('addr', '')
                if ip and not ip.startswith('169.254'):
                    ifaces.append((name, ip))
        if ifaces:
            return ifaces
    except ImportError:
        pass
    except Exception as exc:
        logger.debug('netifaces: %s', exc)

    # 2. Windows ipconfig
    if os.name == 'nt':
        try:
            out = subprocess.run(['ipconfig', '/all'],
                                 capture_output=True, text=True, timeout=5).stdout
            ifaces = _parse_ipconfig(out)
            if ifaces:
                return ifaces
        except Exception as exc:
            logger.debug('ipconfig: %s', exc)

    # 3. Linux: ip addr
    if os.name == 'posix':
        try:
            out = subprocess.run(['ip', '-4', 'addr', 'show'],
                                 capture_output=True, text=True, timeout=5).stdout
            ifaces = _parse_ip_addr(out)
            if ifaces:
                return ifaces
        except Exception:
            pass

    # 4. Final fallback
    return [('eth0', get_ip_address())]


def get_ip_address(_interface: str = None) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def lookup_asn(ip_str: str) -> dict:
    return {'asn': 'AS0', 'org': 'Unknown', 'country': 'XX'}


# ── helpers ───────────────────────────────────────────────────────────────────

def _parse_ipconfig(text: str) -> list:
    ifaces, adapter = [], 'Unknown'
    for line in text.splitlines():
        m = re.match(r'^(\w[\w\s]+) adapter (.+):$', line)
        if m:
            adapter = m.group(2).strip().replace(' ', '_')
            continue
        m = re.search(r'IPv4 Address[^:]*:\s*([\d.]+)', line)
        if m:
            ip = m.group(1).strip()
            if not ip.startswith('169.254'):
                ifaces.append((adapter, ip))
    return ifaces


def _parse_ip_addr(text: str) -> list:
    ifaces, iface = [], 'unknown'
    for line in text.splitlines():
        m = re.match(r'^\d+:\s+(\S+):', line)
        if m:
            iface = m.group(1)
        m = re.search(r'inet\s+([\d.]+)/', line)
        if m:
            ip = m.group(1)
            if not ip.startswith('127.'):
                ifaces.append((iface, ip))
    return ifaces
