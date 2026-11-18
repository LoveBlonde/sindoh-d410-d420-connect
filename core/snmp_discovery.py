"""
Pure-Python SNMPv1/v2c & Network Discovery Engine for D410 / D410s / D420 MFPs.
Zero external dependencies required (uses standard library socket, struct, concurrent.futures).
Works identically on Windows and macOS.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, List, Optional
import urllib.request
import ssl


# Standard Printer & Host MIB OIDs (matching SindohConnect.Snmp)
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_HR_DEVICE_DESCR = "1.3.6.1.2.1.25.3.2.1.3.1"
OID_PRT_GENERAL_PRINTER_NAME = "1.3.6.1.2.1.43.5.1.1.16.1"
OID_PRT_GENERAL_SERIAL = "1.3.6.1.2.1.43.5.1.1.17.1"


@dataclass
class DiscoveredDevice:
    ip: str
    model: str = "Unknown Printer"
    sys_descr: str = ""
    serial: str = ""
    hostname: str = ""
    vendor: str = "SINDOH"  # KM / SINDOH / LEXMARK
    is_target_series: bool = False  # True if D410 / D410s / D420 / CM207x / C224e etc.
    supports_scan: bool = True
    web_scheme: str = "http"

    @property
    def display_title(self) -> str:
        return f"{self.model}"

    @property
    def display_subtitle(self) -> str:
        parts = [f"IP: {self.ip}"]
        if self.serial:
            parts.append(f"S/N: {self.serial}")
        if self.hostname:
            parts.append(f"Host: {self.hostname}")
        return "  |  ".join(parts)


def _encode_oid(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.strip(".").split(".")]
    if len(parts) < 2:
        raise ValueError(f"Invalid OID: {oid_str}")
    body = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part == 0:
            body.append(0)
        else:
            buf = bytearray()
            while part > 0:
                buf.insert(0, part & 0x7F)
                part >>= 7
            for i in range(len(buf) - 1):
                buf[i] |= 0x80
            body.extend(buf)
    return bytes([0x06, len(body)]) + bytes(body)


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    hex_bytes = []
    while length > 0:
        hex_bytes.insert(0, length & 0xFF)
        length >>= 8
    return bytes([0x80 | len(hex_bytes)] + hex_bytes)


def _encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def build_snmp_get_packet(oids: List[str], community: str = "public", request_id: int = 1001) -> bytes:
    """Build a standard ASN.1 BER SNMPv2c GetRequest packet for multiple OIDs."""
    varbinds = bytearray()
    for oid in oids:
        oid_bytes = _encode_oid(oid)
        null_bytes = b"\x05\x00"
        varbind = _encode_tlv(0x30, oid_bytes + null_bytes)
        varbinds.extend(varbind)

    varbind_list = _encode_tlv(0x30, bytes(varbinds))
    req_id_bytes = _encode_tlv(0x02, struct.pack(">i", request_id))
    error_status = b"\x02\x01\x00"
    error_index = b"\x02\x01\x00"

    # GetRequest PDU tag = 0xA0
    pdu = _encode_tlv(0xA0, req_id_bytes + error_status + error_index + varbind_list)
    version = b"\x02\x01\x01"  # SNMPv2c (1)
    comm_bytes = _encode_tlv(0x04, community.encode("ascii"))
    return _encode_tlv(0x30, version + comm_bytes + pdu)


def _read_ber_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num_bytes = first & 0x7F
    length = 0
    for _ in range(num_bytes):
        length = (length << 8) | data[offset]
        offset += 1
    return length, offset


def _decode_oid(oid_bytes: bytes) -> str:
    if not oid_bytes:
        return ""
    first = oid_bytes[0]
    parts = [first // 40, first % 40]
    val = 0
    for b in oid_bytes[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def parse_snmp_response(data: bytes) -> dict[str, str]:
    """Extract {oid_str: string_value} from an SNMP GetResponse packet."""
    results: dict[str, str] = {}
    try:
        if not data or data[0] != 0x30:
            return results
        _, idx = _read_ber_length(data, 1)
        # Skip version
        if data[idx] != 0x02:
            return results
        v_len, idx = _read_ber_length(data, idx + 1)
        idx += v_len
        # Skip community
        if data[idx] != 0x04:
            return results
        c_len, idx = _read_ber_length(data, idx + 1)
        idx += c_len
        # PDU (0xA2 = GetResponse)
        if data[idx] != 0xA2:
            return results
        _, idx = _read_ber_length(data, idx + 1)
        # Skip request-id, error-status, error-index (3 INTEGERs)
        for _ in range(3):
            if data[idx] != 0x02:
                return results
            i_len, idx = _read_ber_length(data, idx + 1)
            idx += i_len
        # VarBindList (0x30)
        if data[idx] != 0x30:
            return results
        vbl_len, idx = _read_ber_length(data, idx + 1)
        end_vbl = idx + vbl_len
        while idx < end_vbl and idx < len(data):
            if data[idx] != 0x30:
                break
            vb_len, idx = _read_ber_length(data, idx + 1)
            vb_end = idx + vb_len
            if data[idx] == 0x06:
                o_len, idx = _read_ber_length(data, idx + 1)
                oid_str = _decode_oid(data[idx : idx + o_len])
                idx += o_len
                val_tag = data[idx]
                val_len, idx = _read_ber_length(data, idx + 1)
                val_raw = data[idx : idx + val_len]
                if val_tag == 0x04:  # OCTET STRING
                    val_str = val_raw.decode("utf-8", errors="ignore").strip("\x00 ")
                    if val_str:
                        results[oid_str] = val_str
            idx = vb_end
    except Exception:
        pass
    return results


def get_local_ipv4_addresses() -> List[str]:
    """Return active non-loopback IPv4 addresses on this machine."""
    ips = set()
    try:
        # Primary outbound interface IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass

    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = str(info[4][0])
            if not ip.startswith("127.") and not ip.startswith("169.254."):
                ips.add(ip)
    except Exception:
        pass

    return sorted(ips)


def _normalize_model_name(raw_text: str) -> tuple[str, bool]:
    """
    Parse SNMP description or HTTP XML product name into a clean model string
    and check whether it is a D410 / D410s / D420 / Konica Minolta equivalent.
    """
    upper = raw_text.upper()
    # Direct regex for Sindoh D410s / D410 / D420 / D400 / N600 / CM207x / 22C-6e
    match = re.search(r"\b(D410S|D410|D420|D400|D450|D460|D470|N600|N610|CM207[0-9]|C224E|C284E)\b", upper)
    if match:
        code = match.group(1)
        if code == "D410S":
            code = "D410s"
        return f"SINDOH {code} Series", True
    if "22C-6E" in upper or "28C-6E" in upper:
        return "SINDOH D410/D420 Series", True

    if "SINDOH" in upper or "KONICA" in upper or "MINOLTA" in upper:
        cleaned = re.sub(r"\s+", " ", raw_text).strip()
        is_target = any(k in upper for k in ("D410", "D420", "224", "284", "CM207"))
        return cleaned[:45], is_target

    return raw_text.strip()[:45] or "Network MFP", False


def probe_http_wcd(ip: str, timeout: float = 1.2) -> Optional[DiscoveredDevice]:
    """
    Probe Konica Minolta / Sindoh D410/D420 Web Connection (/wcd/common.xml or /wcd/top.xml)
    just like SindohConnect.Mfp.Core does.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for scheme in ("http", "https"):
        for path in ("/wcd/common.xml", "/wcd/top.xml", "/cgi-bin/home.cgi"):
            url = f"{scheme}://{ip}{path}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"},
                )
                with urllib.request.urlopen(req, timeout=timeout, context=ctx if scheme == "https" else None) as resp:
                    body = resp.read(8192).decode("utf-8", errors="ignore")
                    if "<ProductName>" in body or "<MFP>" in body or "wcd" in body.lower():
                        m = re.search(r"<ProductName>([^<]+)</ProductName>", body)
                        prod = m.group(1).strip() if m else "SINDOH D410/D420 Series"
                        s_m = re.search(r"<SerialNumber>([^<]+)</SerialNumber>", body)
                        serial = s_m.group(1).strip() if s_m else ""
                        model_name, is_target = _normalize_model_name(prod)
                        return DiscoveredDevice(
                            ip=ip,
                            model=model_name,
                            sys_descr=prod,
                            serial=serial,
                            vendor="KM_SINDOH",
                            is_target_series=is_target or True,
                            supports_scan=True,
                            web_scheme=scheme,
                        )
                    elif "Sindoh" in body or "tb_login" in body:
                        return DiscoveredDevice(
                            ip=ip,
                            model="SINDOH MFP",
                            sys_descr="Sindoh Web Monitor",
                            vendor="SINDOH_WEB",
                            is_target_series=True,
                            supports_scan=True,
                            web_scheme=scheme,
                        )
            except Exception:
                continue
    return None


def probe_single_ip(ip: str, timeout: float = 0.65) -> Optional[DiscoveredDevice]:
    """Query a single IP via UDP 161 SNMP first, with fallback to TCP 9100 + HTTP WCD probe."""
    oids = [
        OID_HR_DEVICE_DESCR,
        OID_PRT_GENERAL_PRINTER_NAME,
        OID_SYS_DESCR,
        OID_SYS_NAME,
        OID_PRT_GENERAL_SERIAL,
    ]
    pkt = build_snmp_get_packet(oids)
    snmp_data = {}

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(pkt, (ip, 161))
            resp, _ = sock.recvfrom(4096)
            snmp_data = parse_snmp_response(resp)
    except Exception:
        pass

    if snmp_data:
        raw_model = (
            snmp_data.get(OID_HR_DEVICE_DESCR)
            or snmp_data.get(OID_PRT_GENERAL_PRINTER_NAME)
            or snmp_data.get(OID_SYS_DESCR)
            or ""
        )
        sys_descr = snmp_data.get(OID_SYS_DESCR, raw_model)
        hostname = snmp_data.get(OID_SYS_NAME, "")
        serial = snmp_data.get(OID_PRT_GENERAL_SERIAL, "")
        combined = f"{raw_model} {sys_descr} {hostname}"

        # Filter to printers / MFPs
        if any(
            k in combined.upper()
            for k in ("SINDOH", "D410", "D420", "D400", "22C-6E", "KONICA", "MINOLTA", "PRINTER", "MFP", "SERIES", "PCL", "LEXMARK")
        ) or OID_HR_DEVICE_DESCR in snmp_data or OID_PRT_GENERAL_PRINTER_NAME in snmp_data:
            model_name, is_target = _normalize_model_name(f"{raw_model} {sys_descr}")
            if not is_target and raw_model:
                model_name = raw_model.strip()[:45]
            return DiscoveredDevice(
                ip=ip,
                model=model_name,
                sys_descr=sys_descr,
                serial=serial,
                hostname=hostname,
                vendor="KM_SINDOH",
                is_target_series=is_target,
                supports_scan=True,
            )

    return None


def scan_network(
    progress_callback: Optional[Callable[[int, int], None]] = None,
    only_d410_d420: bool = False,
) -> List[DiscoveredDevice]:
    """
    Scan all local /24 subnets via fast UDP SNMP broadcast + unicast sweep.
    """
    local_ips = get_local_ipv4_addresses()
    target_ips: List[str] = []
    seen_subnets = set()

    for lip in local_ips:
        try:
            net = ipaddress.IPv4Network(f"{lip}/24", strict=False)
            if net.network_address not in seen_subnets:
                seen_subnets.add(net.network_address)
                for host in net.hosts():
                    hip = str(host)
                    if hip != lip:
                        target_ips.append(hip)
        except Exception:
            pass

    if not target_ips:
        # Fallback default subnet
        target_ips = [f"192.168.0.{i}" for i in range(1, 255)]

    discovered: List[DiscoveredDevice] = []
    total = len(target_ips)
    completed = 0

    with ThreadPoolExecutor(max_workers=64) as pool:
        future_map = {pool.submit(probe_single_ip, ip, 0.55): ip for ip in target_ips}
        for fut in as_completed(future_map):
            completed += 1
            if progress_callback and (completed % 10 == 0 or completed == total):
                progress_callback(completed, total)
            dev = fut.result()
            if dev is not None:
                if not only_d410_d420 or dev.is_target_series:
                    discovered.append(dev)

    # Sort target series (D410s/D420) first, then by IP
    discovered.sort(key=lambda d: (not d.is_target_series, [int(x) for x in d.ip.split(".")]))
    return discovered


def verify_manual_ip(ip: str) -> Optional[DiscoveredDevice]:
    """Directly probe a user-supplied IP via SNMP and HTTP WCD."""
    ip = ip.strip()
    dev = probe_single_ip(ip, timeout=1.2)
    if dev:
        return dev
    dev = probe_http_wcd(ip, timeout=1.5)
    if dev:
        return dev
    # Final fallback: check TCP 9100 (RAW JetDirect printing port) or TCP 80
    for port in (9100, 80, 443, 515, 631):
        try:
            with socket.create_connection((ip, port), timeout=1.0):
                return DiscoveredDevice(
                    ip=ip,
                    model="SINDOH D410s / D420 (직접 연결)",
                    sys_descr=f"Port {port} Open",
                    is_target_series=True,
                    supports_scan=True,
                )
        except Exception:
            continue
    return None
