from __future__ import annotations

import ipaddress
import json
import os
import platform as os_platform
import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.device import Device
from app.services.auth import audit, get_current_user, require_roles

router = APIRouter(prefix="/network", tags=["Network Discovery"])

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    161, 389, 443, 445, 3306, 3389, 5900, 5985,
    5986, 62078, 8080, 8443, 9100,
]
QUICK_PORTS = [53, 80, 135, 139, 443, 445, 3389, 62078, 8080, 9100]


class DiscoverRequest(BaseModel):
    subnet: str | None = None
    deep: bool = True
    max_hosts: int = Field(default=254, ge=1, le=1022)
    family: str = Field(default="auto", pattern="^(auto|ipv4|ipv6)$")


def private(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return bool(obj.is_private and not obj.is_loopback and not obj.is_link_local)
    except Exception:
        return False


def local_ipv6(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return bool((obj.is_private or obj.is_link_local) and not obj.is_loopback)
    except Exception:
        return False


def _json_rows(cmd: list[str], timeout: int = 10):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        raw = (result.stdout or "").strip()
        if not raw:
            return []
        value = json.loads(raw)
        return value if isinstance(value, list) else [value]
    except Exception:
        return []


def wifi_interface_name() -> str | None:
    if not os_platform.system().lower().startswith("win"):
        return None
    try:
        out = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=8,
        ).stdout
        for pattern in (r"^\s*Name\s*:\s*(.+)$", r"^\s*Interface name\s*:\s*(.+)$"):
            match = re.search(pattern, out, re.I | re.M)
            if match:
                return match.group(1).strip()
    except Exception:
        pass
    return None


def windows_ip_configuration():
    if not os_platform.system().lower().startswith("win"):
        return []

    ps = r'''
$items = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object {$_.IPv4Address}
$out = foreach($x in $items) {
  $ipv4 = $x.IPv4Address | Select-Object -First 1
  $ipv6 = Get-NetIPAddress -InterfaceIndex $x.InterfaceIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue |
          Where-Object {$_.IPAddress -notlike '::1*'} | Select-Object -ExpandProperty IPAddress
  [pscustomobject]@{
    InterfaceAlias = $x.InterfaceAlias
    InterfaceIndex = $x.InterfaceIndex
    IPv4 = $ipv4.IPAddress
    Prefix = $ipv4.PrefixLength
    Gateway = $x.IPv4DefaultGateway.NextHop
    NetProfileName = $x.NetProfile.Name
    IPv6 = @($ipv6)
  }
}
$out | ConvertTo-Json -Compress
'''
    try:
        raw = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True, text=True, timeout=12,
        ).stdout.strip()
        if not raw:
            return []
        data = json.loads(raw)
        data = data if isinstance(data, list) else [data]
        wifi_name = wifi_interface_name()
        rows = []
        for x in data:
            ip = str(x.get("IPv4") or "").strip()
            prefix = x.get("Prefix")
            if not ip or prefix is None or not private(ip):
                continue
            ipv6_values = x.get("IPv6") or []
            if isinstance(ipv6_values, str):
                ipv6_values = [ipv6_values]
            ipv6_values = [v for v in ipv6_values if local_ipv6(v)]
            alias = x.get("InterfaceAlias")
            rows.append({
                "interface": alias,
                "index": x.get("InterfaceIndex"),
                "ip": ip,
                "prefix": int(prefix),
                "gateway": x.get("Gateway"),
                "profile": x.get("NetProfileName"),
                "cidr": str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False)),
                "ipv6": ipv6_values,
                "is_wifi": bool(wifi_name and alias and alias.lower() == wifi_name.lower()),
            })
        return rows
    except Exception:
        return []


def parse_ipconfig():
    rows = []
    try:
        out = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=8).stdout
        ipv4 = mask = None
        for raw in out.splitlines():
            line = raw.strip()
            match = re.search(r"(?:IPv4 Address|IPv4-adresse)[^:]*:\s*([0-9.]+)", line, re.I)
            if match:
                ipv4 = match.group(1)
            match = re.search(r"(?:Subnet Mask|Subnetzmaske)[^:]*:\s*([0-9.]+)", line, re.I)
            if match:
                mask = match.group(1)
            if ipv4 and mask and private(ipv4):
                try:
                    rows.append({
                        "interface": None,
                        "ip": ipv4,
                        "netmask": mask,
                        "cidr": str(ipaddress.ip_network(f"{ipv4}/{mask}", strict=False)),
                        "gateway": None,
                        "profile": None,
                        "ipv6": [],
                        "is_wifi": False,
                    })
                except Exception:
                    pass
                ipv4 = mask = None
    except Exception:
        pass
    return rows


def wifi_info():
    base = {"connected": False, "interface": None, "ssid": None, "bssid": None, "signal": None, "radio": None, "channel": None}
    if not os_platform.system().lower().startswith("win"):
        return base
    try:
        out = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=8,
        ).stdout
        def val(pattern):
            match = re.search(pattern, out, re.I | re.M)
            return match.group(1).strip() if match else None
        state = val(r"^\s*State\s*:\s*(.+)$")
        base.update({
            "connected": bool(state and state.lower() == "connected"),
            "state": state,
            "interface": val(r"^\s*(?:Name|Interface name)\s*:\s*(.+)$"),
            "ssid": val(r"^\s*SSID\s*:\s*(.+)$"),
            "bssid": val(r"^\s*BSSID\s*:\s*(.+)$"),
            "signal": val(r"^\s*Signal\s*:\s*(.+)$"),
            "radio": val(r"^\s*Radio type\s*:\s*(.+)$"),
            "channel": val(r"^\s*Channel\s*:\s*(.+)$"),
        })
        return base
    except Exception:
        return base


def arp_table(family: str = "ipv4", interface_filter: str | None = None):
    out: dict[str, dict] = {}
    if not os_platform.system().lower().startswith("win"):
        return out
    af = "IPv4" if family == "ipv4" else "IPv6"
    ps = f"Get-NetNeighbor -AddressFamily {af} -ErrorAction SilentlyContinue | Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias | ConvertTo-Json -Compress"
    for row in _json_rows(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], timeout=10):
        ip = str(row.get("IPAddress") or "").strip()
        mac = str(row.get("LinkLayerAddress") or "").strip()
        if not ip:
            continue
        if interface_filter and str(row.get("InterfaceAlias") or "").lower() != interface_filter.lower():
            continue
        valid = private(ip) if family == "ipv4" else local_ipv6(ip)
        if not valid:
            continue
        entry = {
            "mac": mac.replace("-", ":").upper() if re.fullmatch(r"[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}", mac) else None,
            "state": str(row.get("State") or "unknown").strip(),
            "interface": row.get("InterfaceAlias"),
            "family": family,
        }
        out[ip] = entry
    # IPv4 fallback for older Windows builds.
    if family == "ipv4":
        try:
            r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
            for line in r.stdout.splitlines():
                match = re.search(r"(\d+\.\d+\.\d+\.\d+).*?([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})", line)
                if match and private(match.group(1)):
                    out.setdefault(match.group(1), {
                        "mac": match.group(2).replace("-", ":").upper(),
                        "state": "unknown",
                        "interface": None,
                        "family": "ipv4",
                    })
        except Exception:
            pass
    return out


def local_ipv4():
    cfg = windows_ip_configuration()
    wifi = wifi_info()
    if wifi.get("connected") and wifi.get("interface"):
        for row in cfg:
            if row.get("interface", "").lower() == str(wifi["interface"]).lower() and private(row.get("ip", "")):
                return row["ip"]
    preferred = [x for x in cfg if x.get("gateway") and private(x.get("ip", "")) and not re.search(r"vEthernet|VMware|VirtualBox|Hyper-V|Loopback", str(x.get("interface") or ""), re.I)]
    if preferred:
        return preferred[0]["ip"]
    if cfg:
        return cfg[0]["ip"]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def ping(host, timeout=500, family="ipv4"):
    try:
        if os_platform.system().lower().startswith("win"):
            flag = "-6" if family == "ipv6" else "-4"
            r = subprocess.run(["ping", flag, "-n", "1", "-w", str(timeout), host], capture_output=True, text=True, timeout=1.8)
        else:
            flag = "-6" if family == "ipv6" else "-4"
            r = subprocess.run(["ping", flag, "-c", "1", "-W", "1", host], capture_output=True, text=True, timeout=1.8)
        return r.returncode == 0
    except Exception:
        return False


def probe_port(host, port, timeout=.22, family="ipv4"):
    try:
        af = socket.AF_INET6 if ":" in host or family == "ipv6" else socket.AF_INET
        with socket.socket(af, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
        return True
    except Exception:
        return False


def nmap_available():
    return bool(shutil.which("nmap"))


def nmap_discover(subnet, family="ipv4"):
    exe = shutil.which("nmap")
    if not exe:
        return []
    try:
        args = [exe, "-sn", "-n", "-T2"]
        if family == "ipv4":
            args.append("-PR")
        else:
            args.append("-6")
        args.append(subnet)
        r = subprocess.run(args, capture_output=True, text=True, timeout=120)
        pattern = r"Nmap scan report for (?:[^\s]+ \()?(.*?)\)?$"
        results = []
        for line in r.stdout.splitlines():
            if "Nmap scan report for" in line:
                target = line.split("Nmap scan report for", 1)[1].strip()
                if target.startswith("[") and "]" in target:
                    target = target.strip("[]")
                if " (" in target and target.endswith(")"):
                    target = target.rsplit(" (", 1)[1][:-1]
                try:
                    if family == "ipv4" and private(target):
                        results.append(target)
                    elif family == "ipv6" and local_ipv6(target):
                        results.append(target)
                except Exception:
                    pass
        return sorted(set(results), key=lambda x: ipaddress.ip_address(x.split("%")[0]))
    except Exception:
        return []


def hostname_for(ip):
    try:
        return socket.gethostbyaddr(ip.split("%")[0])[0]
    except Exception:
        return None


def nbt_name_for(ip):
    if ":" in ip or not os_platform.system().lower().startswith("win"):
        return None
    try:
        r = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if "<00>" in line and "UNIQUE" in line.upper():
                name = line.strip().split()[0]
                if name and name != "MAC":
                    return name
    except Exception:
        pass
    return None


def classify(ip, hostname, ports):
    n = (hostname or "").lower()
    s = set(ports)
    if ip.split(".")[-1:] == ["1"] or any(x in n for x in ("router", "gateway", "firewall", "forti", "paloalto", "mikrotik", "unifi", "ubiquiti")):
        return "Router"
    if 3389 in s or 445 in s or any(x in n for x in ("win", "server", "desktop", "laptop")):
        return "Windows/Server"
    if 62078 in s or any(x in n for x in ("iphone", "ipad")):
        return "iOS"
    if 5555 in s or "android" in n:
        return "Android"
    if 5900 in s or 22 in s:
        return "Linux/Unix"
    if any(x in n for x in ("tv", "roku", "bravia", "chromecast", "firetv")):
        return "Smart TV"
    if any(x in n for x in ("printer", "print")) or 9100 in s:
        return "Printer"
    if 80 in s or 443 in s:
        return "Web/Network Device"
    return "Network Device"


def local_info_data():
    cfg = windows_ip_configuration() or parse_ipconfig()
    wifi = wifi_info()
    primary = None
    if wifi.get("connected") and wifi.get("interface"):
        primary = next((x for x in cfg if x.get("interface", "").lower() == str(wifi["interface"]).lower()), None)
    if not primary:
        ip = local_ipv4()
        primary = next((x for x in cfg if x.get("ip") == ip), None)
    if not primary and cfg:
        primary = cfg[0]
    ip4 = primary.get("ip") if primary else local_ipv4()
    subnet4 = primary.get("cidr") if primary else (str(ipaddress.ip_network(f"{ip4}/24", strict=False)) if ip4 != "127.0.0.1" else None)
    ipv6s = list(dict.fromkeys((primary.get("ipv6") if primary else []) or []))
    interface_filter = primary.get("interface") if primary else wifi.get("interface")
    peers4 = arp_table("ipv4", interface_filter)
    peers6 = arp_table("ipv6", interface_filter)
    return {
        "local_ip": ip4,
        "local_ipv4": ip4,
        "subnet": subnet4,
        "wifi_subnet": subnet4 if wifi.get("connected") else None,
        "gateway": primary.get("gateway") if primary else None,
        "platform": os_platform.platform(),
        "primary_interface": primary.get("interface") if primary else wifi.get("interface"),
        "is_wifi_primary": bool(primary and primary.get("is_wifi")),
        "interfaces": cfg,
        "wifi": wifi,
        "local_ipv6": ipv6s,
        "ipv4_neighbors": [{"ip": k, **v} for k, v in sorted(peers4.items())],
        "ipv6_neighbors": [{"ip": k, **v} for k, v in sorted(peers6.items())],
        "arp_entries": len(peers4),
        "visible_neighbors": len(peers4) + len(peers6),
        "neighbors": [{"ip": k, **v} for k, v in sorted(peers4.items())],
        "nmap_available": nmap_available(),
        "visibility_note": "SentinelX reports devices visible to this host's network stack. Wi-Fi client isolation, VLANs, host firewalls, sleeping devices and other segmentation can hide peers. Authoritative Wi-Fi client inventory requires access to the AP/controller or endpoint agents.",
    }


@router.get("/local")
def local_info(user=Depends(get_current_user)):
    return local_info_data()


@router.get("/live")
def live(user=Depends(get_current_user), db: Session = Depends(get_db)):
    info = local_info_data()
    now = datetime.utcnow()
    peers = info.get("ipv4_neighbors", []) + info.get("ipv6_neighbors", [])
    known = db.query(Device).filter(Device.source == "network_discovery").order_by(Device.last_seen.desc()).limit(200).all()
    # Only expose online network-discovered assets as the real-time fleet snapshot.
    online = [
        {
            "id": d.id,
            "ip_address": d.ip_address,
            "hostname": d.hostname,
            "status": d.status,
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
        }
        for d in known if d.status == "online"
    ]
    return {"timestamp": now.isoformat(), "local": info, "visible_peers": peers, "known_assets": online}


def _scan_host_quick(host: str, family: str):
    if ping(host, family=family):
        return host, "icmp"
    for port in QUICK_PORTS:
        if probe_port(host, port, timeout=.18, family=family):
            return host, f"tcp:{port}"
    return None


@router.post("/discover")
def discover(req: DiscoverRequest = DiscoverRequest(), db: Session = Depends(get_db), user=Depends(require_roles("admin", "employee"))):
    info = local_info_data()
    family = req.family
    subnet = req.subnet
    if family == "auto":
        family = "ipv6" if subnet and ":" in subnet else "ipv4"
    # IPv6 auto mode uses the host's visible neighbor table; there is no safe /64 brute-force sweep.
    if family == "ipv6" and not subnet:
        visible = info.get("ipv6_neighbors", [])
        found_items = [
            {**n, "ip_address": n.get("ip"), "family": "ipv6", "hostname": hostname_for(n.get("ip", "")), "device_type": "Network Device", "platform": "Network Discovered", "online": True, "last_seen": datetime.utcnow().isoformat()}
            for n in visible if n.get("ip")
        ]
        created, updated = _persist_network_devices(found_items, info, "ipv6", db)
        audit(db, user, "network.discovery", "success", "ipv6-neighbors", details=f"family=ipv6;found={len(found_items)}")
        return {
            "status": "completed", "family": "ipv6", "subnet": None, "scanned": len(visible),
            "found": len(found_items), "created": created, "updated": updated,
            "methods": ["Windows IPv6 neighbor table"], "devices": found_items,
            "wifi": info.get("wifi", {}), "gateway": info.get("gateway"),
            "ipv6_neighbors": visible,
            "warning": "IPv6 neighbor discovery reports addresses already visible to the Windows host; a typical IPv6 /64 is not brute-force scanned.",
        }
    if not subnet:
        subnet = info.get("wifi_subnet") or info.get("subnet")
    if not subnet:
        raise HTTPException(400, "No local IPv4/Wi-Fi subnet is available. Connect to the target network first.")

    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        raise HTTPException(400, "Invalid local network or subnet.")
    if net.version != (6 if family == "ipv6" else 4):
        raise HTTPException(400, f"The selected subnet is not IPv{6 if family == 'ipv6' else 4}.")
    if family == "ipv4" and not all(private(str(x)) for x in [net.network_address, net.broadcast_address]):
        raise HTTPException(400, "Only private/local IPv4 networks are allowed.")
    if family == "ipv6" and net.prefixlen < 120:
        # Do not attempt a brute-force sweep of a typical IPv6 /64.
        visible = info.get("ipv6_neighbors", [])
        found = []
        for n in visible:
            ip = n.get("ip")
            try:
                if ip and ipaddress.ip_address(ip.split("%")[0]) in net:
                    found.append(ip)
            except Exception:
                pass
        methods = ["Windows IPv6 neighbor table"]
        if nmap_available():
            methods.append("nmap-ipv6 available (explicit small-prefix scan only)")
        created, updated = _persist_network_devices(found, info, family, db)
        audit(db, user, "network.discovery", "success", "subnet:" + str(net), details=f"family=ipv6;found={len(found)};methods={','.join(methods)}")
        return {
            "status": "completed",
            "family": "ipv6",
            "subnet": str(net),
            "scanned": 0,
            "found": len(found),
            "created": created,
            "updated": updated,
            "methods": methods,
            "devices": [{"ip_address": x, "family": "ipv6", "online": True, "last_seen": datetime.utcnow().isoformat()} for x in found],
            "wifi": info.get("wifi", {}),
            "gateway": info.get("gateway"),
            "ipv6_neighbors": info.get("ipv6_neighbors", []),
            "warning": "IPv6 /64 networks are not brute-force scanned. SentinelX uses the host's visible IPv6 neighbor table unless an explicitly small IPv6 prefix is supplied.",
        }
    if net.num_addresses > 1024:
        raise HTTPException(400, "Please scan a local subnet of 1024 addresses or fewer.")

    local_ip = info.get("local_ipv4")
    hosts = [str(h) for h in net.hosts() if str(h) != local_ip][:req.max_hosts]
    methods = []
    interface_filter = info.get("primary_interface")
    arp_before = arp_table("ipv4", interface_filter)
    methods.append("Windows ARP/neighbor table")
    candidates = set(arp_before.keys()) & set(hosts)

    if req.deep and nmap_available():
        nips = nmap_discover(str(net), "ipv4")
        if nips:
            candidates.update(nips)
            methods.append("Nmap ARP discovery")

    # Active discovery does not rely only on ICMP: many hosts block echo while still exposing services.
    with ThreadPoolExecutor(max_workers=96) as executor:
        futures = {executor.submit(_scan_host_quick, host, "ipv4"): host for host in hosts if host not in candidates}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    candidates.add(result[0])
            except Exception:
                pass
    methods.append("ICMP + TCP quick discovery")

    arp_after = arp_table("ipv4", interface_filter)
    arp = {**arp_before, **arp_after}
    candidates.update(set(arp.keys()) & set(hosts))
    methods.append("post-scan ARP refresh")

    def scan_ports(host):
        ports = [port for port in COMMON_PORTS if probe_port(host, port, .22, "ipv4")]
        return host, ports

    enriched = {}
    with ThreadPoolExecutor(max_workers=64) as executor:
        futures = {executor.submit(scan_ports, host): host for host in candidates} if req.deep else {}
        for future in as_completed(futures):
            try:
                host, ports = future.result()
                enriched[host] = ports
            except Exception:
                pass

    found = []
    now = datetime.utcnow()
    for ip in sorted(candidates, key=lambda x: ipaddress.ip_address(x)):
        ports = enriched.get(ip, [])
        hostname = hostname_for(ip) or nbt_name_for(ip)
        entry = arp.get(ip, {})
        found.append({
            "ip_address": ip,
            "family": "ipv4",
            "mac_address": entry.get("mac"),
            "neighbor_state": entry.get("state"),
            "interface": entry.get("interface"),
            "hostname": hostname,
            "device_type": classify(ip, hostname, ports),
            "platform": "Network Discovered",
            "ports": ports,
            "online": True,
            "last_seen": now.isoformat(),
        })

    created, updated = _persist_network_devices(found, info, "ipv4", db)
    seen = {x["ip_address"] for x in found}
    for d in db.query(Device).filter(Device.source == "network_discovery", Device.ip_address.isnot(None)).all():
        if d.ip_address not in seen and d.ip_address != local_ip:
            d.status = "offline"
    db.commit()
    audit(db, user, "network.discovery", "success", "subnet:" + str(net), details=f"family=ipv4;found={len(found)};methods={','.join(methods)}")
    return {
        "status": "completed",
        "family": "ipv4",
        "local_ip": local_ip,
        "subnet": str(net),
        "scanned": len(hosts),
        "found": len(found),
        "created": created,
        "updated": updated,
        "methods": methods,
        "devices": found,
        "wifi": info.get("wifi", {}),
        "gateway": info.get("gateway"),
        "ipv4_neighbors": info.get("ipv4_neighbors", []),
        "ipv6_neighbors": info.get("ipv6_neighbors", []),
        "warning": info["visibility_note"],
    }


def _persist_network_devices(items, info, family, db: Session):
    if family == "ipv6":
        normalized = []
        for item in items:
            normalized.append({"ip_address": item, "family": "ipv6", "hostname": hostname_for(item), "device_type": "Network Device", "ports": [], "mac_address": None, "neighbor_state": None, "interface": info.get("primary_interface"), "platform": "Network Discovered"})
        items = normalized
    else:
        normalized = items
    created = updated = 0
    for item in normalized:
        ip = item.get("ip_address")
        if not ip:
            continue
        hostname = item.get("hostname") or ip
        existing = db.query(Device).filter(Device.ip_address == ip).first()
        ports = item.get("ports") or []
        tags = (
            f"discovery=local;family={family};interface={item.get('interface') or info.get('primary_interface') or 'unknown'};"
            f"mac={item.get('mac_address') or 'unknown'};neighbor={item.get('neighbor_state') or 'unknown'};ports={','.join(map(str, ports))}"
        )
        if not existing:
            existing = Device(
                name=hostname,
                hostname=hostname,
                ip_address=ip,
                device_type=item.get("device_type") or "Network Device",
                platform="Network Discovered",
                status="online",
                risk_score=0,
                source="network_discovery",
                tags=tags,
                last_seen=datetime.utcnow(),
            )
            db.add(existing)
            created += 1
        else:
            existing.name = hostname
            existing.hostname = hostname
            existing.ip_address = ip
            existing.device_type = item.get("device_type") or existing.device_type
            existing.platform = "Network Discovered"
            existing.status = "online"
            existing.source = "network_discovery"
            existing.tags = tags
            existing.last_seen = datetime.utcnow()
            updated += 1
    db.commit()
    return created, updated
