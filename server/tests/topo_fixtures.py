"""Testdaten für die Switch-Topologie: MIB eines Switches für den FakeAgent."""
from __future__ import annotations

from .snmp_agent import Counter32, Gauge32, IpAddress, Oid, TimeTicks


def mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def switch_mib(name: str, base_mac: str, ports: list[tuple[int, str, int, bool]], fdb: list[tuple[str, int]] = (),
               lldp: list[tuple[int, str, str, str, int, str | None]] = (), poe: list[int] = (),
               gateway: str | None = None, ips: list[str] = (), errors: dict[int, int] | None = None,
               uptime: int = 360000, arp: list[tuple[str, str]] = ()) -> dict:
    """ports: (ifIndex, Name, Mbit/s, up); fdb: (MAC, Bridge-Port = ifIndex); lldp: (lokaler Port, Chassis-MAC,
    Port-ID, sysName, Fähigkeiten-Byte, Mgmt-IP)."""
    errors = errors or {}
    m: dict = {
        "1.3.6.1.2.1.1.1.0": f"{name} Managed Switch 24G".encode(), "1.3.6.1.2.1.1.2.0": Oid("1.3.6.1.4.1.99999.1"),
        "1.3.6.1.2.1.1.3.0": TimeTicks(uptime * 100), "1.3.6.1.2.1.1.4.0": b"it@example.org",
        "1.3.6.1.2.1.1.5.0": name.encode(), "1.3.6.1.2.1.1.6.0": b"Technikraum",
        "1.3.6.1.2.1.17.1.1.0": mac_bytes(base_mac),
    }
    for idx, pname, mbps, up in ports:
        m[f"1.3.6.1.2.1.2.2.1.2.{idx}"] = pname.encode()
        m[f"1.3.6.1.2.1.2.2.1.3.{idx}"] = 6
        m[f"1.3.6.1.2.1.2.2.1.5.{idx}"] = Gauge32(mbps * 1_000_000 if mbps < 4000 else 4_294_967_295)
        m[f"1.3.6.1.2.1.2.2.1.6.{idx}"] = mac_bytes(base_mac[:-2] + f"{idx:02X}")
        m[f"1.3.6.1.2.1.2.2.1.7.{idx}"] = 1
        m[f"1.3.6.1.2.1.2.2.1.8.{idx}"] = 1 if up else 2
        m[f"1.3.6.1.2.1.2.2.1.14.{idx}"] = Counter32(errors.get(idx, 0))
        m[f"1.3.6.1.2.1.2.2.1.20.{idx}"] = Counter32(0)
        m[f"1.3.6.1.2.1.31.1.1.1.1.{idx}"] = pname.encode()
        m[f"1.3.6.1.2.1.31.1.1.1.15.{idx}"] = Gauge32(mbps)
        m[f"1.3.6.1.2.1.10.7.2.1.19.{idx}"] = 3
        m[f"1.3.6.1.2.1.17.1.4.1.2.{idx}"] = idx
        m[f"1.3.6.1.2.1.17.7.1.4.5.1.1.{idx}"] = Gauge32(10)
    for mac, port in fdb:
        sub = ".".join(str(b) for b in mac_bytes(mac))
        m[f"1.3.6.1.2.1.17.4.3.1.1.{sub}"] = mac_bytes(mac)
        m[f"1.3.6.1.2.1.17.4.3.1.2.{sub}"] = port
        m[f"1.3.6.1.2.1.17.4.3.1.3.{sub}"] = 3
    m["1.0.8802.1.1.2.1.3.1.0"] = 4
    m["1.0.8802.1.1.2.1.3.2.0"] = mac_bytes(base_mac)
    for n, (lport, chassis, port_id, sysname, caps, ip) in enumerate(lldp, 1):
        sub = f"0.{lport}.{n}"
        m[f"1.0.8802.1.1.2.1.4.1.1.4.{sub}"] = 4
        m[f"1.0.8802.1.1.2.1.4.1.1.5.{sub}"] = mac_bytes(chassis)
        m[f"1.0.8802.1.1.2.1.4.1.1.6.{sub}"] = 5
        m[f"1.0.8802.1.1.2.1.4.1.1.7.{sub}"] = port_id.encode()
        m[f"1.0.8802.1.1.2.1.4.1.1.9.{sub}"] = sysname.encode()
        m[f"1.0.8802.1.1.2.1.4.1.1.12.{sub}"] = bytes([caps, 0])
        if ip:
            m[f"1.0.8802.1.1.2.1.4.2.1.3.{sub}.1.4.{ip}"] = 2
    if poe:
        m["1.3.6.1.2.1.105.1.3.1.1.2.1"] = Gauge32(370)
        m["1.3.6.1.2.1.105.1.3.1.1.4.1"] = Gauge32(62)
        for p in poe:
            m[f"1.3.6.1.2.1.105.1.1.1.6.1.{p}"] = 3
    for ip in ips:
        m[f"1.3.6.1.2.1.4.20.1.2.{ip}"] = 1
    for ip, mac in arp:
        m[f"1.3.6.1.2.1.4.22.1.2.1.{ip}"] = mac_bytes(mac)
    if gateway:
        m["1.3.6.1.2.1.4.21.1.7.0.0.0.0"] = IpAddress(gateway)
    return m


CORE_MAC, EG_MAC, OG_MAC, GW_MAC = "00:1A:2B:00:01:00", "00:1A:2B:00:02:00", "00:1A:2B:00:03:00", "00:0C:29:AA:00:01"
PC1, PC2, PRN = "3C:52:82:11:0A:01", "3C:52:82:11:0A:02", "00:80:77:3A:19:2C"
DESK = ["3C:52:82:22:00:01", "3C:52:82:22:00:02", "3C:52:82:22:00:03"]


def core_mib(**kw) -> dict:
    """Core: Port 1 → EG (LLDP), Port 2 → Gateway, Port 3 → OG (nur MAC-Tabelle, 100 Mbit)."""
    return switch_mib(
        "SW-Core-01", CORE_MAC,
        [(1, "Port 1", 10000, True), (2, "Port 2", 10000, True), (3, "Port 3", 100, True), (4, "Port 4", 1000, False)],
        fdb=[(EG_MAC, 1), (PC1, 1), (PRN, 1)] + [(m, 1) for m in DESK] + [(GW_MAC, 2), (OG_MAC, 3), (PC2, 3)],
        lldp=[(1, EG_MAC, "Port 25", "SW-EG-01", 0x20, "192.168.10.3")],
        gateway="192.168.10.1", ips=["192.168.10.2"], arp=[("192.168.10.1", GW_MAC), ("192.168.10.41", PC1)], **kw)


def eg_mib(errors: int = 0) -> dict:
    """EG: Uplink Port 25, PC an Port 4 (mit Fehlern), Tisch-Switch mit drei PCs an Port 2, Drucker an Port 7."""
    return switch_mib(
        "SW-EG-01", EG_MAC,
        [(2, "Port 2", 1000, True), (4, "Port 4", 1000, True), (7, "Port 7", 100, True), (25, "Port 25", 10000, True)],
        fdb=[(CORE_MAC, 25), (GW_MAC, 25), (OG_MAC, 25), (PC2, 25), (PC1, 4), (PRN, 7)] + [(m, 2) for m in DESK],
        lldp=[(25, CORE_MAC, "Port 1", "SW-Core-01", 0x20, "192.168.10.2")], poe=[4],
        ips=["192.168.10.3"], errors={4: errors})


def og_mib() -> dict:
    """OG: kein LLDP; Uplink Port 15 (100 Mbit), PC an Port 1."""
    return switch_mib(
        "SW-OG-01", OG_MAC, [(1, "Port 1", 1000, True), (15, "Port 15", 100, True)],
        fdb=[(CORE_MAC, 15), (EG_MAC, 15), (GW_MAC, 15), (PC1, 15), (PC2, 1)], ips=["192.168.10.4"])
