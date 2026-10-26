"""Gateways automatisch erkennen und als Wurzel des Topologie-Baums zeigen (docs/TOPOLOGIE.md)."""
import json
import unittest

from wachtl import repo
from wachtl.db import ins, q1
from wachtl.serverprobe import gateway as probe_gateway
from wachtl.services import gateways, topology

from .helpers import AppTestCase
from .test_topology import DEVICES, rows
from .topo_fixtures import GW_MAC

TR64 = """<?xml version="1.0"?><root xmlns="urn:dslforum-org:device-1-0"><device>
<deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType><friendlyName>FRITZ!Box 7590 AX</friendlyName>
<manufacturer>AVM Berlin</manufacturer><modelName>FRITZ!Box 7590 AX</modelName><modelNumber>-</modelNumber>
<softwareVersion>7.57</softwareVersion></device></root>"""


class IdentifyTest(unittest.TestCase):
    def ident(self, mac=None, services=(), upnp=None, lldp=None, hostname=None):
        return gateways.identify("192.168.1.1", mac, list(services), upnp, lldp, hostname)

    def test_vendors(self):
        cases = [
            (dict(mac="C8:0E:14:00:00:01", upnp=probe_gateway.parse_device_xml(TR64)), "FRITZ!Box 7590 AX", "AVM"),
            (dict(services=[{"port": 443, "http_title": "UniFi OS", "tls": True, "tls_subject": "CN=UDM-Pro"}]),
             "UniFi UDM-PRO", "Ubiquiti"),
            (dict(services=[{"port": 4444, "http_title": "Sophos", "tls": True, "tls_subject": "CN=XGS2100_RL01"}]),
             "Sophos XGS2100", "Sophos"),
            (dict(services=[{"port": 443, "tls": True, "tls_subject": "CN=FGT60FTK21000000,O=Fortinet"}]),
             "FortiGate 60F", "Fortinet"),
            (dict(lldp=[{"sys_descr": "Juniper Networks Session Smart Router SSR120"}]), "Juniper SSR120", "Juniper"),
            (dict(services=[{"port": 443, "http_title": "SSR Conductor", "tls": True}]),
             "Juniper SSR (Session Smart Router)", "Juniper"),
            (dict(services=[{"port": 80, "http_title": "Speedport Smart 4"}]), "Speedport Smart 4", "Telekom"),
            (dict(services=[{"port": 443, "http_server": "LANCOM 1793VA 10.80", "tls": True}]), "LANCOM 1793VA", "LANCOM"),
            (dict(services=[{"port": 443, "http_title": "USG FLEX 200", "tls": True}]), "Zyxel USG FLEX 200", "Zyxel"),
            (dict(services=[{"port": 443, "http_title": "pfSense - Login", "tls": True}]), "pfSense", "Netgate"),
            (dict(services=[{"port": 443, "http_title": "OPNsense", "tls": True}]), "OPNsense", "Deciso"),
            (dict(mac="00:1F:95:11:22:33"), "Provider-Router (Sagemcom)", "Sagemcom"),
        ]
        for kw, label, vendor in cases:
            r = self.ident(**kw)
            self.assertEqual((r["label"], r["vendor"]), (label, vendor), kw)
        self.assertEqual(self.ident()["label"], "Gateway")

    def test_web_link_and_confidence(self):
        r = self.ident(mac="00:09:0F:AA:BB:CC", services=[{"port": 80, "http_status": 301},
                                                          {"port": 4444, "tls": True, "http_title": "Sophos"}])
        self.assertEqual(r["web"], "https://192.168.1.1:4444/")
        self.assertEqual(self.ident(services=[{"port": 4444, "http_title": "Sophos"}])["confidence"], 80)
        self.assertEqual(self.ident(mac="C8:0E:14:00:00:01", services=[{"port": 80, "http_title": "FRITZ!Box"}])
                         ["confidence"], 95)

    def test_clean_probe_gateway(self):
        self.assertEqual(gateways.clean_probe_gateway("192.168.1.1", "c8-0e-14-00-00-01"),
                         ("192.168.1.1", "C8:0E:14:00:00:01"))
        self.assertEqual(gateways.clean_probe_gateway("8.8.8.8", "x"), (None, None))
        self.assertEqual(gateways.clean_probe_gateway("kaputt", None), (None, None))


class CollectTest(unittest.TestCase):
    def test_collect_with_tr64(self):
        def scan(ip, port, timeout):
            return {"port": port, "tls": port == 443, "http_title": "FRITZ!Box"} if port in (80, 443) else None

        data = probe_gateway.collect("192.168.178.1", scan_port=scan,
                                     fetch=lambda url: TR64 if url.endswith("tr64desc.xml") else None,
                                     ssdp=lambda gw: None, arp=lambda: {"192.168.178.1": "C8:0E:14:00:00:01"})
        self.assertEqual([s["port"] for s in data["services"]], [80, 443])
        self.assertEqual(data["upnp"]["modelName"], "FRITZ!Box 7590 AX")
        self.assertEqual(data["mac"], "C8:0E:14:00:00:01")
        self.assertEqual(probe_gateway.parse_device_xml("<kaputt"), {})


class AnalyzeTest(unittest.TestCase):
    def test_gateway_without_switches_is_root_with_devices(self):
        gw = gateways.identify("192.168.10.1", GW_MAC, [{"port": 443, "http_title": "UniFi OS", "tls": True}])
        cands = [{"id": 5, "mac": "50:C7:BF:00:00:09", "ip": "192.168.10.9", "label": "TL-SG108E", "access": "easysmart"}]
        topo = topology.analyze([], dict(DEVICES), {}, cands, gateway=gw, now=repo.now())
        self.assertEqual(topo.roots, ["internet"])
        node = topo.nodes["gw"]
        self.assertEqual((node.label, node.parent), ("UniFi Gateway", "internet"))
        self.assertEqual(node.children, ["c5"])
        self.assertEqual(sorted(d["label"] for d in node.devices), ["PC-Empfang-01", "PC-OG-03"])
        lay = topology.layout(topo)
        self.assertEqual(len(lay["boxes"]), 3)

    def test_gateway_not_on_a_port_sits_above_core(self):
        gw = gateways.identify("192.168.10.254", "C8:0E:14:00:00:01", [{"port": 80, "http_title": "FRITZ!Box 7530"}])
        topo = topology.analyze(rows(), dict(DEVICES), {}, [], gateway=gw)
        # der Switch kennt sein Gateway 192.168.10.1 (Firewall an Port 2) – das gewinnt gegen eine abweichende Meldung
        self.assertEqual(topo.nodes["gw"].label, "Firewall")
        gw = gateways.identify("192.168.10.1", None, [{"port": 443, "http_title": "Sophos", "tls": True}])
        topo = topology.analyze(rows(), dict(DEVICES), {}, [], gateway=gw)
        self.assertEqual(topo.nodes["gw"].label, "Sophos Firewall")
        self.assertEqual(topo.nodes["gw"].link.via, "gateway")


class GatewayAppTest(AppTestCase):
    def test_heartbeat_result_and_pages(self):
        probe = self.enroll()
        auth = {"Authorization": f"Bearer {probe['token']}"}
        site = q1("SELECT site_id FROM probes WHERE id = ?", (probe["probe_id"],))["site_id"]
        self.client.post("/api/probe/v1/heartbeat", json={"version": "1", "gateway": "192.168.178.1",
                                                          "gateway_mac": "c8:0e:14:00:00:01"}, headers=auth)
        row = q1("SELECT gateway, gateway_mac FROM probes WHERE id = ?", (probe["probe_id"],))
        self.assertEqual((row["gateway"], row["gateway_mac"]), ("192.168.178.1", "C8:0E:14:00:00:01"))
        # Heartbeat ohne MAC behält die bekannte MAC
        self.client.post("/api/probe/v1/heartbeat", json={"version": "1", "gateway": "192.168.178.1"}, headers=auth)
        self.assertEqual(q1("SELECT gateway_mac FROM probes")["gateway_mac"], "C8:0E:14:00:00:01")
        # Was die Server-Probe herausfand
        r = self.client.post("/api/probe/v1/results/gateway", headers=auth, json={
            "ip": "192.168.178.1", "services": [{"port": 80, "http_title": "FRITZ!Box", "tls": False}],
            "upnp": {"manufacturer": "AVM Berlin", "modelName": "FRITZ!Box 7590 AX", "softwareVersion": "7.57"}})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.client.post("/api/probe/v1/results/gateway", headers=auth, json={"ip": "x"}).status_code, 422)
        gw = gateways.for_site(site)
        self.assertEqual((gw["label"], gw["confidence"], gw["probes"]), ("FRITZ!Box 7590 AX", 95, 1))
        self.assertIn("UPnP/TR-064", gw["sources_text"])
        # Gerät aus dem Netzwerkscan unter dem Gateway
        ins("INSERT INTO net_devices (site_id, dev_key, mac, ip, hostname, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)", (site, "mac:AA:00:00:00:00:01", "AA:00:00:00:00:01", "192.168.178.20",
                                             "drucker-eg", repo.now(), repo.now()))
        self.make_user()
        self.login()
        page = self.client.get(f"/sites/{site}/topologie").get_data(as_text=True)
        for text in ("FRITZ!Box 7590 AX", "Internet", "automatisch aufgebaut", "Weboberfläche öffnen", "7.57",
                     "1 Gerät"):
            self.assertIn(text, page)
        self.assertEqual(self.client.get("/topologie").status_code, 302)      # nur ein Standort: direkt zum Baum
        net = self.client.get(f"/sites/{site}/netzwerk").get_data(as_text=True)
        self.assertIn("Netzwerk", net)
        data = json.loads(q1("SELECT data FROM net_gateway_info")["data"])
        self.assertEqual(data["upnp"]["softwareVersion"], "7.57")
