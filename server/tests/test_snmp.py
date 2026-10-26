"""SNMP-Client: Schlüssel, BER, v1/v2c/v3 gegen den falschen Agenten."""
import threading
import time
import unittest

from wachtl import snmp
from wachtl.snmp import Credentials, Session, SnmpAuthError, SnmpError, SnmpTimeout

from .snmp_agent import Counter32, Counter64, FakeAgent, Gauge32, IpAddress, Oid, Opaque, TimeTicks

SYS = "1.3.6.1.2.1.1"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
MIB = {
    "1.3.6.1.2.1.1.1.0": b"Fake Switch 1.0",
    "1.3.6.1.2.1.1.2.0": Oid("1.3.6.1.4.1.9.1.1"),
    "1.3.6.1.2.1.1.3.0": TimeTicks(123456),
    "1.3.6.1.2.1.1.5.0": b"sw-core",
    "1.3.6.1.2.1.1.7.0": 72,
    "1.3.6.1.2.1.4.20.1.1.10.0.0.1": IpAddress("10.0.0.1"),
    "1.3.6.1.2.1.31.1.1.1.6.1": Counter64(2**64 - 1),
    "1.3.6.1.2.1.2.2.1.10.1": Counter32(4294967295),
    "1.3.6.1.2.1.2.2.1.5.1": Gauge32(1000000000),
    "1.3.6.1.2.1.99.1.0": -5,
    "1.3.6.1.2.1.99.2.0": Opaque(b"\x9f\x78\x04"),
    **{f"{IF_DESCR}.{i}": f"Port {i}".encode() for i in range(1, 151)},
}
EID = bytes(11) + b"\x02"


def v3(user, auth="none", akey="", priv="none", pkey=""):
    return Credentials(version="3", user=user, auth_proto=auth, auth_key=akey, priv_proto=priv, priv_key=pkey)


class KeyTest(unittest.TestCase):
    def test_rfc3414_a3(self):
        self.assertEqual(snmp._auth_key("md5", b"maplesyrup", EID).hex(), "526f5eed9fcce26f8964c2930787d82b")
        self.assertEqual(snmp._auth_key("sha", b"maplesyrup", EID).hex(), "6695febc9288e36282235fc7151f128497b38f3f")

    def test_sha2_and_extension(self):
        # Gegengeprüft mit pysnmp 7.1 (localkey, eso.priv.aes192/aes256 Blumenthal bzw. Reeder)
        self.assertEqual(snmp._auth_key("sha224", b"maplesyrup", EID).hex(),
                         "0bd8827c6e29f8065e08e09237f177e410f69b90e1782be682075674")
        self.assertEqual(snmp._auth_key("sha256", b"maplesyrup", EID).hex(),
                         "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b")
        self.assertEqual(snmp._auth_key("sha512", b"maplesyrup", EID).hex()[:32], "22a5a36cedfcc085807a128d7bc6c238")
        self.assertEqual(snmp._priv_key("md5", "aes256", b"maplesyrup", EID).hex(),
                         "526f5eed9fcce26f8964c2930787d82bfa24a92467426c2f4b09192be10dfaec")
        self.assertEqual(snmp._priv_key("md5", "aes256c", b"maplesyrup", EID).hex(),
                         "526f5eed9fcce26f8964c2930787d82b79eff44a90650ee0a3a40abfac5acc12")
        self.assertEqual(snmp._priv_key("sha", "aes192", b"maplesyrup", EID).hex(),
                         "6695febc9288e36282235fc7151f128497b38f3f505e07eb")
        self.assertEqual(snmp._priv_key("sha", "aes192c", b"maplesyrup", EID).hex(),
                         "6695febc9288e36282235fc7151f128497b38f3f9b8b6d78")
        self.assertEqual(len(snmp._priv_key("sha", "des", b"maplesyrup", EID)), 16)

    def test_cipher_roundtrip(self):
        for priv in snmp.PRIV_PROTOCOLS[1:]:
            key = snmp._priv_key("sha256", priv, b"geheim123", EID)
            data = b"\x30\x03\x02\x01\x05"
            enc, params = snmp._encrypt(priv, key, 3, 4711, 99, data)
            self.assertEqual(snmp._decrypt(priv, key, 3, 4711, params, enc)[:5], data)


class BerTest(unittest.TestCase):
    def roundtrip(self, encoded):
        tag, s, e = snmp._tlv_at(encoded, 0, len(encoded))
        self.assertEqual(e, len(encoded))
        return snmp._dec_value(tag, encoded[s:e])

    def test_values(self):
        for v in (0, 1, 127, 128, 255, 256, -1, -128, -129, -32768, 2**31 - 1, -2**31):
            self.assertEqual(self.roundtrip(snmp._int(v)), v)
        self.assertEqual(snmp._int(128), b"\x02\x02\x00\x80")
        self.assertEqual(snmp._int(-129), b"\x02\x02\xff\x7f")
        self.assertEqual(self.roundtrip(snmp._uint(2**64 - 1, 0x46)), 2**64 - 1)
        self.assertEqual(snmp._uint(2**32 - 1, 0x41), b"\x41\x05\x00\xff\xff\xff\xff")
        big = bytes(range(256)) * 300
        self.assertEqual(snmp._tlv(4, big)[:5], b"\x04\x83\x01\x2c\x00")
        self.assertEqual(self.roundtrip(snmp._tlv(4, big)), big)
        self.assertEqual(self.roundtrip(snmp._tlv(0x40, bytes([10, 0, 0, 1]))), "10.0.0.1")
        for v in (b"\x80\x00", b"\x81\x00", b"\x82\x00", snmp.NULL):
            self.assertIsNone(self.roundtrip(v))

    def test_oids(self):
        for text in ("1.3.6.1.2.1.1.5.0", "1.3.6.1.4.1.4294967295.268435456.128.127", "2.999.3", "0.0"):
            oid = snmp.parse_oid(text)
            self.assertEqual(self.roundtrip(snmp._oid(oid)), text)
        self.assertEqual(snmp._oid((1, 3, 6, 1)), b"\x06\x03\x2b\x06\x01")
        self.assertEqual(snmp.parse_oid(".1.3.6"), (1, 3, 6))
        self.assertEqual(snmp.format_oid((1, 3, 6)), "1.3.6")
        for bad in ("", "1", "1.3.x", "3.1", "1.40", "1..3", "-1.3"):
            with self.assertRaises(SnmpError):
                snmp.parse_oid(bad)

    def test_malformed(self):
        for junk in (b"", b"\x30", b"\x30\x05\x02", b"\x30\x84\xff\xff\xff\xff", b"\x1f\x01\x00", b"\x30\x85\x01"):
            with self.assertRaises(ValueError):
                snmp._top(junk)
        with self.assertRaises(ValueError):
            snmp._dec_oid(b"\x2b\x86")
        with self.assertRaises(ValueError):
            snmp._parse_v3(snmp._tlv(0x30, snmp._int(3)))

    def test_credentials(self):
        for creds, text in ((Credentials(version="4"), "Version"), (v3(""), "Benutzername"),
                            (v3("u", "sha", "kurz"), "mindestens 8"), (v3("u", "sha", "12345678", "aes", "x"), "mindestens 8"),
                            (v3("u", "none", "", "aes", "12345678"), "setzt eine Anmeldung"),
                            (v3("u", "sha3", "12345678"), "Auth-Verfahren"), (v3("u", "sha", "12345678", "3des", "12345678"), "Priv")):
            with self.assertRaises(SnmpError) as cm:
                Session("127.0.0.1", creds)
            self.assertIn(text, str(cm.exception))
        with self.assertRaises(SnmpError):
            Session("host.invalid", Credentials())


class AgentTestCase(unittest.TestCase):
    agent_args: dict = {}

    def setUp(self):
        self.agent = FakeAgent(MIB, **self.agent_args).start()
        self.addCleanup(self.agent.stop)

    def session(self, creds=Credentials(), timeout=1.0, retries=0):
        s = Session("127.0.0.1", creds, port=self.agent.port, timeout=timeout, retries=retries)
        self.addCleanup(s.close)
        return s


class V1V2Test(AgentTestCase):
    agent_args = {"users": {}}

    def test_v2c_get_types(self):
        r = self.session().get(["1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.7.0",
                                "1.3.6.1.2.1.4.20.1.1.10.0.0.1", "1.3.6.1.2.1.31.1.1.1.6.1", "1.3.6.1.2.1.2.2.1.10.1",
                                "1.3.6.1.2.1.2.2.1.5.1", "1.3.6.1.2.1.99.1.0", "1.3.6.1.2.1.99.2.0", "1.3.6.1.2.1.1.9.0"])
        self.assertEqual(r, {"1.3.6.1.2.1.1.5.0": b"sw-core", "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.9.1.1",
                             "1.3.6.1.2.1.1.3.0": 123456, "1.3.6.1.2.1.1.7.0": 72,
                             "1.3.6.1.2.1.4.20.1.1.10.0.0.1": "10.0.0.1", "1.3.6.1.2.1.31.1.1.1.6.1": 2**64 - 1,
                             "1.3.6.1.2.1.2.2.1.10.1": 4294967295, "1.3.6.1.2.1.2.2.1.5.1": 1000000000,
                             "1.3.6.1.2.1.99.1.0": -5, "1.3.6.1.2.1.99.2.0": b"\x9f\x78\x04", "1.3.6.1.2.1.1.9.0": None})

    def test_v2c_get_many_chunks(self):
        before = self.agent.requests
        r = self.session().get([f"{IF_DESCR}.{i}" for i in range(1, 46)])
        self.assertEqual(r[f"{IF_DESCR}.45"], b"Port 45")
        self.assertEqual(self.agent.requests - before, 3)

    def test_v2c_walk(self):
        s = self.session()
        rows = s.walk(IF_DESCR)
        self.assertEqual(len(rows), 150)
        self.assertEqual(rows[0], (f"{IF_DESCR}.1", b"Port 1"))
        self.assertEqual(rows[-1], (f"{IF_DESCR}.150", b"Port 150"))
        self.assertEqual([k for k, _ in s.walk(SYS)], ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.3.0",
                                                       "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.7.0"])
        self.assertEqual(len(s.walk(IF_DESCR, max_rows=30, bulk=7)), 30)
        self.assertEqual(s.walk("1.3.6.1.2.1.99.2.0"), [])
        self.assertEqual(s.walk("1.3.6.1.2.1.99"), [("1.3.6.1.2.1.99.1.0", -5), ("1.3.6.1.2.1.99.2.0", b"\x9f\x78\x04")])
        self.assertEqual(s.walk("1.9"), [])                # hinter dem Ende: endOfMibView

    def test_v1(self):
        s = self.session(Credentials(version="1"))
        r = s.get(["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.9.0", "1.3.6.1.2.1.31.1.1.1.6.1", "1.3.6.1.2.1.1.7.0"])
        self.assertEqual(r, {"1.3.6.1.2.1.1.5.0": b"sw-core", "1.3.6.1.2.1.1.9.0": None,
                             "1.3.6.1.2.1.31.1.1.1.6.1": None, "1.3.6.1.2.1.1.7.0": 72})
        self.assertEqual(s.get(["1.3.6.1.2.1.1.9.0"]), {"1.3.6.1.2.1.1.9.0": None})
        self.assertEqual(len(s.walk(IF_DESCR)), 150)
        self.assertEqual(s.walk("1.3.6.1.2.1.99"), [("1.3.6.1.2.1.99.1.0", -5), ("1.3.6.1.2.1.99.2.0", b"\x9f\x78\x04")])
        self.assertEqual(s.walk("1.3.6.1.2.1.31"), [])     # Counter64 gibt es in v1 nicht
        self.assertEqual(s.walk("1.9"), [])                # noSuchName am Ende

    def test_wrong_community_and_disabled_version(self):
        t0 = time.monotonic()
        with self.assertRaises(SnmpTimeout) as cm:
            self.session(Credentials(community="falsch"), timeout=0.2).get(["1.3.6.1.2.1.1.5.0"])
        self.assertIn("Zeitüberschreitung", str(cm.exception))
        self.assertLess(time.monotonic() - t0, 1.0)
        self.agent.v1 = False
        with self.assertRaises(SnmpTimeout):
            self.session(Credentials(version="1"), timeout=0.2).get(["1.3.6.1.2.1.1.5.0"])

    def test_retries(self):
        self.agent.drop = True
        before = self.agent.requests
        with self.assertRaises(SnmpTimeout):
            self.session(timeout=0.1, retries=2).get(["1.3.6.1.2.1.1.5.0"])
        self.assertEqual(self.agent.requests - before, 3)

    def test_context_manager_and_threads(self):
        results, errors = [], []

        def work():
            try:
                with Session("127.0.0.1", Credentials(), port=self.agent.port, timeout=2) as s:
                    results.append(len(s.walk(IF_DESCR)))
            except Exception as e:                     # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=work) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual((results, errors), ([150] * 6, []))


class JunkTest(AgentTestCase):
    agent_args = {"junk": True, "users": {"u": ("sha", "authpass1", "aes", "privpass1")}}

    def test_junk_ignored(self):
        self.assertEqual(self.session().get(["1.3.6.1.2.1.1.5.0"])["1.3.6.1.2.1.1.5.0"], b"sw-core")
        self.assertEqual(len(self.session(Credentials(version="1")).walk(SYS)), 5)
        self.assertEqual(len(self.session(v3("u", "sha", "authpass1", "aes", "privpass1")).walk(SYS)), 5)

    def test_only_junk(self):
        self.agent.drop = True
        for creds in (Credentials(), v3("u", "sha", "authpass1", "aes", "privpass1")):
            with self.assertRaises(SnmpTimeout):
                self.session(creds, timeout=0.2).get(["1.3.6.1.2.1.1.5.0"])


class BulkTest(AgentTestCase):
    agent_args = {"bulk_limit": 6}

    def test_too_big_halves(self):
        self.assertEqual(len(self.session().walk(IF_DESCR, bulk=50)), 150)

    def test_non_increasing(self):
        def answer(tag, a, b, vbs, v1):                # Agent liefert immer dieselbe OID
            return 0, 0, [(snmp.parse_oid(f"{IF_DESCR}.1"), b"\x04\x00")] * 3

        self.agent.answer = answer
        self.assertEqual(self.session().walk(IF_DESCR), [(f"{IF_DESCR}.1", b"")])

    def test_error_status(self):
        self.agent.answer = lambda tag, a, b, vbs, v1: (5, 1, [])
        with self.assertRaises(SnmpError) as cm:
            self.session().get(["1.3.6.1.2.1.1.5.0"])
        self.assertIn("genErr", str(cm.exception))


USERS = {f"{a}-{p}": (a, f"auth-{a}-pw", p, f"priv-{p}-pw" if p != "none" else "")
         for a in snmp.AUTH_PROTOCOLS[1:] for p in snmp.PRIV_PROTOCOLS}
USERS["noauth"] = ("none", "", "none", "")


class V3Test(AgentTestCase):
    agent_args = {"users": USERS, "boots": 7}

    def creds(self, name):
        a, ak, p, pk = USERS[name]
        return v3(name, a, ak, p, pk)

    def test_all_protocols(self):
        for name in USERS:
            with self.subTest(name):
                s = self.session(self.creds(name))
                r = s.get(["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.9.0", "1.3.6.1.2.1.31.1.1.1.6.1"])
                self.assertEqual(r, {"1.3.6.1.2.1.1.5.0": b"sw-core", "1.3.6.1.2.1.1.9.0": None,
                                     "1.3.6.1.2.1.31.1.1.1.6.1": 2**64 - 1})
                self.assertEqual(s.engine_id, self.agent.engine_id)
        s = self.session(self.creds("sha512-aes256c"))
        self.assertEqual(len(s.walk(IF_DESCR, bulk=40)), 150)
        self.assertEqual(self.agent.errors, [])

    def test_auth_errors(self):
        cases = ((v3("nobody", "sha", "12345678"), "unbekannt"),
                 (v3("sha-none", "sha", "falschespw"), "Auth"),
                 (v3("sha-none", "md5", "auth-sha-pw"), "Auth"),
                 (v3("sha-aes", "sha", "auth-sha-pw", "aes", "falschespw"), "Verschlüsselung (Priv)"),
                 (v3("sha-aes", "sha", "auth-sha-pw", "des", "priv-aes-pw"), "Verschlüsselung (Priv)"),
                 (v3("sha-aes", "sha", "auth-sha-pw"), "Sicherheitsstufe"),
                 (v3("noauth", "sha", "12345678"), "Sicherheitsstufe"))
        for creds, text in cases:
            with self.subTest(creds.user), self.assertRaises(SnmpAuthError) as cm:
                self.session(creds).get(["1.3.6.1.2.1.1.5.0"])
            self.assertIn(text, str(cm.exception))

    def test_time_window_resync(self):
        s = self.session(self.creds("sha256-aes"))
        s.get(["1.3.6.1.2.1.1.5.0"])
        self.agent.reboot()                            # boots + 1 → notInTimeWindow, dann neuer Versuch
        self.assertEqual(s.get(["1.3.6.1.2.1.1.5.0"])["1.3.6.1.2.1.1.5.0"], b"sw-core")
        self.agent.time_offset = 5000                  # Uhr springt
        self.assertEqual(s.get(["1.3.6.1.2.1.1.5.0"])["1.3.6.1.2.1.1.5.0"], b"sw-core")
        self.assertEqual(s._boots, 8)
        self.agent.engine_id = b"\x80\x00\x00\x00\x01neu"      # Engine-ID gewechselt → neue Erkennung
        self.assertEqual(s.get(["1.3.6.1.2.1.1.5.0"])["1.3.6.1.2.1.1.5.0"], b"sw-core")
        self.assertEqual(s.engine_id, b"\x80\x00\x00\x00\x01neu")

    def test_v3_disabled(self):
        self.agent.users = None
        with self.assertRaises(SnmpTimeout):
            self.session(self.creds("noauth"), timeout=0.2).get(["1.3.6.1.2.1.1.5.0"])


if __name__ == "__main__":
    unittest.main()
