import base64
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import fetch_vpngate as fv


SAMPLE_VALID_TCP_OVPN = """
client
dev tun
proto tcp
remote public-vpn-100.opengw.net 443
cipher AES-128-CBC
auth SHA1
comp-lzo no
<ca>
-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEB
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA
-----END RSA PRIVATE KEY-----
</key>
"""

SAMPLE_TAP_OVPN = SAMPLE_VALID_TCP_OVPN.replace("dev tun", "dev tap")
SAMPLE_BF_OVPN = SAMPLE_VALID_TCP_OVPN.replace("cipher AES-128-CBC", "cipher BF-CBC")
SAMPLE_LZ4_OVPN = SAMPLE_VALID_TCP_OVPN.replace("comp-lzo no", "compress lz4-v2")
SAMPLE_TLSV2_OVPN = SAMPLE_VALID_TCP_OVPN + "\n<tls-crypt-v2>\nkey\n</tls-crypt-v2>\n"


def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


class TestVpnGateParser(unittest.TestCase):
    def test_valid_tcp_ovpn(self) -> None:
        cfg, err = fv.parse_ovpn_for_mihomo(b64(SAMPLE_VALID_TCP_OVPN), "219.100.37.10")
        self.assertIsNone(err)
        assert cfg is not None
        self.assertEqual(cfg["type"], "openvpn")
        self.assertEqual(cfg["server"], "219.100.37.10")
        self.assertEqual(cfg["port"], 443)
        self.assertEqual(cfg["proto"], "tcp")
        self.assertEqual(cfg["dev"], "tun")
        self.assertEqual(cfg["cipher"], "AES-128-CBC")
        self.assertEqual(cfg["auth"], "SHA1")
        self.assertEqual(cfg["comp-lzo"], "no")

    def test_reject_tap_mode(self) -> None:
        cfg, err = fv.parse_ovpn_for_mihomo(b64(SAMPLE_TAP_OVPN), "219.100.37.11")
        self.assertIsNone(cfg)
        self.assertEqual(err, "unsupported_dev_tap")

    def test_reject_bf_cbc(self) -> None:
        cfg, err = fv.parse_ovpn_for_mihomo(b64(SAMPLE_BF_OVPN), "219.100.37.12")
        self.assertIsNone(cfg)
        self.assertEqual(err, "unsupported_cipher_BF-CBC")

    def test_reject_lz4_compress(self) -> None:
        cfg, err = fv.parse_ovpn_for_mihomo(b64(SAMPLE_LZ4_OVPN), "219.100.37.13")
        self.assertIsNone(cfg)
        self.assertEqual(err, "unsupported_compress_lz4-v2")

    def test_reject_tls_crypt_v2(self) -> None:
        cfg, err = fv.parse_ovpn_for_mihomo(b64(SAMPLE_TLSV2_OVPN), "219.100.37.14")
        self.assertIsNone(cfg)
        self.assertEqual(err, "unsupported_tls_crypt_v2")

    def test_classify_isp_vs_dc_vs_edu(self) -> None:
        self.assertEqual(
            fv.classify_ip_tier({"isp": "NTT Communications", "org": "OCN", "asname": "OCN", "hosting": False})[0],
            "ISP",
        )
        self.assertEqual(
            fv.classify_ip_tier({"isp": "DigitalOcean", "org": "DigitalOcean LLC", "asname": "DIGITALOCEAN-ASN", "hosting": True})[0],
            "DC",
        )
        self.assertEqual(
            fv.classify_ip_tier({"isp": "University of Tsukuba", "org": "University of Tsukuba", "asname": "TSUKUBA-AS", "hosting": False})[0],
            "EDU",
        )

    def test_render_yaml_output(self) -> None:
        csv_data = (
            "*vpn_servers\n"
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
            f"vpn1,219.100.37.10,900000,15,50000000,Japan,JP,10,1000,100,100000,2weeks,Volunteer,,{b64(SAMPLE_VALID_TCP_OVPN)}\n"
            f"vpn2,219.100.37.11,800000,20,40000000,Japan,JP,5,1000,50,100000,2weeks,Volunteer,,{b64(SAMPLE_TAP_OVPN)}\n"
            "*\n"
        )
        opener = fv.build_opener(None)
        nodes, stats = fv.process_vpngate_csv(csv_data, opener=opener, skip_ip_api=True)
        self.assertEqual(stats["total_rows"], 2)
        self.assertEqual(stats["compatible"], 1)
        self.assertEqual(stats["reject_unsupported_dev_tap"], 1)
        yaml_text = fv.render_proxies_yaml(nodes, ["test header"])
        self.assertIn("type: openvpn", yaml_text)
        self.assertIn("server: 219.100.37.10", yaml_text)
        self.assertIn("-----BEGIN CERTIFICATE-----", yaml_text)


if __name__ == "__main__":
    unittest.main()
