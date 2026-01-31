import json
import unittest

if __name__ == "__main__":
    if __package__ is None:
        import sys
        from os import path

        sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
        from protocol import _request_payload, _response_json
    else:
        from .protocol import _request_payload, _response_json


def to_hex(buf):
    return f"{''.join(format(b, '02x') for b in buf)}"


class DahuaPOE_local_post1_request(unittest.TestCase):

    def test_keepAlive(self):
        payload = _request_payload(
            0x3C,
            0,
            "thing.service.keepAlive",
            {"active": False, "clientID": "1E5D9E98BFE0A42B8F89B9807543E425"},
        )
        self.assertEqual(
            to_hex(payload),
            "74e00139003c0000000000000000000400010328033404203145354439453938424645304134324238463839423938303735343345343235f2",
        )

    def test_getSupportLanguageList(self):
        payload = _request_payload(
            2, 0, "thing.service.getSupportLanguageList", {"offset": 0, "len": 13}
        )
        self.assertEqual(
            to_hex(payload), "74e0011a0002000000000000000000040000ce24050024060dfd"
        )

    def test_tspGetDeviceCaps(self):
        payload = _request_payload(4, 0, "thing.service.tspGetDeviceCaps", None)
        self.assertEqual(to_hex(payload), "74e0011400040000000000000000000400002d4a")

    def test_property_get_1(self):
        payload = _request_payload(
            6,
            0,
            "thing.service.property.get",
            ["vendor", "tspWizardFinishFlag", "language"],
        )
        self.assertEqual(
            to_hex(payload),
            "74e0011d0006000000000000000000040000013e02002500ca00271c63",
        )

    def test_setPoePortCfgBatch(self):
        payload = _request_payload(
            0x2A,
            0,
            "thing.service.setPoePortCfgBatch",
            {
                "poePortInfo": [
                    {
                        "poePortCfg": {
                            "poeEnable": 1,
                            "longDistanceEnable": 0,
                            "watchDogEnable": 0,
                            "forcePoeEnable": 0,
                            "enhancedPoeEnable": 0,
                        },
                        "poePortListInfo": ["0000000000000110000000000000"],
                    }
                ]
            },
        )
        self.assertEqual(
            to_hex(payload),
            "74e00135002a0000000000000000000400012c3e011d3d022401012402002403002405002404001f5e010c0504000600001c1f1c82",
        )


class DahuaPOE_local_post1_response(unittest.TestCase):

    # print(json.dumps(data))

    def test_keepAlive(self):
        data = _response_json(
            bytes.fromhex(
                "74e0011e003400000000000000000084010000000001034201700000008d"
            )
        )
        self.assertEqual(
            json.dumps(data),
            '{"result": 1879048192}',
        )

    def test_getSupportLanguageList(self):
        data = _response_json(
            bytes.fromhex(
                "74e0012900020b290bd8d24008000084010000000000ce4002015e031403456e671c420170000000f0"
            )
        )
        self.assertEqual(
            json.dumps(data),
            '{"total": 1, "languageList": ["Eng"], "result": 1879048192}',
        )

    def test_tspGetDeviceCaps(self):
        data = _response_json(
            bytes.fromhex(
                "74e001d70100040b290bd8d240080000840100000000002d4005005d01480148024805480d480e4810481448174818481b49044916491549074908490a490b490c490f4911491a491c491d491348124c190200004c1e02000248061f5d04480249114803480448054806480748084809480a480b480c480e480f4810481249011f5d02480348044805480748084809480a480b480c480e48014802480d1f5d0349014806480748084809480a480b480c49044905490249031f5d0848014902490349041f480a490c480d410b0bb8480f420670000000bb"
            )
        )
        self.assertEqual(
            json.dumps(data),
            '{"numberOfConcurrency": 0, "common": {"utc": false, "systemTime": false, "SSH": false, "cpuInfo": false, "memoryInfo": false, "ftp": false, "ipRoute": false, "TLS": false, "vlanInterface": false, "ntp": false, "log": true, "arpTable": true, "macTable": true, "cloudUpgrader": true, "devInfo": true, "userManager": true, "configCloudBackup": true, "reset": true, "portManager": true, "vlan": true, "eventPeriodicReportCap": true, "poePowerQuery": true, "upLink": true, "poe": true, "linkAggregation": false, "oneClickDetect": "00000000", "actualStatusOfData": "00000010", "telnet": false}, "protocolL1L2": {"STP": false, "loopDetection": true, "DHCPRelay": false, "DHCPSNOOPING": false, "ERPS": false, "OSPF": false, "HWPing": false, "BFD": false, "ISIS": false, "MFF": false, "ECMP": false, "MVRP": false, "QINQ": false, "RRPP": false, "VPLS": false, "MSTP": false, "LLDP": true}, "protocolL3L4": {"L2TP": false, "IPSec": false, "DHCPServer": false, "radius": false, "VRRP": false, "RIP": false, "BGP": false, "MPLS": false, "MSDP": false, "PIM": false, "SNMP": false, "DNS": false, "IGMP": false}, "securityControl": {"ACL": true, "firewall": false, "blackHoleMAC": false, "policyRouting": false, "portal": false, "EAD": false, "802_1x": false, "VPN": false, "portSpeedLimiting": true, "stormSuppression": true, "portIsolation": true, "portMirroring": true}, "alarm": {"ipConflict": false, "loopback": true, "portCongestion": true, "portPlug": true}, "openSourceLicense": false, "supportCloud": true, "supportInfoCode": false, "upgradePollTime": 3000, "supportWeakPwdCheck": false, "result": 1879048192}',
        )

    def test_tspGetDeviceCaps(self):
        data = _response_json(
            bytes.fromhex(
                "74e0012500060b290bd8d2400800008401000000000001542502444849ca542703456e6701"
            )
        )
        self.assertEqual(
            json.dumps(data),
            '{"vendor": "DH", "tspWizardFinishFlag": true, "language": "Eng"}',
        )

    def test_setPoePortCfgBatch(self):
        data = _response_json(
            bytes.fromhex(
                "74e0011e002a000000000000000000840100000000012c420170000000ac"
            )
        )
        self.assertEqual(json.dumps(data), '{"result": 1879048192}')


if __name__ == "__main__":
    unittest.main(verbosity=2)
