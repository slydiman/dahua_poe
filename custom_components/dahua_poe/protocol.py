import base64
import collections.abc
import json
import numbers
import random
import requests
import socket
import struct
import urllib.parse
from math import log
from hashlib import sha256, md5

try:
    from .const import LOGGER
except ImportError:
    import logging

    logging.basicConfig()
    LOGGER = logging.getLogger("tests")
    LOGGER.setLevel(logging.DEBUG)


_USER_AGENT = "Mozilla/5.0 (Linux; Android 12)"
# _USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"


def DahuaPOE_local_get(ip: str, uid: str, url: str):
    LOGGER.debug(f"DahuaPOE_local_get({ip}, {uid}, {url})...")

    headers = {
        "Connection": "close",
        "User-Agent": _USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
    }
    if uid:
        headers["Cookie"] = f"sessionID={uid}"
        headers["X-Cookie"] = f"sessionID={uid}"

    try:
        response = requests.get(
            f"http://{ip}{url}", headers=headers, verify=False, timeout=(5, 5)
        )
    except Exception as e:
        LOGGER.error(f"DahuaPOE_local_get({ip}, {uid}, {url}): {str(e)}")
        return None, None

    if response.status_code != requests.codes.ok:
        LOGGER.warning(
            f"DahuaPOE_local_get({ip}, {uid}, {url}): HTTP {response.status_code}: {response.reason}: {response.text}"
        )
        return None, response.text

    LOGGER.debug(f"DahuaPOE_local_get({ip}, {uid}, {url}): {response.text}")
    return response.text, None


def DahuaPOE_local_post(ip: str, uid: str, url: str, data):
    LOGGER.debug(f"DahuaPOE_local_post({ip}, {uid}, {url}, {data})...")

    headers = {
        "Connection": "close",
        "User-Agent": _USER_AGENT,
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en",
    }
    if uid:
        headers["Cookie"] = f"sessionID={uid}"
        headers["X-Cookie"] = f"sessionID={uid}"

    try:
        # Dahua web server expect headers and payload in the same packet!!!

        # response = requests.post(
        #    f"http://{ip}{url}",
        #    headers=headers,
        #    data={"params": data},
        #    verify=False,
        #    timeout=(5, 5),
        # )

        resp = ""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            server_address = (ip, 80)
            sock.connect(server_address)

            hdr_lines = ""
            for h in headers.items():
                hdr_lines += f"{h[0]}: {h[1]}\r\n"

            payload = urllib.parse.urlencode({"params": data})

            request = f"POST {url} HTTP/1.1\r\nHost: {ip}\r\nContent-Length: {len(payload)}\r\n{hdr_lines}\r\n{payload}"
            LOGGER.debug(
                f"DahuaPOE_local_post({ip}, {uid}, {url}, {data}): request: {request}"
            )
            sock.sendall(request.encode("utf-8"))

            while True:
                data = sock.recv(1024)
                if not data:
                    break
                resp += data.decode("utf-8")

        LOGGER.debug(
            f"DahuaPOE_local_post({ip}, {uid}, {url}, {data}): response: {resp}"
        )
        resp = resp.split("\r\n")
        code = resp[0].split(" ")
        if len(code) < 3 or code[0] != "HTTP/1.1":
            return None, "Invalid response"
        response_status_code = int(code[1])
        response_reason = " ".join(code[2:])

        response_text = None
        sessionID = None
        for line in resp:
            if response_text is None:
                if len(line) == 0:
                    response_text = ""
                elif line.startswith("Set-Cookie:"):
                    cookie = line[11:]
                    id = cookie.find("sessionID=")
                    if id >= 0:
                        sessionID = cookie[id + 10 :]
            else:
                response_text += line + "\r\n"

    except Exception as e:
        LOGGER.error(f"DahuaPOE_local_post({ip}, {uid}, {url}): {str(e)}")
        return None, None

    if response_status_code != requests.codes.ok:
        LOGGER.warning(
            f"DahuaPOE_local_post({ip}, {uid}, {url}): HTTP {response_status_code}: {response_reason}: {response_text}"
        )
        return None, response_text

    # res = response.text if uid else response.cookies.get_dict().get("sessionID", None)
    res = response_text if uid else sessionID
    LOGGER.debug(f"DahuaPOE_local_post({ip}, {uid}, {url}, {data}): {res}")
    return res, None


def DahuaPOE_local_login(ip: str, password: str):
    c, err = DahuaPOE_local_get(ip, None, "/get_challenge.cgi?params=admin")
    if c is None:
        return None, err or "invalid_ip"

    c = c.split("/")
    l = len(c)
    e = c[3] if l > 3 else "md5"
    o = c[2] if l > 2 else None
    t = c[1] if l > 1 else None
    i = c[0]
    if e == "sha256":
        e = sha256(f"admin:{password}:{i}".encode("utf-8")).hexdigest().upper()
        e = sha256(f"{t}:{e}".encode("utf-8")).hexdigest().upper()
        n = sha256(f"admin:{i}:{password}".encode("utf-8")).hexdigest().upper()
        n = (
            ""
            if o == "0"
            else "/" + sha256(f"{t}:{n}".encode("utf-8")).hexdigest().upper()
        )
    else:
        e = md5(f"admin:{password}:{i}".encode("utf-8")).hexdigest().upper()
        e = md5(f"{t}:{e}".encode("utf-8")).hexdigest().upper()
        n = md5(f"admin:{i}:{password}".encode("utf-8")).hexdigest().upper()
        n = (
            ""
            if o == "0"
            else "/" + md5(f"{t}:{n}".encode("utf-8")).hexdigest().upper()
        )

    uid, err = DahuaPOE_local_post(ip, None, "/login.cgi", f"admin/{e}{n}")
    if uid is None:
        if err is None or err == "":
            err = "login_failed"
        else:
            e = err.split("/")
            if e[2] == "1":
                LOGGER.warning(
                    f"DahuaPOE_local_login({ip}): Number of session connections exceeds limit"
                )
                err = "sessions_limit"
            elif e[0] != "0":
                LOGGER.warning(
                    f"DahuaPOE_local_login({ip}): Invalid password ({e[0]} retries)"
                )
                err = "invalid_password"
            else:
                LOGGER.warning(
                    f"DahuaPOE_local_login({ip}): Invalid password (locked for {e[1]} sec)"
                )
                err = "invalid_password_lock"
        return None, err
    LOGGER.debug(f"DahuaPOE_local_login({ip}): uid={uid}")
    return uid, None


_URL_LOGIN1 = "/things/v1/login"
_USERNAME = "admin"


def DahuaPOE_local_login1_get(ip: str, username: str, digest=None, url=_URL_LOGIN1):
    LOGGER.debug(f"DahuaPOE_local_login1_get({ip}, {username}, {digest}, {url})...")

    headers = {
        "Connection": "close",
        "User-Agent": _USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
    }
    if digest:
        digest_str = f"Digest username=\"{username}\",realm=\"{digest['realm']}\",nonce=\"{digest['nonce']}\",uri=\"{url}\",algorithm=\"{digest['algorithm']}\",response=\"{digest['pwd']}\",opaque=\"{digest['opaque']}\",qop={digest['qop']},nc={digest['nc']},cnonce=\"{digest['cnonce']}\""
        if "response2" in digest:
            digest_str += f",response2=\"{digest['response2']}\""
        headers["Authorization"] = digest_str
    else:
        headers["Custom-Authenticate"] = "a"
        headers["Username"] = username

    try:
        response = requests.get(
            f"http://{ip}{url}", headers=headers, verify=False, timeout=(5, 5)
        )
    except Exception as e:
        LOGGER.error(
            f"DahuaPOE_local_login1_get({ip}, {username}, {digest}, {url}): {str(e)}"
        )
        return None, None

    if response.status_code == requests.codes.unauthorized:
        digest = response.headers.get("Custom-Authenticate", None)
        if digest:
            if digest.startswith("Digest "):
                digest = digest[7:]
            digest_params = digest.split(",")
            digest = {}
            for param in digest_params:
                kv = param.split("=")
                if len(kv) > 1:
                    digest[kv[0].lower()] = kv[1].strip('"')
            LOGGER.debug(
                f"DahuaPOE_local_login1_get({ip}, {username}, {digest}, {url}): {digest}"
            )
            return None, digest

        LOGGER.warning(
            f"DahuaPOE_local_login1_get({ip}, {username}, {digest}, {url}): HTTP {response.status_code}: {response.reason}: {response.headers} {response.text}"
        )
        return None, None

    elif response.status_code != requests.codes.ok:
        LOGGER.warning(
            f"DahuaPOE_local_login1_get({ip}, {username}, {digest}, {url}): HTTP {response.status_code}: {response.reason}: {response.text}"
        )
        return None, None

    try:
        j = json.loads(response.text)
    except Exception as e:
        LOGGER.error(
            f"DahuaPOE_local_login1_get({ip}, {username}, {digest}, {url}): HTTP {response.status_code}: {response.reason}: {response.text}"
        )
        return None, None

    LOGGER.debug(f"DahuaPOE_local_login1_get({ip}, {username}, {digest}, {url}): {j}")
    return j, None


_ERRORS = {
    0x70000000: "OK",
    1879048193: "com.InputInvalid",
    1894713611: "net.EnablePortFail",
    1894715905: "com.GetVlanFailTip",
    1894715913: "com.AggregatePortFailTip",
    1894715915: "com.SetPvidFailedTip",
    1894715916: "com.VlanModeNotSupportTip",
    1894715930: "com.VlanNotExistTip",
    1894715940: "com.DefaultVlanCantDelTip",
    1894715942: "com.VLANRepeatTip",
    1894711848: "com.StaticMacMaxTip",
    1894711847: "net.MACHasExisted",
    671485195: "net.MACNotExist",
    671485199: "com.MacMaxTip",
    1894714625: "com.MacMaxTip",
    1894715659: "com.LoopDeteWithIGMPConflictTip",
    1894711840: "com.AggrWithMirrorConflictTip",
    1894711841: "com.AggrWithLimitConflictTip",
    1894714370: "com.PortIsolationWithLoopConfictTip",
    1894711842: "com.AggrWithStormConfictTip",
    1894711843: "com.PortIsolationWithAggrConfictTip",
    1879113736: "com.DeviceInitializedAlready",
    1894711809: "com.AggregationNotExistTip",
    1894711810: "com.AggregationPortNotExistTip",
    1894711811: "com.AggregationMaxTip",
    1894711812: "com.AggregationPortMaxTip",
    1894711813: "com.BalanceNotChooseTip",
    1894711814: "com.DHCPv4ConflictsTip",
    1894711815: "com.PortIsInMirrorGroupTip",
    1894711816: "com.PortIsErpsTip",
    1894711817: "com.PortIsTapTip",
    1894711818: "com.PortIsOpenflowTip",
    1894711819: "com.PortIsAclRedirectPortTip",
    1894711820: "com.PortHasBoundAclTip",
    1894711821: "com.PortHasBoundQosTip",
    1894711822: "com.PortModeInconsistentTip",
    1894711823: "com.PortIsInAnotherGroupTip",
    1894711824: "com.PortIsMirrorDestPortTip",
    1894711825: "com.PortEnableSflowTip",
    1894711826: "com.PortEnableOpenflowTip",
    1894711827: "com.PortEnableDhcpSnoopingTip",
    1894711828: "net.AggregationPortConfiguredMirror",
    1894711829: "net.MirrorNotJoinAggregation",
    1894711830: "net.AlgorithmAcquisitionFailed",
    1894711831: "net.AlgorithmNotSupported",
    1894711832: "com.VLANFilConflictAgg",
    1894711833: "net.AggregationMemberVLANsDifferent",
    1894711834: "com.AggregationNotExistTip",
    1894711835: "com.PortIsolationWithAggrConfictTip",
    1894711836: "net.AggregationMemberVLANsDifferent",
    1894711837: "com.MacFilConflictAgg",
    1894711838: "com.StormWithAggregationConflictTip",
    1894711839: "com.PortModeInconsistentTip",
    1894711844: "com.LimitWithAggrConflictTip",
    1894713609: "com.SpeedNotSupportTip",
    1894713622: "net.RateDuplexEEETip",
    1894715954: "net.ManageVlanNotDelete",
    1894715956: "net.ManageVlanWithoutPortTip",
    1894715957: "net.ManageVlanWithoutPortTip",
    1894715958: "net.VlanConflict",
    1894715959: "net.VlanConflict",
    1894713616: "com.BlockPortLimitFailTip",
    1894713617: "com.PortConfigurationFailTip",
    1894715917: "net.PortInvalid",
    1894715649: "com.DelayTimeInvalidTip",
    1894715651: "com.AgeingTimeInvalidTip2",
    1879048196: "com.PasswordStrengthRequire",
    1894713626: "net.FiberEEETip",
    671486464: "net.UnknowError",
    1894713624: "com.DownNoVCT",
    1894713625: "com.NoSupportVCT",
    1894713623: "com.ComboNoVCT",
    1879048194: "com.PasswordNoTureTip",
    1879048195: "com.LockedTryAgain",
    1879048236: "sys.SessionNumOverLimit",
}


def DahuaPOE_local_login1(ip: str, password: str):
    _, digest = DahuaPOE_local_login1_get(ip, _USERNAME)
    if digest is None:
        return None, "invalid_ip"

    algorithm = digest.get("algorithm", None)
    qop = digest.get("qop", None)
    realm = digest.get("realm", None)
    nonce = digest.get("nonce", None)

    if (
        algorithm not in ["sha256", "Default", "MD5", "MD5-D", "DigestMD5-D"]
        or qop is None
        or realm is None
        or nonce is None
    ):
        LOGGER.error(f"DahuaPOE_local_login1({ip}): Invalid digest {digest}")
        return None, "unknown"

    url = f"GET:{_URL_LOGIN1}"

    a = "00000001"
    n = ""
    for i in range(16):
        n += chr(ord("0") + random.randrange(10))

    digest["nc"] = a
    digest["cnonce"] = n

    if algorithm == "sha256":
        p = (
            sha256(f"{_USERNAME}:{realm}:{password}".encode("utf-8"))
            .hexdigest()
            .lower()
        )
        c = sha256(url.encode("utf-8")).hexdigest().lower()
        digest["pwd"] = (
            sha256(f"{p}:{nonce}:{a}:{n}:{qop}:{c}".encode("utf-8")).hexdigest().lower()
        )
    else:  # algorithm in ["Default", "MD5", "MD5-D", "DigestMD5-D"]
        p = md5(f"{_USERNAME}:{realm}:{password}".encode("utf-8")).hexdigest().lower()
        c = md5(url.encode("utf-8")).hexdigest().lower()
        digest["pwd"] = (
            md5(f"{p}:{nonce}:{a}:{n}:{qop}:{c}".encode("utf-8")).hexdigest().lower()
        )
        if algorithm in ["MD5-D", "DigestMD5-D"]:
            l = (
                md5(f"{_USERNAME}:{password}:{realm}".encode("utf-8"))
                .hexdigest()
                .lower()
            )
            digest["response2"] = (
                md5(f"{l}:{nonce}:{a}:{n}:{qop}:{c}".encode("utf-8"))
                .hexdigest()
                .lower()
            )

    j, _ = DahuaPOE_local_login1_get(ip, _USERNAME, digest)
    if j is None or "Token" not in j:
        err = j.get("ErrorCode", "unknown") if j else "unknown"
        err = _ERRORS.get(err, str(err))
        LOGGER.error(f"DahuaPOE_local_login1({ip}): Invalid Token {j}, {err}")
        return None, err

    uid = j["Token"]

    LOGGER.debug(f"DahuaPOE_local_login1({ip}): uid={uid}")
    return uid, None


_methodRefMap = {
    "thing.service.property.get": {
        "ref": 1,
        "tspOverloadPower": 279,
        "tspAvailablePower": 280,
        "PasswdFindWay": 282,
        "localPort": 289,
        "https": 290,
        "TLSv1Enable": 291,
        "telnetEnable": 210,
        "tspPortNumber": 4,
        "tspLogLevel": 214,
        "tspLogFacility": 215,
        "tspSyslog": 218,
        "deviceTime": 220,
        "deviceTimeZone": 221,
        "NTPInfo": 222,
        "NTPAuthInfo": 223,
        "NTPEnable": 224,
        "NTPOptionalServerAddressList": 225,
        "deviceLocalTime": 226,
        "deviceTimeZoneDesc": 227,
        "tspDHCPEnable": 231,
        "SSHD": 252,
        "authorityHashType": 253,
        "portTxRate": 140,
        "portUsage": 141,
        "portRxRate": 143,
        "cloudWebVersion": 125,
        "buildTime": 99,
        "keepAliveTimeout": 258,
        "tspDevDiscoveryEnable": 29,
        "alias": 33,
        "model": 34,
        "softVersion": 35,
        "deviceClass": 36,
        "vendor": 37,
        "tag1": 38,
        "language": 39,
        "standard": 41,
        "firmwareVersion": 50,
        "area": 52,
        "ip": 53,
        "gateway": 54,
        "poePortPower": 146,
        "netmask": 55,
        "portLinkState": 147,
        "DNS1": 56,
        "actualRateInfo": 148,
        "DNS2": 57,
        "bootProto": 58,
        "MAC": 60,
        "deviceName": 62,
        "DNSAuto": 63,
        "SN": 65,
        "taskPlans": 66,
        "tspTotalPower": 70,
        "tspUsedPower": 71,
        "tspMaxPower7D": 72,
        "tspForeverPoEEnable": 73,
        "tspIPConflictEnable": 78,
        "supportedEventAndIntervalList": 132,
        "tspIpConflictAlarmEnable": 79,
        "productId": 81,
        "enableMsgReporting": 82,
        "tspWizardFinishFlag": 202,
        "tspWizardTimeout": 203,
        "tspUpTime": 83,
        "tspCPUUsage": 84,
        "tspMemUsage": 85,
        "strBuildTime": 98,
        "serial": 155,
        "tspDevCloudEnable": 274,
        "deviceSubClass": 156,
        "securityBaselineVersion": 275,
        "tspDevCloudState": 276,
    },
    "thing.service.property.set": {
        "ref": 2,
        "tspOverloadPower": 279,
        "tspAvailablePower": 280,
        "PasswdFindWay": 282,
        "localPort": 289,
        "https": {"type": 96, "ref": 290},
        "TLSv1Enable": 291,
        "telnetEnable": 210,
        "tspPortNumber": 4,
        "tspLogLevel": 214,
        "tspLogFacility": 215,
        "tspSyslog": {
            "ref": 218,
            "enable": 4,
            "enableTLS": 5,
            "server": 6,
            "port": 7,
            "facility": 8,
        },
        "deviceTime": 220,
        "deviceTimeZone": 221,
        "NTPInfo": {
            "ref": 222,
            "NTPServerAddress": 1,
            "NTPServerPort": 2,
            "updatePeriod": 3,
            "tolerance": 4,
        },
        "NTPAuthInfo": {"ref": 223, "authEnable": 1, "keyID": 2, "key": 3},
        "NTPEnable": 224,
        "NTPOptionalServerAddressList": {
            "ref": 225,
            "NTPServerAddress": 1,
            "NTPServerPort": 2,
            "NTPAuthInfo": {"ref": 3, "authEnable": 1, "keyID": 2, "key": 3},
        },
        "deviceLocalTime": 226,
        "deviceTimeZoneDesc": 227,
        "tspDHCPEnable": 231,
        "SSHD": {"ref": 252, "SSHDEnable": 1, "SSHDOpenDuration": 2, "SSHDPort": 3},
        "authorityHashType": 253,
        "portTxRate": {"type": 44, "ref": 140},
        "portUsage": {"type": 44, "ref": 141},
        "portRxRate": {"type": 44, "ref": 143},
        "cloudWebVersion": 125,
        "buildTime": 99,
        "keepAliveTimeout": 258,
        "tspDevDiscoveryEnable": 29,
        "alias": 33,
        "model": 34,
        "softVersion": 35,
        "deviceClass": 36,
        "vendor": 37,
        "tag1": 38,
        "language": 39,
        "standard": 41,
        "firmwareVersion": 50,
        "area": 52,
        "ip": 53,
        "gateway": 54,
        "poePortPower": {"type": 44, "ref": 146},
        "netmask": 55,
        "portLinkState": {"ref": 147},
        "DNS1": 56,
        "actualRateInfo": {"type": 44, "ref": 148},
        "DNS2": 57,
        "bootProto": 58,
        "MAC": 60,
        "deviceName": 62,
        "DNSAuto": 63,
        "SN": 65,
        "taskPlans": {
            "ref": 66,
            "type": 1,
            "startTime": 2,
            "endTime": 3,
            "weeklyRepeat": {"ref": 4},
            "taskID": 5,
            "devices": {"ref": 6},
        },
        "tspTotalPower": 70,
        "tspUsedPower": 71,
        "tspMaxPower7D": 72,
        "tspForeverPoEEnable": 73,
        "tspIPConflictEnable": 78,
        "supportedEventAndIntervalList": {
            "ref": 132,
            "periodicEventType": 1,
            "minPeriodicReportInterval": 2,
            "maxPeriodicReportInterval": 3,
        },
        "tspIpConflictAlarmEnable": 79,
        "productId": 81,
        "enableMsgReporting": 82,
        "tspWizardFinishFlag": 202,
        "tspWizardTimeout": 203,
        "tspUpTime": {"ref": 83, "day": 1, "hour": 2, "minute": 3, "second": 4},
        "tspCPUUsage": 84,
        "tspMemUsage": 85,
        "strBuildTime": 98,
        "serial": 155,
        "tspDevCloudEnable": {"type": 96, "ref": 274},
        "deviceSubClass": 156,
        "securityBaselineVersion": 275,
        "tspDevCloudState": {"type": 96, "ref": 276},
    },
    "thing.service.tspGetPortCaps": {"ref": 5},
    "thing.service.tspGetPortInfo": {"ref": 6, "len": 4, "offset": 3},
    "thing.service.tspSetPortInfo": {
        "ref": 7,
        "portListInfo": {
            "ref": 10,
            "duplexMode": 1,
            "eeeCfg": 2,
            "flowControlCfg": 3,
            "linkCfg": 4,
            "negotiateRate": 5,
            "portID": 6,
            "portNick": 7,
            "portType": 8,
            "subPortID": 9,
            "flowControlDirection": 10,
        },
    },
    "thing.service.tspGetPortFaceBoardLayer": {"ref": 8},
    "thing.service.tspGetLoopProtectionCaps": {"ref": 14},
    "thing.service.tspSetGlobalLoopProtectionEnableConfigAndAlarmEnableConfig": {
        "ref": 15,
        "alarmEnableConfig": 3,
        "globalLoopProtectionConfig": 2,
    },
    "thing.service.tspGetGlobalLoopProtectionEnableConfigAndAlarmEnableConfig": {
        "ref": 16
    },
    "thing.service.tspGetVlanCaps": {"ref": 20},
    "thing.service.tspAddVlanGroup": {"ref": 21, "vlanDescription": 3, "vlanGroup": 2},
    "thing.service.tspDeleteVlanGroup": {"ref": 22, "operation": 3, "vlanGroup": 1},
    "thing.service.tspSetVlanDescription": {
        "ref": 24,
        "vlanDescriptionInfo": {"ref": 2, "vlanID": 1, "vlanDescription": 2},
    },
    "thing.service.tspGetVlanInfo": {"ref": 25, "len": 4, "offset": 3},
    "thing.service.tspSetPortVlanInfo": {
        "ref": 26,
        "portVlanInfo": {
            "ref": 2,
            "portID": 1,
            "portType": 2,
            "subPortID": 3,
            "PVID": 4,
            "portMode": 5,
            "tagVlan": 6,
            "untagVlan": 7,
        },
    },
    "thing.service.tspGetPortVlanInfo": {"ref": 27, "len": 4, "offset": 3},
    "thing.service.tspGetDevListCaps": {"ref": 30},
    "thing.service.tspGetDevNeighborInfo": {"ref": 31, "len": 5, "offset": 4},
    "thing.service.tspGetDeviceCaps": {"ref": 45},
    "thing.service.configLocalWiredNet": {
        "ref": 61,
        "DNS1": 6,
        "DNS2": 7,
        "DNSAuto": 9,
        "bootProto": 3,
        "gateway": 8,
        "ip": 5,
        "netmask": 4,
        "networkName": 2,
    },
    "thing.service.reset": {"ref": 69, "type": 2},
    "thing.service.tspDevPoECaps": {"ref": 74},
    "thing.service.tspGetPoEPortCfg": {"ref": 75, "len": 3, "offset": 2},
    "thing.service.tspSetPoEPortCfg": {
        "ref": 76,
        "poePortCfg": {
            "ref": 2,
            "poeEnable": 1,
            "longDistanceEnable": 2,
            "watchDogEnable": 3,
            "portType": 4,
            "portID": 5,
            "subPortID": 6,
            "forcePoEEnable": 7,
        },
    },
    "thing.service.authCode": {"ref": 77, "code": 2},
    "thing.service.tspGetSTPInstanceInfo": {"ref": 87, "len": 3, "offset": 2},
    "thing.service.tspSetSTPGlobalCfg": {
        "ref": 88,
        "bpduFilterState": 13,
        "bpduGuard": 4,
        "bridgePriority": 2,
        "enableState": 10,
        "forwardingDelayTime": 6,
        "helloTime": 8,
        "maxAgeTime": 7,
        "maxHops": 3,
        "mode": 9,
        "pathCost": 1,
        "tcFlushLimit": 12,
        "tcProtection": 5,
    },
    "thing.service.tspGetLoopProtectionPortInfo": {"ref": 90, "len": 2, "offset": 1},
    "thing.service.tspGetAggrCaps": {"ref": 91},
    "thing.service.tspSetLoadBalanceMode": {
        "ref": 92,
        "destinationIP": 5,
        "destinationMac": 3,
        "destinationPort": 7,
        "ipProtocol": 8,
        "rtag7Hash": 9,
        "sourceIP": 4,
        "sourceMac": 2,
        "sourcePort": 6,
    },
    "thing.service.tspGetLoadBalanceMode": {"ref": 93},
    "thing.service.tspCreateAggrGroup": {
        "ref": 94,
        "aggrGroupInfo": {
            "ref": 2,
            "portInfo": {"ref": 1, "portID": 1, "portIDType": 2, "subPortID": 3},
            "groupId": 2,
            "mode": 3,
            "balanceMode": 4,
        },
    },
    "thing.service.tspGetAggregationGroupInfo": {
        "ref": 95,
        "len": 9,
        "length": 4,
        "offset": 3,
    },
    "thing.service.tspDeleteAggrGroup": {
        "ref": 97,
        "aggrGroupInfo": {"ref": 2, "groupId": 1},
    },
    "thing.service.tspGetPortPoEPower": {"ref": 100, "len": 2, "offset": 3},
    "thing.service.reboot": {"ref": 107, "delay": 3, "operate": 2},
    "thing.service.tspSetSTPInstanceInfo": {
        "ref": 172,
        "setSTPInstanceInfo": {
            "ref": 2,
            "portID": 1,
            "portType": 2,
            "subPortID": 3,
            "priority": 11,
            "pathCost": 12,
            "instanceID": 21,
            "rootPathCost": 22,
        },
    },
    "thing.service.tspAddPortMirror": {
        "ref": 174,
        "mirrorGroupInfo": {
            "ref": 2,
            "mirrorGroupID": 1,
            "mirrorGroupType": 2,
            "renoteMirrorVlanID": 7,
            "dstPortInfo": {"ref": 16, "portID": 1, "subPortID": 2, "portType": 3},
            "remoteMirrorReflectorPortInfo": {
                "ref": 17,
                "portID": 1,
                "subPortID": 2,
                "protType": 3,
            },
            "srcPortInfo": {"type": 44, "ref": 18},
        },
    },
    "thing.service.tspGetMirrorGroupInfo": {"ref": 175, "len": 3, "offset": 5},
    "thing.service.tspDeletePortMirrorGroup": {
        "ref": 176,
        "mirrorGroupIDList": {"ref": 2},
    },
    "thing.service.addMacInfo": {
        "ref": 181,
        "MACInfo": {
            "ref": 2,
            "MACType": 1,
            "MACAddress": 2,
            "portID": 3,
            "portType": 4,
            "vlanID": 5,
        },
    },
    "thing.service.delMacInfo": {
        "ref": 182,
        "MACInfo": {
            "ref": 3,
            "MACType": 1,
            "MACAddress": 2,
            "portID": 3,
            "portType": 4,
            "vlanID": 5,
        },
    },
    "thing.service.getMacInfo": {
        "ref": 183,
        "MACSearchInfo": {
            "ref": 4,
            "MACType": 1,
            "MACAddress": 2,
            "portID": 3,
            "portType": 4,
            "vlanID": 5,
        },
        "len": 10,
        "offset": 11,
        "requestID": 3,
        "requestType": 2,
    },
    "thing.service.getMacCaps": {"ref": 186},
    "thing.service.modifyUserPassword": {
        "ref": 188,
        "ipAddr": 5,
        "passwordNew": 4,
        "passwordOld": 3,
        "userName": 2,
    },
    "thing.service.tspGetPortIsolationGroupCaps": {"ref": 201},
    "thing.service.setWizardConfig": {
        "ref": 204,
        "WANConfig": {
            "ref": 3,
            "WANName": 1,
            "WANType": 2,
            "IPAddress": 3,
            "subnetMask": 4,
            "defaultGateway": 5,
            "DNS": {"ref": 6},
            "dnsAutoGet": 7,
            "PPPoE": {"ref": 8, "userName": 1, "password": 2},
        },
        "language": 2,
        "locationConfig": {
            "ref": 5,
            "countryCode": 1,
            "deviceTimeZone": 2,
            "deviceTimeZoneDesc": 3,
        },
        "userConfig": {"ref": 6, "userName": 1, "password": 2, "mode": 3, "contact": 4},
        "wifiConfig": {
            "ref": 7,
            "SSID": 1,
            "password": 2,
            "isEnable": 3,
            "encryptType": 4,
            "authenticationEncryptType": 5,
            "frequency": 6,
        },
    },
    "thing.service.setLanguage": {"ref": 205, "language": 2},
    "thing.service.getSupportLanguageList": {"ref": 206, "len": 6, "offset": 5},
    "thing.service.tspGetPortStatisticsInfo": {"ref": 207, "len": 4, "offset": 6},
    "thing.service.tspClearPortStatisticsInfo": {
        "ref": 208,
        "portInfo": {"ref": 2, "portID": 1, "portType": 2, "subPortID": 3},
    },
    "thing.service.getUpgraderState": {"ref": 209},
    "thing.service.addStormCtrlInfo": {
        "ref": 211,
        "ctrlInfo": {
            "ref": 3,
            "portInfo": {"ref": 1, "portID": 1, "portType": 2, "subPortID": 3},
            "bcCtrlInfo": {
                "ref": 2,
                "ctrlType": 1,
                "ctrlRate": 2,
                "ctrlRateUnit": 3,
                "ctrlPercent": 4,
            },
            "mcCtrlInfo": {
                "ref": 3,
                "ctrlType": 1,
                "ctrlRate": 2,
                "ctrlRateUnit": 3,
                "ctrlPercent": 4,
            },
            "ucCtrlInfo": {
                "ref": 4,
                "ctrlType": 1,
                "ctrlRate": 2,
                "ctrlRateUnit": 3,
                "ctrlPercent": 4,
            },
        },
    },
    "thing.service.delStormCtrlInfo": {
        "ref": 212,
        "ctrlInfo": {"ref": 3, "portID": 1, "portType": 2, "subPortID": 3},
    },
    "thing.service.getStormCtrlInfo": {"ref": 213, "len": 4, "offset": 3},
    "thing.service.tspGetLog": {"ref": 216, "len": 6, "offset": 7},
    "thing.service.authentication1": {"ref": 255, "userName": 7},
    "thing.service.keepAlive": {"ref": 259, "active": 3, "clientID": 4},
    "thing.service.logCaps": {"ref": 260},
    "thing.service.setDownlinkIsolationEnable": {"ref": 261, "enable": 2},
    "thing.service.getDownlinkIsolationEnable": {"ref": 262},
    "thing.service.tspGetPortStatisticsCaps": {"ref": 263},
    "thing.service.clearMACInfo": {"ref": 264, "MACType": {"type": 76, "ref": 2}},
    "thing.service.tspSetManageVLAN": {"ref": 265, "vlanID": 2},
    "thing.service.tspGetManageVLAN": {"ref": 266},
    "thing.service.setPortSpeedLimitInfo": {
        "ref": 267,
        "portSpeedLimitInfo": {
            "ref": 2,
            "portInfo": {"ref": 1, "portID": 1, "portType": 2, "subPortID": 3},
            "ingressSpeedLimitInfo": {"ref": 2, "limitRateUnit": 2, "limitRate": 3},
            "egressSpeedLimitInfo": {"ref": 3, "limitRateUnit": 1, "limitRate": 2},
        },
    },
    "thing.service.getPortSpeedLimitInfo": {"ref": 268, "len": 7, "offset": 6},
    "thing.service.portLimitCaps": {"ref": 269},
    "thing.service.tspGetStormCtrlCaps": {"ref": 278},
    "thing.service.negotiateEncryptionKey": {
        "ref": 286,
        "keyType": 5,
        "encrypteKeyECDHPublic1": {"ref": 3, "type": 80},
    },
    "thing.service.setSymmetricKey": {"ref": 295, "secretKey": 2},
    "thing.service.tspGetPortVctInfo": {"ref": 149, "portListInfo": 3},
    "thing.service.authentication2": {
        "ref": 254,
        "NC": 8,
        "QOP": 7,
        "authorityType": 6,
        "clientNonce": 9,
        "digest": 3,
        "method": 11,
        "nonce": 4,
        "opaque": 17,
        "requestURI": 10,
        "userName": 2,
        "alternateDigest": 19,
    },
    "thing.service.setPortSpeedLimitCfg": {
        "ref": 304,
        "portSpeedLimitInfo": {
            "ref": 1,
            "portListInfo": {"type": 44, "ref": 1},
            "portSpeedLimitCfg": {
                "ref": 2,
                "ingressSpeedLimitInfo": {"ref": 1, "limitRateUnit": 1, "limitRate": 2},
                "egressSpeedLimitInfo": {"ref": 2, "limitRateUnit": 1, "limitRate": 2},
            },
        },
    },
    "thing.service.setPoePortCfgBatch": {
        "ref": 300,
        "poePortInfo": {
            "ref": 1,
            "poePortListInfo": {"type": 44, "ref": 1},
            "poePortCfg": {
                "ref": 2,
                "poeEnable": 1,
                "longDistanceEnable": 2,
                "watchDogEnable": 3,
                "enhancedPoeEnable": 4,
                "forcePoeEnable": 5,
            },
        },
    },
    "thing.service.setPortCfgBatch": {
        "ref": 301,
        "portInfo": {
            "ref": 1,
            "portListInfo": {"type": 44, "ref": 1},
            "portCfg": {
                "ref": 2,
                "duplexMode": 1,
                "eeeCfg": 2,
                "flowControlCfg": 3,
                "linkCfg": 4,
                "negotiateRate": 5,
                "flowControlDirection": 6,
                "portNick": 7,
            },
        },
    },
    "thing.service.setPortVlanCfgBatch": {
        "ref": 302,
        "portVlanInfo": {
            "ref": 1,
            "portListInfo": {"type": 44, "ref": 1},
            "portVlanCfg": {
                "ref": 2,
                "portMode": 1,
                "tagVlan": 2,
                "untagVlan": 3,
                "pvid": 4,
            },
        },
    },
    "thing.service.addStormCtrlCfg": {
        "ref": 305,
        "stormCtrlInfo": {
            "ref": 1,
            "portListInfo": {"type": 44, "ref": 1},
            "stormCtrlCfg": {
                "ref": 2,
                "bcCtrlInfo": {
                    "ref": 1,
                    "ctrlType": 1,
                    "ctrlRate": 2,
                    "ctrlRateUnit": 3,
                    "ctrlPercent": 4,
                },
                "mcCtrlInfo": {
                    "ref": 2,
                    "ctrlType": 1,
                    "ctrlRate": 2,
                    "ctrlRateUnit": 3,
                    "ctrlPercent": 4,
                },
                "ucCtrlInfo": {
                    "ref": 3,
                    "ctrlType": 1,
                    "ctrlRate": 2,
                    "ctrlRateUnit": 3,
                    "ctrlPercent": 4,
                },
            },
        },
    },
}

_refMethodMap = {
    1: {
        4: "tspPortNumber",
        29: "tspDevDiscoveryEnable",
        33: "alias",
        34: "model",
        35: "softVersion",
        36: "deviceClass",
        37: "vendor",
        38: "tag1",
        39: "language",
        41: "standard",
        50: "firmwareVersion",
        52: "area",
        53: "ip",
        54: "gateway",
        55: "netmask",
        56: "DNS1",
        57: "DNS2",
        58: "bootProto",
        60: "MAC",
        62: "deviceName",
        63: "DNSAuto",
        65: "SN",
        66: {
            1: "type",
            2: "startTime",
            3: "endTime",
            4: "weeklyRepeat",
            5: "taskID",
            6: "devices",
            "ref": "taskPlans",
        },
        70: "tspTotalPower",
        71: "tspUsedPower",
        72: "tspMaxPower7D",
        73: "tspForeverPoEEnable",
        78: "tspIPConflictEnable",
        79: "tspIpConflictAlarmEnable",
        81: "productId",
        82: "enableMsgReporting",
        83: {1: "day", 2: "hour", 3: "minute", 4: "second", "ref": "tspUpTime"},
        84: "tspCPUUsage",
        85: "tspMemUsage",
        98: "strBuildTime",
        99: "buildTime",
        125: "cloudWebVersion",
        132: {
            1: "periodicEventType",
            2: "minPeriodicReportInterval",
            3: "maxPeriodicReportInterval",
            "ref": "supportedEventAndIntervalList",
        },
        140: "portTxRate",
        141: "portUsage",
        143: "portRxRate",
        146: "poePortPower",
        147: "portLinkState",
        148: "actualRateInfo",
        155: "serial",
        156: "deviceSubClass",
        202: "tspWizardFinishFlag",
        203: "tspWizardTimeout",
        210: "telnetEnable",
        214: "tspLogLevel",
        215: "tspLogFacility",
        218: {
            4: "enable",
            5: "enableTLS",
            6: "server",
            7: "port",
            8: "facility",
            "ref": "tspSyslog",
        },
        220: "deviceTime",
        221: "deviceTimeZone",
        222: {
            1: "NTPServerAddress",
            2: "NTPServerPort",
            3: "updatePeriod",
            4: "tolerance",
            "ref": "NTPInfo",
        },
        223: {1: "authEnable", 2: "keyID", 3: "key", "ref": "NTPAuthInfo"},
        224: "NTPEnable",
        225: {
            1: "NTPServerAddress",
            2: "NTPServerPort",
            3: {1: "authEnable", 2: "keyID", 3: "key", "ref": "NTPAuthInfo"},
            "ref": "NTPOptionalServerAddressList",
        },
        226: "deviceLocalTime",
        227: "deviceTimeZoneDesc",
        231: "tspDHCPEnable",
        252: {1: "SSHDEnable", 2: "SSHDOpenDuration", 3: "SSHDPort", "ref": "SSHD"},
        253: "authorityHashType",
        258: "keepAliveTimeout",
        274: "tspDevCloudEnable",
        275: "securityBaselineVersion",
        276: "tspDevCloudState",
        279: "tspOverloadPower",
        280: "tspAvailablePower",
        282: "PasswdFindWay",
        289: "localPort",
        290: "https",
        291: "TLSv1Enable",
        "method": "thing.service.property.get",
    },
    2: {1: "set_results", "method": "thing.service.property.set"},
    5: {
        1: "supportSpeedDuplexCfg",
        2: "supportSpeedDuplexCurrentState",
        3: "supportFlowControlCfg",
        4: "supportFlowControlCurrentState",
        5: "supportEEECfg",
        6: "supportEEECurrentState",
        7: "supportPortRateStatistics",
        8: "supportPortUsageStatistics",
        13: "supportPortNick",
        14: "portNickLen",
        15: "paginationGetMaxLenPerRequest",
        16: "multiPortSetMaxLenPerRequest",
        17: "supportPortCongestionAlarm",
        18: "result",
        19: {1: "portLowMask", 2: "portHighMask", "ref": "supportPortVct"},
        20: "supportPortBatchSet",
        "method": "thing.service.tspGetPortCaps",
    },
    6: {
        1: "total",
        2: {
            1: "portID",
            2: "portType",
            3: "subPortID",
            4: "portFlowDirect",
            5: "portDescri",
            6: "portNick",
            7: "MediumType",
            8: "actualNegotiateRate",
            9: "actualDuplexMode",
            10: "negotiateRateCfg",
            11: "linkState",
            12: "portCongestionState",
            13: "actualFlowContorlState",
            14: "flowControlCfg",
            15: "actualEEEEnableState",
            16: "eeeEnableCfg",
            17: "negotiateRateDuplexOption",
            18: "rxRate",
            19: "txRate",
            20: "rxUsage",
            21: "txUsage",
            22: "duplexModeCfg",
            23: "linkCfg",
            24: "rxRateUnit",
            25: "txRateUnit",
            "ref": "portInfo",
        },
        5: "result",
        6: "dataListLength",
        7: {
            1: "portID",
            2: "portType",
            3: "subPortID",
            4: "portFlowDirect",
            5: "portDescri",
            6: "portNick",
            7: "MediumType",
            8: "actualNegotiateRate",
            9: "actualDuplexMode",
            10: "negotiateRateCfg",
            11: "linkState",
            12: "portCongestionState",
            13: "actualFlowContorlState",
            14: "flowControlCfg",
            15: "actualEEEEnableState",
            16: "eeeEnableCfg",
            17: "negotiateRateDuplexOption",
            18: "rxRate",
            19: "txRate",
            20: "rxUsage",
            21: "txUsage",
            22: "duplexModeCfg",
            23: "linkCfg",
            24: "rxRateUnit",
            25: "txRateUnit",
            26: "flowControlDirection",
            27: "portLinkDirect",
            "ref": "dataList",
        },
        8: "curOffset",
        "method": "thing.service.tspGetPortInfo",
    },
    7: {
        9: "result",
        11: {1: "portID", 2: "result", "ref": "portResult"},
        "method": "thing.service.tspSetPortInfo",
    },
    8: {
        1: "layerCnt",
        2: "portIDTraversalMode",
        3: "portIDTraversalStartLayer",
        4: "portNumPerLevel",
        5: "combPortList",
        6: "combLayerType",
        7: "result",
        "method": "thing.service.tspGetPortFaceBoardLayer",
    },
    14: {
        1: "supportPortConfigLoopProtectionState",
        3: "supportGlobalConfigLoopProtectionState",
        4: "supportAlarm",
        5: "paginationGetMaxLenPerRequest",
        6: "result",
        "method": "thing.service.tspGetLoopProtectionCaps",
    },
    15: {
        1: "result",
        "method": "thing.service.tspSetGlobalLoopProtectionEnableConfigAndAlarmEnableConfig",
    },
    16: {
        1: "globalLoopProtectionConfig",
        2: "alarmEnableConfig",
        3: "result",
        "method": "thing.service.tspGetGlobalLoopProtectionEnableConfigAndAlarmEnableConfig",
    },
    20: {
        1: "vlanMaxNum",
        2: "vlanRange",
        3: "supportDeleteVlan1",
        4: "supportBatchCreateVlan",
        5: "supportVlanDescription",
        6: "vlanDescriptionLen",
        7: "supportAccessMode",
        8: "supportTrunkMode",
        9: "supportHybridMode",
        10: "supportPvidSetNotExistVlan",
        11: "supportTaggedvlanSetNotExistVlan",
        12: "supportUntaggedvlanSetNotExistVlan",
        13: "multiVlanSetMaxLenPerRequest",
        14: "paginationGetMaxLenPerRequest",
        15: "result",
        16: "supportManageVlan",
        "method": "thing.service.tspGetVlanCaps",
    },
    21: {1: "result", "method": "thing.service.tspAddVlanGroup"},
    22: {2: "result", "method": "thing.service.tspDeleteVlanGroup"},
    24: {1: "result", "method": "thing.service.tspSetVlanDescription"},
    25: {
        1: {
            1: "vlanID",
            2: "vlanDescription",
            3: "taggedPortList",
            4: "untaggedPortList",
            "ref": "vlanInfo",
        },
        2: "total",
        5: "result",
        6: "dataListLength",
        7: {
            1: "vlanID",
            2: "vlanDescription",
            3: "taggedPortList",
            4: "untaggedPortList",
            "ref": "dataList",
        },
        8: "curOffset",
        "method": "thing.service.tspGetVlanInfo",
    },
    26: {1: "result", "method": "thing.service.tspSetPortVlanInfo"},
    27: {
        5: {
            1: "portID",
            2: "portType",
            3: "subPortID",
            4: "PVID",
            5: "portMode",
            6: "taggedVlan",
            7: "untaggedVlan",
            "ref": "portVlanInfo",
        },
        6: "total",
        7: "result",
        8: "dataListLength",
        9: {
            1: "portID",
            2: "portType",
            3: "subPortID",
            4: "PVID",
            5: "portMode",
            6: "taggedVlan",
            7: "untaggedVlan",
            "ref": "dataList",
        },
        10: "curOffset",
        "method": "thing.service.tspGetPortVlanInfo",
    },
    30: {
        1: "paginationGetMaxLenPerRequest",
        2: "supportDevDiscoveryEnable",
        3: "result",
        "method": "thing.service.tspGetDevListCaps",
    },
    31: {
        1: "total",
        3: {
            3: "localPortDesc",
            4: "remotePortDesc",
            5: "remoteMacAddr",
            6: "remoteSN",
            7: "remoteIPAddr",
            8: "remoteCustomDeviceType",
            9: "remoteDeviceClass",
            10: "remoteDeviceSubClass",
            "ref": "deviceInfo",
        },
        6: "result",
        7: "dataListLength",
        8: {
            3: "localPortDesc",
            4: "remotePortDesc",
            5: "remoteMacAddr",
            6: "remoteSN",
            7: "remoteIPAddr",
            8: "remoteCustomDeviceType",
            9: "remoteDeviceClass",
            10: "remoteDeviceSubClass",
            11: "remoteDeviceName",
            12: "remoteChassisID",
            "ref": "dataList",
        },
        9: "curOffset",
        "method": "thing.service.tspGetDevNeighborInfo",
    },
    45: {
        1: {
            1: "utc",
            2: "systemTime",
            4: "log",
            5: "SSH",
            6: "telnet",
            7: "cloudUpgrader",
            8: "devInfo",
            10: "userManager",
            11: "configCloudBackup",
            12: "reset",
            13: "cpuInfo",
            14: "memoryInfo",
            15: "portManager",
            16: "ftp",
            17: "vlan",
            18: "linkAggregation",
            19: "poe",
            20: "ipRoute",
            21: "macTable",
            22: "arpTable",
            23: "TLS",
            24: "vlanInterface",
            25: "oneClickDetect",
            26: "eventPeriodicReportCap",
            27: "ntp",
            28: "poePowerQuery",
            29: "upLink",
            30: "actualStatusOfData",
            31: "cloudUpgraderSubDev",
            32: "oneClickAssociation",
            "ref": "common",
        },
        2: {
            1: "SNMP",
            2: "DNS",
            3: "L2TP",
            4: "IPSec",
            5: "DHCPServer",
            7: "radius",
            8: "VRRP",
            9: "RIP",
            10: "BGP",
            11: "MPLS",
            12: "MSDP",
            13: "IGMP",
            14: "PIM",
            "ref": "protocolL3L4",
        },
        3: {
            1: "ACL",
            2: "portIsolation",
            3: "portMirroring",
            4: "portSpeedLimiting",
            5: "stormSuppression",
            6: "firewall",
            7: "blackHoleMAC",
            8: "policyRouting",
            9: "portal",
            10: "EAD",
            11: "802_1x",
            12: "VPN",
            "ref": "securityControl",
        },
        4: {
            1: "LLDP",
            2: "STP",
            3: "DHCPRelay",
            4: "DHCPSNOOPING",
            5: "ERPS",
            6: "OSPF",
            7: "HWPing",
            8: "BFD",
            9: "ISIS",
            10: "MFF",
            11: "ECMP",
            12: "MVRP",
            14: "QINQ",
            15: "RRPP",
            16: "VPLS",
            17: "loopDetection",
            18: "MSTP",
            "ref": "protocolL1L2",
        },
        5: "numberOfConcurrency",
        6: "result",
        7: {1: "tunnelCap", 2: "webOnOSS", "ref": "tunnel"},
        8: {
            1: "ipConflict",
            2: "loopback",
            3: "portCongestion",
            4: "portPlug",
            5: "optlinkDetect",
            "ref": "alarm",
        },
        9: {
            1: "supportMesh",
            2: "supportCellularFeatures",
            3: "supportGuest",
            4: "support2GWifi",
            5: "support5GWifi",
            6: "supportDualBandSync",
            "ref": "wireless",
        },
        10: "openSourceLicense",
        11: "upgradePollTime",
        12: "supportCloud",
        13: "supportInfoCode",
        14: "deviceDefect",
        15: "supportWeakPwdCheck",
        "method": "thing.service.tspGetDeviceCaps",
    },
    61: {1: "result", "method": "thing.service.configLocalWiredNet"},
    69: {1: "result", "method": "thing.service.reset"},
    74: {
        1: "supportForeverPoE",
        2: "supportLongDistance",
        3: "supportWatchDog",
        4: "multiPortSetMaxLenPerRequest",
        5: "paginationGetMaxLenPerRequest",
        6: "supportForcePoE",
        7: "supportGreenPoE",
        8: "result",
        9: "supportBridgeRebootPortPoE",
        10: "supportPoEPortList",
        11: "supportPoEPortBatchSet",
        12: "supportEnhancedPoe",
        "method": "thing.service.tspDevPoECaps",
    },
    75: {
        1: {
            1: "longDistanceEnable",
            2: "watchDogEnable",
            3: "poeEnable",
            4: "portID",
            5: "portType",
            6: "subPortID",
            7: "forcePoEEnable",
            "ref": "poePortCfg",
        },
        4: "result",
        5: "dataListLength",
        6: "total",
        7: {
            1: "longDistanceEnable",
            2: "watchDogEnable",
            3: "poeEnable",
            4: "portID",
            5: "portType",
            6: "subPortID",
            7: "forcePoEEnable",
            8: "enhancedPoeEnable",
            "ref": "dataList",
        },
        8: "curOffset",
        "method": "thing.service.tspGetPoEPortCfg",
    },
    76: {
        1: "result",
        3: {1: "portID", 2: "result", "ref": "portResult"},
        "method": "thing.service.tspSetPoEPortCfg",
    },
    77: {1: "result", "method": "thing.service.authCode"},
    87: {
        1: {
            1: "portID",
            2: "portType",
            3: "subPortID",
            4: "role",
            5: "state",
            6: "rootPathCost",
            7: "portRootID",
            8: "regionRootID",
            9: "designatedBridgeID",
            10: "designatedPortID",
            11: "priority",
            12: "pathCost",
            13: "instanceID",
            14: "portGuardType",
            "ref": "STPInstanceInfo",
        },
        4: "result",
        "method": "thing.service.tspGetSTPInstanceInfo",
    },
    88: {11: "result", "method": "thing.service.tspSetSTPGlobalCfg"},
    90: {
        3: {
            1: "portID",
            2: "portType",
            3: "subPortID",
            4: "action",
            5: "state",
            "ref": "portInfo",
        },
        4: "result",
        "method": "thing.service.tspGetLoopProtectionPortInfo",
    },
    91: {
        1: "supportAnyHashMode",
        2: "supportSrcMacLoadBalanceMode",
        3: "supportDstMacLoadBalanceMode",
        4: "supportSrcAndDstMacLoadBalanceMode",
        5: "supportSrcIpLoadBalanceMode",
        6: "supportDstIpLoadBalanceMode",
        7: "supportSrcPortLoadBalanceMode",
        8: "supportDstPortLoadBalanceMode",
        9: "supportIpProtocolLoadBalanceMode",
        10: "maxAggrGroups",
        11: "maxPortNumPerGroup",
        12: "supportAnyPortInGroup",
        13: "portInGroupInfo",
        14: "supportStaticMode",
        15: "supportLacpActive",
        16: "supportLacpPassive",
        17: "supportLacpDynamicMode",
        18: "multiPortSetMaxLenPerRequest",
        19: "paginationGetMaxLenPerRequest",
        20: "result",
        21: "supportRtag7BalanceMode",
        "method": "thing.service.tspGetAggrCaps",
    },
    92: {1: "result", "method": "thing.service.tspSetLoadBalanceMode"},
    93: {
        1: "sourceMac",
        2: "destinationMac",
        3: "sourceIP",
        4: "destinationIP",
        5: "sourcePort",
        6: "destinationPort",
        7: "ipProtocol",
        8: "result",
        9: "rtag7Hash",
        "method": "thing.service.tspGetLoadBalanceMode",
    },
    94: {1: "result", "method": "thing.service.tspCreateAggrGroup"},
    95: {
        1: "totalNum",
        2: {
            1: "gourpId",
            2: "mode",
            3: "portID",
            4: "portIDType",
            5: "subPortID",
            6: "portAggregationState",
            7: "rxRate",
            8: "txRate",
            "ref": "aggregationGroupInfo",
        },
        5: "result",
        6: "dataListLength",
        7: {
            1: "gourpId",
            2: "mode",
            3: "portID",
            4: "portIDType",
            5: "subPortID",
            6: "portAggregationState",
            7: "rxRate",
            8: "txRate",
            9: "balanceMode",
            "ref": "dataList",
        },
        8: "total",
        10: "curOffset",
        "method": "thing.service.tspGetAggregationGroupInfo",
    },
    97: {1: "result", "method": "thing.service.tspDeleteAggrGroup"},
    100: {
        1: {
            1: "portID",
            2: "portType",
            3: "subPortID",
            4: "nowPower",
            5: "nowClass",
            6: "totalPower",
            "ref": "poePortStates",
        },
        4: "result",
        5: "dataListLength",
        6: {
            1: "portID",
            2: "portType",
            3: "subPortID",
            4: "nowPower",
            5: "nowClass",
            6: "totalPower",
            "ref": "dataList",
        },
        7: "total",
        8: "curOffset",
        "method": "thing.service.tspGetPortPoEPower",
    },
    107: {1: "result", "method": "thing.service.reboot"},
    172: {1: "result", "method": "thing.service.tspSetSTPInstanceInfo"},
    174: {
        1: "result",
        3: "mirrorGroupIDList",
        "method": "thing.service.tspAddPortMirror",
    },
    175: {
        1: "result",
        6: {
            1: "mirrorGroupID",
            2: "mirrorGroupType",
            3: "mirrorGroupValidState",
            7: "renoteMirrorVlanID",
            8: {1: "portID", 2: "subPortID", 3: "portType", "ref": "dstPortInfo"},
            9: {
                1: "portID",
                2: "subPortID",
                3: "portType",
                "ref": "remoteMirrorReflectorPortInfo",
            },
            10: "srcPortInfo",
            "ref": "dataList",
        },
        7: "curOffset",
        8: "dataListLength",
        9: "total",
        "method": "thing.service.tspGetMirrorGroupInfo",
    },
    176: {1: "result", "method": "thing.service.tspDeletePortMirrorGroup"},
    181: {
        1: "result",
        3: {2: "MACAddress", "ref": "addInfo"},
        "method": "thing.service.addMacInfo",
    },
    182: {
        1: "result",
        2: {2: "MACAddress", "ref": "delInfo"},
        "method": "thing.service.delMacInfo",
    },
    183: {
        1: "result",
        5: "replyID",
        6: {
            1: "MACAddress",
            2: "MACType",
            3: "vlanID",
            4: "portID",
            5: "portType",
            "ref": "dataList",
        },
        7: "dataListLength",
        8: "total",
        9: "curOffset",
        "method": "thing.service.getMacInfo",
    },
    186: {
        1: "result",
        2: "portLearningMACMaxNum",
        3: "agingTimeRange",
        4: "maxAddMACNum",
        5: "maxMACNum",
        6: "supportBatchDelMAC",
        7: "supportSetBlackholeMAC",
        8: "supportSetStaticMAC",
        9: "supportSetDynamicMAC",
        10: "supportSetLimitActCaps",
        11: "supportSetPortLearningMACNum",
        12: "supportPortLearningMACCaps",
        13: "supportdisableAgingTime",
        14: "supportSetAgingTime",
        16: "multiMACAddMaxLenPerRequest",
        17: "MACEntrySupportVid",
        18: "multiMACDelMaxLenPerRequest",
        "method": "thing.service.getMacCaps",
    },
    188: {
        1: "result",
        6: {1: "remainLockTimes", 2: "remainLockSecond", "ref": "lockInfo"},
        "method": "thing.service.modifyUserPassword",
    },
    201: {
        4: "supportAddMaxIsolationGroups",
        6: "result",
        8: "portIsoLateVlanExist",
        9: "paginationAddMaxLenPerRequest",
        10: "paginationDelMaxLenPerRequest",
        11: "paginationModMaxLenPerRequest",
        12: "supportIsolateMethod",
        "method": "thing.service.tspGetPortIsolationGroupCaps",
    },
    204: {1: "result", "method": "thing.service.setWizardConfig"},
    205: {1: "result", "method": "thing.service.setLanguage"},
    206: {
        1: "result",
        2: "total",
        3: "languageList",
        "method": "thing.service.getSupportLanguageList",
    },
    207: {
        1: "result",
        2: {
            1: "portID",
            2: "rxPacketsHigh",
            3: "rxBytesHigh",
            4: "txPacketsHigh",
            5: "txBytesHigh",
            7: "rxBroadcastPacketsHigh",
            8: "rxMulticastPacketsHigh",
            9: "rxErrPacketsHigh",
            10: "rxUsage",
            11: "rxTotalRate",
            12: "rxBroadcastRate",
            13: "rxMulticastRate",
            15: "txBroadcastPacketsHigh",
            16: "txMulticastPacketsHigh",
            17: "txErrPacketsHigh",
            18: "txUsage",
            19: "txTotalRate",
            20: "txBroadcastRate",
            21: "txMulticastRate",
            22: "lastClearTime",
            23: "portType",
            24: "subPortID",
            25: "rxRateUnit",
            26: "txRateUnit",
            27: "rxPacketsLow",
            28: "rxBytesLow",
            29: "txPacketsLow",
            30: "txBytesLow",
            31: "rxBroadcastPacketsLow",
            32: "rxMulticastPacketsLow",
            33: "rxErrPacketsLow",
            34: "txBroadcastPacketsLow",
            35: "txMulticastPacketsLow",
            36: "txErrPacketsLow",
            "ref": "dataList",
        },
        7: "curOffset",
        8: "total",
        9: "dataListLength",
        "method": "thing.service.tspGetPortStatisticsInfo",
    },
    208: {1: "result", "method": "thing.service.tspClearPortStatisticsInfo"},
    209: {
        1: "result",
        2: "rebootType",
        3: "needReboot",
        4: "chipType",
        5: "progress",
        6: "status",
        "method": "thing.service.getUpgraderState",
    },
    211: {
        1: "result",
        4: {
            1: {1: "portID", 2: "portType", 3: "subPortID", "ref": "portInfo"},
            2: {
                1: "ctrlType",
                2: "ctrlRate",
                3: "ctrlRateUnit",
                4: "ctrlPercent",
                "ref": "bcCtrlInfo",
            },
            3: {
                1: "ctrlType",
                2: "ctrlRate",
                3: "ctrlRateUnit",
                4: "ctrlPercent",
                "ref": "mcCtrlInfo",
            },
            4: {
                1: "ctrlType",
                2: "ctrlRate",
                3: "ctrlRateUnit",
                4: "ctrlPercent",
                "ref": "ucCtrlInfo",
            },
            "ref": "addInfo",
        },
        "method": "thing.service.addStormCtrlInfo",
    },
    212: {
        1: "result",
        4: {1: "portID", 2: "portType", 3: "subPortID", "ref": "delInfo"},
        "method": "thing.service.delStormCtrlInfo",
    },
    213: {
        1: "result",
        5: "curOffset",
        6: "total",
        7: "dataListLength",
        8: {
            1: {1: "portID", 2: "portType", 3: "subPortID", "ref": "portInfo"},
            2: {
                1: "ctrlType",
                2: "ctrlRate",
                3: "ctrlRateUnit",
                4: "ctrlPercent",
                "ref": "bcCtrlInfo",
            },
            3: {
                1: "ctrlType",
                2: "ctrlRate",
                3: "ctrlPercent",
                4: "ctrlRateUnit",
                "ref": "mcCtrlInfo",
            },
            4: {
                1: "ctrlType",
                2: "ctrlRate",
                3: "ctrlPercent",
                4: "ctrlRateUnit",
                "ref": "ucCtrlInfo",
            },
            "ref": "dataList",
        },
        "method": "thing.service.getStormCtrlInfo",
    },
    216: {
        1: "result",
        4: "total",
        5: {
            1: "time",
            2: "level",
            3: "facility",
            4: "content",
            5: "IP",
            "ref": "dataList",
        },
        8: "dataListLength",
        9: "curOffset",
        "method": "thing.service.tspGetLog",
    },
    255: {
        1: "result",
        2: "opaque",
        3: "nonce",
        4: "QOP",
        5: "realm",
        6: "authorityTypes",
        "method": "thing.service.authentication1",
    },
    259: {1: "result", "method": "thing.service.keepAlive"},
    260: {1: "result", 3: "supportLogInfo", "method": "thing.service.logCaps"},
    261: {1: "result", "method": "thing.service.setDownlinkIsolationEnable"},
    262: {
        1: "result",
        2: "enable",
        "method": "thing.service.getDownlinkIsolationEnable",
    },
    263: {
        1: "result",
        2: "portStatisticsPollTime",
        3: "supportField",
        "method": "thing.service.tspGetPortStatisticsCaps",
    },
    264: {1: "result", "method": "thing.service.clearMACInfo"},
    265: {1: "result", "method": "thing.service.tspSetManageVLAN"},
    266: {1: "result", 2: "vlanID", "method": "thing.service.tspGetManageVLAN"},
    267: {1: "result", "method": "thing.service.setPortSpeedLimitInfo"},
    268: {
        1: "result",
        2: {
            1: {1: "portID", 2: "protType", 3: "subPortID", "ref": "portInfo"},
            2: {2: "limitRate", 3: "limitRateUnit", "ref": "ingressSpeedLimitInfo"},
            3: {1: "limitRateUnit", 2: "limitRate", "ref": "egressSpeedLimitInfo"},
            "ref": "dataList",
        },
        3: "curOffset",
        4: "total",
        5: "dataListLength",
        "method": "thing.service.getPortSpeedLimitInfo",
    },
    269: {
        1: "result",
        3: "paginationSetMaxLenPerRequest",
        4: {
            1: "bps",
            2: "Bps",
            3: "Kbps",
            4: "Mbps",
            5: "Gbps",
            6: "Tbps",
            7: "pps",
            "ref": "supportUnitAndMaxRange",
        },
        "method": "thing.service.portLimitCaps",
    },
    278: {
        1: "result",
        2: "paginationAddMaxLenPerRequest",
        3: {
            1: "supportBroadcastStormCtrl",
            2: "supportMulticastStormCtrl",
            3: "supportUnicastStormCtrl",
            "ref": "supportStormCtrlType",
        },
        4: "supportPercentCtrl",
        5: "supportRateCtrl",
        6: {
            1: "bps",
            2: "Bps",
            3: "Kbps",
            4: "Mbps",
            5: "Gbps",
            6: "Tbps",
            7: "pps",
            "ref": "supportUnitAndMaxRange",
        },
        7: "stormSupportIndividualRate",
        8: "paginationDelMaxLenPerRequest",
        "method": "thing.service.tspGetStormCtrlCaps",
    },
    286: {
        1: "result",
        2: "publicKey2",
        4: "encrypteType",
        "method": "thing.service.negotiateEncryptionKey",
    },
    295: {1: "result", "method": "thing.service.setSymmetricKey"},
    149: {
        "method": "thing.service.tspGetPortVctInfo",
        4: {3: "channelFaultInfo", 4: "portID", "ref": "vctInfo"},
        1: "result",
    },
    254: {
        1: "result",
        18: {1: "remainLockTimes", 2: "remainLockSecond", "ref": "lockInfo"},
        "method": "thing.service.authentication2",
    },
    # FIXME: Seems BUG in Dahua firmware!!!
    # 300: {2: "result", "method": "thing.service.setPoePortCfgBatch"},
    300: {1: "result", "method": "thing.service.setPoePortCfgBatch"},
    301: {2: "result", "method": "thing.service.setPortCfgBatch"},
    302: {2: "result", "method": "thing.service.setPortVlanCfgBatch"},
    304: {2: "result", "method": "thing.service.setPortSpeedLimitCfg"},
    305: {2: "result", "method": "thing.service.addStormCtrlCfg"},
}


def _crc(buf):
    s = 0
    for b in buf[2:]:
        s += b
        if s >= 255:
            s = (~s & 0xFFFF) + 1
    return s & 0xFF


def _bytes_needed(n):
    if n == 0:
        return 1
    return int(log(n, 256)) + 1


def _bytes_needed_signed(n):
    if -128 <= n and n <= 127:
        return 1
    if -32768 <= n and n <= 32767:
        return 2
    if -2147483648 <= n and n <= 2147483647:
        return 4
    return 8


def _ctrl_byte(val, ref=None, signed=False):
    h = 0 if ref is None else 0x60 if ref > 255 else 0x20  # 011, 001, 000
    if isinstance(val, bool):
        l = 8 + int(val)
    elif isinstance(val, numbers.Number):
        if val < 0 or signed:
            n = _bytes_needed_signed(val)
            if n == 1:
                l = 4
            elif n == 2:
                l = 5
            elif n == 4:
                l = 6
            else:
                l = 7
        else:
            n = _bytes_needed(val)
            if n == 1:
                l = 0
            elif n == 2:
                l = 1
            elif n == 4:
                l = 2
            else:
                l = 3
    elif isinstance(val, str):
        l = 19 + _bytes_needed(len(val))
    elif isinstance(val, collections.abc.Sequence):
        l = 30  # 0x1E
    # elif isinstance(val, dict):
    else:
        l = 29  # 0x1D
    return h | l


def _pack(val, info=None, signed=False, is_array=False):
    ctrl = None
    if isinstance(info, dict):
        ctrl = info.get("type", None)
        ref = info["ref"]
    else:
        ref = info

    if ctrl is None:
        ctrl = _ctrl_byte(val, ref, signed)

    ctrl_type = ctrl & 0x1F

    if isinstance(val, collections.abc.Sequence) and not isinstance(
        val, str
    ):  # Use info["type"] for items
        if ctrl_type == 12 or ctrl_type == 13:
            ctrl_type = 30  # 0x1E []
            ctrl = 0x5E  #
        else:
            ctrl_type = 30  # 0x1E []
            ctrl = (ctrl & 0xE0) | ctrl_type

    if (ctrl_type == 12 or ctrl_type == 13 or ctrl_type == 29) and is_array:
        ref = None
        ctrl = ctrl & 0x1F

    buf = bytearray(bytes([ctrl]))
    if ref:
        if ref > 255:
            buf.extend(struct.pack(">H", ref))
        else:
            buf.extend(struct.pack(">B", ref))

    if ctrl_type == 0:
        buf.extend(struct.pack(">B", val))
    elif ctrl_type == 1:
        buf.extend(struct.pack(">H", val))
    elif ctrl_type == 2:
        buf.extend(struct.pack(">L", val))
    elif ctrl_type == 3:
        buf.extend(struct.pack(">Q", val))

    elif ctrl_type == 4:
        buf.extend(struct.pack(">b", val))
    elif ctrl_type == 5:
        buf.extend(struct.pack(">h", val))
    elif ctrl_type == 6:
        buf.extend(struct.pack(">l", val))
    elif ctrl_type == 7:
        buf.extend(struct.pack(">q", val))

    elif ctrl_type == 8 or ctrl_type == 9:  # bool
        pass

    elif ctrl_type == 12 or ctrl_type == 13:  # bits, bits2
        if not isinstance(val, str):
            raise ValueError(f"val {val} must be str")
        buf2 = bytearray()
        bits_skip = 0
        while True:
            s = val[:8]
            _len = len(s)
            if _len < 8:
                bits_skip = 8 - _len
            b = int(s, 2) << bits_skip
            buf2.extend(struct.pack(">B", b))
            val = val[8:]
            if len(val) == 0:
                break
        buf.extend(struct.pack(">B", len(buf2) + 1))
        buf.extend(struct.pack(">B", bits_skip))
        buf.extend(buf2)

    elif ctrl_type >= 16 and ctrl_type <= 23:  # str
        n = _bytes_needed(len(val))
        if n == 1:
            buf.extend(struct.pack(">B", len(val)))
        elif n == 2:
            buf.extend(struct.pack(">H", len(val)))
        else:
            raise NotImplementedError
        buf.extend(bytearray(val, "utf-8"))

    elif ctrl_type == 29:  # 0x1D {}
        for key in val:
            buf.extend(_pack(val[key], info[key], signed))
        buf.append(31)  # 0x1F End of Object

    elif ctrl_type == 30:  # 0x1E []
        for item in val:
            buf.extend(_pack(item, info, signed, is_array=True))
        buf.append(28)  # 0x1C EOL

    else:
        raise NotImplementedError

    return buf


def _ref_bytes(ctrl):
    ctrl = ctrl >> 5
    if ctrl == 0:  # 000
        return 0
    if ctrl in [1, 2, 4]:  # 001 010 100
        return 1
    return 2


def _unpack(buf, info: dict, res: dict, ref=None):
    # LOGGER.debug(f"DahuaPOE_local_post1 _unpack {''.join(format(b, '02x') for b in buf)}\ninfo={info}\nres={res}\nref={ref}")

    ctrl = struct.unpack_from(">B", buf)[0]
    pos = 1

    ref_len = _ref_bytes(ctrl)
    if ref_len == 1:
        ref = struct.unpack_from(">B", buf, pos)[0]
        pos += 1
    elif ref_len == 2:
        ref = struct.unpack_from(">H", buf, pos)[0]
        pos += 2

    val = None
    ctrl_type = ctrl & 0x1F

    # unsigned
    if ctrl_type == 0:
        val = struct.unpack_from(">B", buf, pos)[0]
        pos += 1
    elif ctrl_type == 1:
        val = struct.unpack_from(">H", buf, pos)[0]
        pos += 2
    elif ctrl_type == 2:
        val = struct.unpack_from(">L", buf, pos)[0]
        pos += 4
    elif ctrl_type == 3:
        val = struct.unpack_from(">Q", buf, pos)[0]
        pos += 8

    # signed
    elif ctrl_type == 4:
        val = struct.unpack_from(">b", buf, pos)[0]
        pos += 1
    elif ctrl_type == 5:
        val = struct.unpack_from(">h", buf, pos)[0]
        pos += 2
    elif ctrl_type == 6:
        val = struct.unpack_from(">l", buf, pos)[0]
        pos += 4
    elif ctrl_type == 7:
        val = struct.unpack_from(">q", buf, pos)[0]
        pos += 8

    elif ctrl_type == 8:
        val = False
    elif ctrl_type == 9:
        val = True

    elif ctrl_type == 10:
        val = struct.unpack_from(">f", buf, pos)[0]
        pos += 4
    elif ctrl_type == 11:
        val = struct.unpack_from(">d", buf, pos)[0]
        pos += 8

    elif ctrl_type == 12:  # bits
        _len = struct.unpack_from(">B", buf, pos)[0]
        pos += 1
        bits = buf[pos : pos + _len]
        bits_skip = struct.unpack_from(">B", bits)[0]
        val = "".join(f"{b:08b}" for b in bits[1:-1])
        last_byte = f"{bits[-1]:08b}"
        val += last_byte[0 : 8 - bits_skip]
        pos += _len

    elif ctrl_type == 13:  # bits2
        _len = struct.unpack_from(">H", buf, pos)[0]
        pos += 2
        raise NotImplementedError
        val = "0"
        pos += _len

    elif ctrl_type >= 16 and ctrl_type <= 19:
        if ctrl_type == 16:
            _len = struct.unpack_from(">B", buf, pos)[0]
            pos += 1
        elif ctrl_type == 17:
            _len = struct.unpack_from(">H", buf, pos)[0]
            pos += 2
        elif ctrl_type == 18:
            _len = struct.unpack_from(">L", buf, pos)[0]
            pos += 4
        elif ctrl_type == 19:
            _len = struct.unpack_from(">Q", buf, pos)[0]
            pos += 8
        val = buf[pos : pos + _len].decode("ascii")
        pos += _len

    elif ctrl_type >= 20 and ctrl_type <= 23:
        if ctrl_type == 20:
            _len = struct.unpack_from(">B", buf, pos)[0]
            pos += 1
        elif ctrl_type == 21:
            _len = struct.unpack_from(">H", buf, pos)[0]
            pos += 2
        elif ctrl_type == 22:
            _len = struct.unpack_from(">L", buf, pos)[0]
            pos += 4
        elif ctrl_type == 23:
            _len = struct.unpack_from(">Q", buf, pos)[0]
            pos += 8
        val = buf[pos : pos + _len].decode("utf-8")
        pos += _len

    elif ctrl_type == 0x1C:  # 28 End of List
        return pos, None
    elif ctrl_type == 0x1F:  # 31 End of Object
        return pos, None

    elif ctrl_type == 30:  # 0x1E
        val = []
        while True:
            pos2, v = _unpack(buf[pos:], info, None, ref)
            pos += pos2
            if v is None:
                break
            val.append(v)

    elif ctrl_type == 29:  # 0x1D
        val = {}
        info2 = info.get(ref, None)
        if info2 is None:
            raise ValueError(f"Invalid dict ref {ref}")
        while True:
            pos2, v = _unpack(buf[pos:], info2, val)
            pos += pos2
            if v is None:
                break
        pass

    if ref and res is not None:
        key = info.get(ref, None)
        if isinstance(key, dict):
            key = key.get("ref", None)
        if key is None:
            # raise ValueError(f"Invalid prop ref {ref}")
            i = 0
            while True:
                key = "undefined" if i == 0 else f"undefined{i}"
                if key not in res:
                    break
                i += 1
        if val is None:
            raise ValueError(f"Invalid val")
        res[key] = val

    return pos, val


def _request_payload(request_id, session_id, method: str, data):
    info = _methodRefMap.get(method, None)
    if info is None:
        raise ValueError(f"Invalid method {method}")

    buf = bytearray()
    if isinstance(data, collections.abc.Sequence):
        if method == "thing.service.property.get":
            buf.extend(bytes([0x3E, 0x02]))
            for key_property in data:
                buf.extend(_pack(info[key_property], None, signed=False, is_array=True))
        else:
            buf.append(0x1E)  # 30
            for item in data:
                buf.extend(_pack(item, info, signed=False, is_array=True))
        buf.append(0x1C)  # 28 EOL
    elif data:
        for key in data:
            buf.extend(_pack(data[key], info[key], signed=True))

    _len = len(buf) + 20
    if _len > 127:
        _len += 1
        blen = bytes([0x80 | (_len & 0x7F), _len >> 7])
    else:
        blen = bytes([_len])

    payload = bytearray([0x74, 0xE0, 0x01])
    payload.extend(blen)
    payload.extend(struct.pack(">H", request_id))
    payload.extend(struct.pack(">Q", session_id))
    payload.extend(bytes([0x00, 0x04, 0x00]))
    payload.extend(struct.pack(">H", info["ref"]))
    payload.extend(buf)
    payload.append(_crc(payload))

    return payload


def _response_json(raw, method=None, request_id=None, session_id=None):
    if raw[0] != 0x74 or raw[1] != 0xE0 or raw[2] != 0x01:
        raise ValueError(f"Invalid response header")
    _len = raw[3]
    pos = 4
    if _len & 0x80:
        pos += 1
        _len = (int(raw[4]) << 7) | (_len & 0x7F)

    _request_id = struct.unpack_from(">H", raw, pos)[0]
    pos += 2

    if request_id is not None and _request_id != request_id:
        raise ValueError(f"Invalid request ID {_request_id}, expected {request_id}")

    _session_id = struct.unpack_from(">Q", raw, pos)[0]
    pos += 8

    # TODO: compare session_id

    pos += 1  # skip 00

    if raw[pos] != 0x84:
        raise ValueError(f"Invalid response header")
    pos += 1

    pos += 1
    if raw[pos - 1] == 0x01:
        res = struct.unpack_from(">L", raw, pos)
        pos += 4
        if res in [1, 2, 3, 4]:
            raise ValueError(f"Unknown error 01")
    ref = struct.unpack_from(">H", raw, pos)[0]
    pos += 2

    info = _refMethodMap.get(ref, None)
    if info is None:
        raise ValueError(f"Unknown ref {ref}")

    if method and method != info["method"]:
        raise ValueError(f"Invalid method {method}, header contains {info['method']}")

    res = {}
    while pos < len(raw) - 1:
        pos2, v = _unpack(raw[pos:-1], info, res)
        pos += pos2
    return res


DahuaPOE_RequestID = {}
DahuaPOE_SessionID = {}

_URL_MULTICALL1 = "/things/v1/multicall"
_URL_SERVICE1 = "/things/v1/service"
_URL_EXT_SERVICE1 = "/things/v1/extern/service"


def DahuaPOE_local_post1(ip: str, uid: str, method: str, data, url=_URL_SERVICE1):
    # LOGGER.debug(f"DahuaPOE_local_post1({ip}, {uid}, {method}, {data}, {url})...")

    try:
        global DahuaPOE_RequestID
        if ip not in DahuaPOE_RequestID:
            DahuaPOE_RequestID[ip] = 0

        global DahuaPOE_SessionID
        if ip not in DahuaPOE_SessionID:
            DahuaPOE_SessionID[ip] = 0

        DahuaPOE_RequestID[ip] += 2
        if DahuaPOE_RequestID[ip] > 0xFFFF:
            DahuaPOE_RequestID[ip] = 0

        payload = _request_payload(
            DahuaPOE_RequestID[ip], DahuaPOE_SessionID[ip], method, data
        )

        headers = {
            "Connection": "close",
            "User-Agent": _USER_AGENT,
            "Content-Type": "plain/text",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en",
        }
        if uid:
            headers["Cookie"] = f"sessionID={uid}"
            headers["X-custom-token"] = uid
        else:
            headers["X-custom-token"] = ""

        base64_payload = base64.b64encode(payload).decode("utf-8")

        # if is_sec:
        #    headers["X-Content-Encryption"] = "encrypted"
        #    base64_payload = AES.encrypt(base64_payload, IOTKEY)

        hdr_lines = ""
        for h in headers.items():
            hdr_lines += f"{h[0]}: {h[1]}\r\n"

        request = f"POST {url} HTTP/1.1\r\nHost: {ip}\r\nContent-Length: {len(base64_payload)}\r\n{hdr_lines}\r\n{base64_payload}"

        LOGGER.debug(
            f"DahuaPOE_local_post1({ip}, {uid}, {method}, {data}, {url}): request: {''.join(format(b, '02x') for b in payload)}"
        )

        # Dahua web server expect headers and payload in the same packet!!!

        # response = requests.post(
        #    f"http://{ip}{url}",
        #    headers=headers,
        #    data={"params": data},
        #    verify=False,
        #    timeout=(5, 5),
        # )

        resp = ""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            server_address = (ip, 80)
            sock.connect(server_address)
            sock.sendall(request.encode("utf-8"))

            while True:
                d = sock.recv(1024)
                if not d:
                    break
                resp += d.decode("utf-8")

        resp = resp.split("\r\n")
        code = resp[0].split(" ")
        if len(code) < 3 or code[0] != "HTTP/1.1":
            return None, "Invalid response"
        response_status_code = int(code[1])
        response_reason = " ".join(code[2:])

        encrypted = False
        response_text = None
        for line in resp:
            if response_text is None:
                if len(line) == 0:
                    response_text = ""
                elif line == "x-content-encryption: encrypted":
                    encrypted = True
            else:
                response_text += line + "\r\n"

        if response_text is None:
            response_text = ""

        # if encrypted:
        #    response_text = AES.decrypt(response_text, IOTKEY)
        # if method == "thing.service.negotiateEncryptionKey" and  url == _URL_EXT_SERVICE1:
        #    TODO: Update IOTKEY

        raw_resp = base64.b64decode(response_text)

    except Exception as e:
        LOGGER.error(
            f"DahuaPOE_local_post1({ip}, {uid}, {method}, {data}, {url}): {str(e)}"
        )
        return None, None

    if response_status_code != requests.codes.ok:
        LOGGER.warning(
            f"DahuaPOE_local_post1({ip}, {uid}, {method}, {data}, {url}): HTTP {response_status_code}: {response_reason}: {response_text}"
        )
        return None, response_text

    try:
        res = _response_json(
            raw_resp, method, DahuaPOE_RequestID[ip], DahuaPOE_SessionID[ip]
        )
    except Exception as e:
        LOGGER.error(
            f"DahuaPOE_local_post1({ip}, {uid}, {method}, {data}, {url}): response {''.join(format(b, '02x') for b in raw_resp)}\r\n{str(e)}"
        )
        return None, None

    LOGGER.debug(
        f"DahuaPOE_local_post1({ip}, {uid}, {method}, {data}, {url}): response {''.join(format(b, '02x') for b in raw_resp)}\r\n{res}"
    )
    return res, None
