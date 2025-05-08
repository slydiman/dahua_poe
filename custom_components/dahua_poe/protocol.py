import requests
import socket
import urllib.parse
from hashlib import sha256, md5
from .const import LOGGER


_USER_AGENT = "Mozilla/5.0 (Linux; Android 12)"
# _USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"


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
