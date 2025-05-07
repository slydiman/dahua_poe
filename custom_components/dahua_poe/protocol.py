import requests
from hashlib import sha256, md5
from .const import LOGGER


_USER_AGENT = "Mozilla/5.0 (Linux; Android 12)"
# _USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"


def DahuaPOE_local_get(ip: str, uid: str, url: str):
    LOGGER.debug(f"DahuaPOE_local_get({ip}, {uid}, {url})...")

    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "User-Agent": _USER_AGENT,
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

    response.close()
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
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        # "Accept-Language": "en-US,en",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        # "Origin": f"http://{ip}",
        # "Referer": f"http://{ip}/",
        "User-Agent": _USER_AGENT,
    }
    if uid:
        headers["Cookie"] = f"sessionID={uid}"
        headers["X-Cookie"] = f"sessionID={uid}"

    try:
        response = requests.post(
            f"http://{ip}{url}",
            headers=headers,
            data={"params": data},
            verify=False,
            timeout=(5, 5),
        )
    except Exception as e:
        LOGGER.error(f"DahuaPOE_local_post({ip}, {uid}, {url}): {str(e)}")
        return None, None

    response.close()
    if response.status_code != requests.codes.ok:
        LOGGER.warning(
            f"DahuaPOE_local_post({ip}, {uid}, {url}): HTTP {response.status_code}: {response.reason}: {response.text}"
        )
        return None, response.text

    res = response.text if uid else response.cookies.get_dict().get("sessionID", None)
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
