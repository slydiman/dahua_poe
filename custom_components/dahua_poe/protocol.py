import requests
from hashlib import sha256, md5
from .const import LOGGER


DahuaPOE_session = {}


def DahuaPOE_local_get(ip: str, uid: str, url: str):
    global DahuaPOE_session
    headers = {
        "user-agent": "Mozilla/5.0 (Linux; Android 9) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 uni-app Html5Plus/1.0 (Immersed/24.0)",
        "Connection": "keep-alive",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
    }
    if uid:
        headers["X-Cookie"] = f"sessionID={uid}"
    try:
        if DahuaPOE_session.get(ip, None) is None:
            DahuaPOE_session[ip] = requests.Session()
        response = DahuaPOE_session[ip].get(
            "http://" + ip + url, headers=headers, cookies=DahuaPOE_session[ip].cookies
        )
    except Exception as e:
        LOGGER.exception(f"DahuaPOE_local_get({ip}, {uid}, {url}): exception {e}")
        DahuaPOE_session[ip].close()
        DahuaPOE_session[ip] = None
        return None

    if response.status_code != requests.codes.ok:
        LOGGER.warning(
            f"DahuaPOE_local_get({ip}, {uid}, {url}): response code HTTP {response.status_code}"
        )
        return None

    return response.text


def DahuaPOE_local_post(ip: str, uid: str, url: str, data):
    global DahuaPOE_session
    headers = {
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "user-agent": "Mozilla/5.0 (Linux; Android 9) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 uni-app Html5Plus/1.0 (Immersed/24.0)",
        "Connection": "keep-alive",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
    }
    if uid:
        headers["X-Cookie"] = f"sessionID={uid}"
    try:
        if DahuaPOE_session.get(ip, None) is None:
            DahuaPOE_session[ip] = requests.Session()
        response = DahuaPOE_session[ip].post(
            "http://" + ip + url,
            headers=headers,
            data={"params": data},
            cookies=DahuaPOE_session[ip].cookies,
        )
    except Exception as e:
        LOGGER.exception(f"DahuaPOE_local_post({ip}, {uid}, {url}): exception {e}")
        DahuaPOE_session[ip].close()
        DahuaPOE_session[ip] = None
        return None, None

    if response.status_code != requests.codes.ok:
        LOGGER.warning(
            f"DahuaPOE_local_post({ip}, {uid}, {url}): response code HTTP {response.status_code}"
        )
        return None, response.text

    return response.text, None


def DahuaPOE_local_login(ip: str, password: str):
    c = DahuaPOE_local_get(ip, None, "/get_challenge.cgi?params=admin")
    if c is None:
        return None, "invalid_ip"
    LOGGER.debug(f"DahuaPOE_local_login({ip}): get_challenge: {c}")

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
    LOGGER.debug(f"DahuaPOE_local_login({ip}): login: admin/{e}{n}")
    res, err = DahuaPOE_local_post(ip, None, "/login.cgi", f"admin/{e}{n}")
    if res is None:
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
    global DahuaPOE_session
    return DahuaPOE_session[ip].cookies.get_dict().get("sessionID", None), None
