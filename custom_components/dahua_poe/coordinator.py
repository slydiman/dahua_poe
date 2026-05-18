from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import (
    HomeAssistantError,
    ConfigEntryAuthFailed,
)
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.const import (
    CONF_IP_ADDRESS,
    CONF_PASSWORD,
    CONF_TOKEN,
    CONF_PROTOCOL,
)

import asyncio
from datetime import timedelta
from .const import DOMAIN, LOGGER
from .protocol import (
    DahuaPOE_local_get,
    DahuaPOE_local_post,
    DahuaPOE_local_login,
    DahuaPOE_local_login1,
    DahuaPOE_local_post1,
)


class DahuaPOE_Coordinator(DataUpdateCoordinator):

    def __init__(self, hass: HomeAssistant, config_entry):
        self._ip = config_entry.data.get(CONF_IP_ADDRESS, None)
        self._password = config_entry.data[CONF_PASSWORD]
        self.protocol = config_entry.data.get(CONF_PROTOCOL, 0)
        self._uid = config_entry.data.get(CONF_TOKEN, None)
        self._uid_write = False
        self.desc = None
        self.sn = None
        self.device_info = None
        self.poe = None
        self.tp = None
        self.ports = None
        # self.keepalive = 0
        # self.keepalive_init = 1

        super().__init__(
            hass,
            LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=30),  # 15
            config_entry=config_entry,
        )

    def get_port_desc(self, port: str) -> str:
        desc = self.ports.get(port, {}).get("desc", port) if self.ports else port
        return desc if desc else port

    def write_token(self) -> None:
        if self._uid_write:
            new_data = {**self.config_entry.data}
            if self._uid:
                new_data[CONF_TOKEN] = self._uid
            elif CONF_TOKEN in new_data:
                new_data.pop(CONF_TOKEN)
            self.hass.config_entries.async_update_entry(
                self.config_entry,
                data=new_data,
            )
            self._uid_write = False

    async def _async_update_data(self) -> None:
        try:
            async with asyncio.timeout(10):
                await self.hass.async_add_executor_job(self._fetch_data)
        except ApiAuthError as err:
            self._uid = None
            self._uid_write = True
            self.write_token()
            # Raising ConfigEntryAuthFailed will cancel future updates
            # and start a config flow with SOURCE_REAUTH (async_step_reauth)
            raise ConfigEntryAuthFailed from err
        except ApiError as err:
            self._uid = None
            self._uid_write = True
            self.write_token()
            raise UpdateFailed(f"Error communicating with API: {err}")
        self.write_token()

    def _fetch_data(self) -> None:
        if self._uid is None:
            if self.protocol == 1:
                self._uid, err = DahuaPOE_local_login1(self._ip, self._password)
            else:
                self._uid, err = DahuaPOE_local_login(self._ip, self._password)
            if self._uid is None:
                raise ApiAuthError(
                    f"DahuaPOE_local_login({self._ip}): {err or 'unknown'}"
                )
            self._uid_write = True
        if self.device_info is None:
            if self.protocol == 1:
                self._set_device_info_1()
            else:
                self._set_device_info_0()

        if self.protocol == 1:
            self._fetch_data_1()
        else:
            self._fetch_data_0()

    def _set_device_info_0(self):
        info, err = DahuaPOE_local_get(self._ip, self._uid, "/get_device_info.cgi")
        if info is None:
            raise ApiError(
                f"DahuaPOE_local_get({self._ip}, /get_device_info.cgi): {err or 'unknown'}"
            )
        # POE8/DH-CS4010-8ET-110/AH08EBBPAJ00XXX/F8:CE:07:XX:XX:XX/V1.001.0000000.7.R/2024-09-28/12919/1/V2.4
        info = info.split("/")
        self.desc = info[0]
        self.sn = info[2]
        self.device_info = DeviceInfo(
            identifiers={(DOMAIN, info[2])},
            manufacturer="Dahua",
            model=info[1],
            name=info[0],
            sw_version=info[4],
            connections={(CONNECTION_NETWORK_MAC, info[3])},
        )

        info, err = DahuaPOE_local_get(self._ip, self._uid, "/port_get_conf.cgi")
        if info is None:
            raise ApiError(
                f"DahuaPOE_local_get({self._ip}, /port_get_conf.cgi): {err or 'unknown'}"
            )
        # Total number of ports "6|" or "10|"
        ports = info.split("|")
        if self.ports is None:
            self.ports = {}
        n = int(ports[0])
        for i in range(n):
            self.ports[str(i + 1)] = {}

    def _set_device_info_1(self):
        info, err = DahuaPOE_local_post1(
            self._ip,
            self._uid,
            "thing.service.property.get",
            ["tspPortNumber", "alias", "SN", "model", "firmwareVersion", "ip", "MAC"],
        )
        if info is None:
            raise ApiError(
                f"DahuaPOE_local_post1({self._ip}, thing.service.property.get): {err or 'unknown'}"
            )
        self.desc = info["alias"]
        self.sn = info["SN"]
        self.device_info = DeviceInfo(
            identifiers={(DOMAIN, info["SN"])},
            manufacturer="Dahua",  # info["vendor"]
            model=info["model"],
            name=info["alias"],
            sw_version=info["firmwareVersion"],  # info["softVersion"]
            connections={(CONNECTION_NETWORK_MAC, info["MAC"])},
        )

        if self.ports is None:
            self.ports = {}
        n = info["tspPortNumber"]
        i = 0
        while True:
            info, err = DahuaPOE_local_post1(
                self._ip,
                self._uid,
                "thing.service.tspGetPortInfo",
                {"offset": i, "len": n},
            )
            if info is None:
                raise ApiError(
                    f"DahuaPOE_local_post1({self._ip}, thing.service.tspGetPortInfo): {err or 'unknown'}"
                )
            for port_info in info["dataList"]:
                port_name = str(port_info["portID"])
                if port_name not in self.ports:
                    self.ports[port_name] = {}
                self.ports[port_name]["desc"] = port_info["portNick"]
                self.ports[port_name]["negotiate_rate"] = port_info[
                    "actualNegotiateRate"
                ]
                self.ports[port_name]["duplex_mode"] = port_info["actualDuplexMode"]
            n = info["total"]
            i = info["dataListLength"]
            if i >= n:
                break

    def _fetch_data_0(self):
        # if self.keepalive:
        #    self.keepalive = 0
        #    res, err = DahuaPOE_local_post(
        #        self._ip, self._uid, "/keepalive.cgi", self.keepalive_init
        #    )
        #    if res is not None:
        #        self.keepalive_init = 0
        #    return

        ports = len(self.ports) if self.ports else 0
        ports = f"/&params=0/{ports}" if ports > 0 else ""

        for i in range(2):
            info, err = DahuaPOE_local_get(
                self._ip,
                self._uid,
                f"/mutil_call.cgi?mutilreqs=get_power_port.cgi/get_power_cfg.cgi/port_get_conf.cgi{ports}",
            )
            if info is not None:
                break
            if i > 0:
                raise ApiError(
                    f"DahuaPOE_local_get({self._ip}, /multi_call.cgi): {err or 'unknown'}"
                )
            self._uid, err = DahuaPOE_local_login(self._ip, self._password)
            if self._uid is None:
                raise ApiAuthError(
                    f"DahuaPOE_local_login({self._ip}): {err or 'unknown'}"
                )
            self._uid_write = True

        info = info.split("\n")
        if len(info) < 2:
            raise ApiError(
                f"DahuaPOE_local_get({self._ip}, /multi_call.cgi): [{len(info)}]: {info}"
            )

        # info[0] = DahuaPOE_local_get(self._ip, self._uid, "/get_power_port.cgi")
        # 8|1/0/22/1/0/1/0|2/0/18/1/0/1/0|3/0/17/1/0/1/0|4/0/35/1/0/1/0|5/0/30/1/0/1/0|6/0/34/1/0/1/0|7/0/34/1/0/1/0|8/0/29/1/0/1/0|
        power_port = info[0].split("|")
        if self.poe is None:
            self.poe = {}
        n = int(power_port[0])
        for i in range(n):
            d = power_port[i + 1].split("/")
            self.poe[d[0]] = {
                "level": d[1],
                "power": d[2],
                "enable": d[3],
                "ext": d[4],
                "watchdog": d[5],
                "force": d[6],
                "unknown": d[7] if len(d) > 7 else None,  # Since V1.003.0000000.8.R
            }

        # info[1] = DahuaPOE_local_get(self._ip, self._uid, "/get_power_cfg.cgi")
        # 1100/990/1100/207/0/893/0
        # Total/Available/Alert/Consumption/Reserved/Remaining/Perpetual
        power_cfg = info[1].split("/")
        self.tp = power_cfg[3]

        # info[2] = "6|1/0/0/Desc1/0/0-1-2-3-4-5/1/5/0/0/0/0|...|6/0/1/Desc6/0/0-1-2-3-4-5-6/1/6/0/0/0/0|"
        ports = info[2].split("|")
        if self.ports is None:
            self.ports = {}
        n = int(ports[0])
        for i in range(n):
            if i + 1 < len(ports):
                d = ports[i + 1].split("/")
                port_name = d[0]
                # d[1] = 0 # type
                # d[2] = 1 # IsUplink
                desc = d[3]
                # d[4] = 0 # medium type
                # d[5] = "0-1-2-3-4-5-6" # DuplexCapsOption
                # d[6] = 1 # DuplexCfg AUTO
                duplex_state = int(d[7])
                # d[8] = 0 # FlowCfg
                # d[9] = 0 # FlowState
                # d[10] = 0 # EEECfg
                # d[11] = 0 # EEEState
                match duplex_state:
                    case 0:  # DOWN
                        negotiate_rate = 0
                        duplex_mode = 0
                    case 1:  # AUTO
                        negotiate_rate = 0
                        duplex_mode = 0
                    case 2:  # 10M_HALF
                        negotiate_rate = 10
                        duplex_mode = 2
                    case 3:  # 10M_FULL
                        negotiate_rate = 10
                        duplex_mode = 1
                    case 4:  # 100M_HALF
                        negotiate_rate = 100
                        duplex_mode = 2
                    case 5:  # 100M_FULL
                        negotiate_rate = 100
                        duplex_mode = 1
                    case 6:  # 1000M_FULL
                        negotiate_rate = 1000
                        duplex_mode = 1
                    case _:
                        negotiate_rate = 0
                        duplex_mode = 0
            else:
                port_name = str(i + 1)
                desc = ""
                negotiate_rate = 0
                duplex_mode = 0

            self.ports[port_name]["negotiate_rate"] = negotiate_rate
            self.ports[port_name]["duplex_mode"] = duplex_mode
            self.ports[port_name]["desc"] = desc

        # self.keepalive = 1

    def _fetch_data_1(self):
        for i in range(2):
            info, err = DahuaPOE_local_post1(
                self._ip,
                self._uid,
                "thing.service.keepAlive",
                {"active": False, "clientID": self._uid},
            )
            if info is not None:
                break
            if i > 0:
                raise ApiError(
                    f"DahuaPOE_local_post1({self._ip}, thing.service.keepAlive): {err or 'unknown'}"
                )
            self._uid, err = DahuaPOE_local_login1(self._ip, self._password)
            if self._uid is None:
                raise ApiAuthError(
                    f"DahuaPOE_local_login1({self._ip}): {err or 'unknown'}"
                )
            self._uid_write = True

        info, err = DahuaPOE_local_post1(
            self._ip,
            self._uid,
            "thing.service.property.get",
            [
                "tspPortNumber",
                "tspUsedPower",
                "tspTotalPower",
                "poePortPower",
            ],
        )
        if info is None:
            raise ApiError(
                f"DahuaPOE_local_post1({self._ip}, thing.service.property.get): {err or 'unknown'}"
            )

        self.tp = info["tspUsedPower"]

        if self.poe is None:
            self.poe = {}
        power_port = info["poePortPower"]
        n = len(power_port)
        for i in range(n):
            port_name = f"{i+1}"
            if port_name not in self.poe:
                self.poe[port_name] = {}
            bits = power_port[i]
            power = int(bits[:16], 2)
            self.poe[port_name]["power"] = power

        i = 0
        while True:
            info, err = DahuaPOE_local_post1(
                self._ip,
                self._uid,
                "thing.service.tspGetPoEPortCfg",
                {"offset": i, "len": n},
            )
            if info is None:
                raise ApiError(
                    f"DahuaPOE_local_post1({self._ip}, thing.service.tspGetPoEPortCfg): {err or 'unknown'}"
                )
            for cfg in info["dataList"]:
                port_name = str(cfg["portID"])
                if port_name not in self.poe:
                    self.poe[port_name] = {}
                self.poe[port_name]["enable"] = str(int(cfg["poeEnable"]))
                self.poe[port_name]["ext"] = cfg["longDistanceEnable"]
                self.poe[port_name]["watchdog"] = cfg["watchDogEnable"]
                self.poe[port_name]["force"] = cfg["forcePoEEnable"]
            n = info["total"]
            i = info["curOffset"]
            if i >= n:
                break

        info, err = DahuaPOE_local_post1(
            self._ip,
            self._uid,
            "thing.service.property.get",
            [
                "actualRateInfo",
            ],
        )
        if info is None:
            raise ApiError(
                f"DahuaPOE_local_post1({self._ip}, actualRateInfo): {err or 'unknown'}"
            )
        if self.ports is None:
            self.ports = {}
        for i, bits in enumerate(info["actualRateInfo"]):
            port_name = str(i + 1)
            if port_name not in self.ports:
                self.ports[port_name] = {}
            self.ports[port_name]["negotiate_rate"] = int(bits[:28], 2)
            self.ports[port_name]["duplex_mode"] = int(bits[28:32], 2)

    async def _async_switch_poe(self, port: str, enable: bool) -> None:
        try:
            async with asyncio.timeout(3):
                return await self.hass.async_add_executor_job(
                    self._switch_poe_local, port, enable
                )
        except ApiError as err:
            self._uid = None
            self._uid_write = True
            raise UpdateFailed(f"Error communicating with API: {err}")

    def _switch_poe_local(self, port: str, enable: bool) -> None:
        if self.poe is None:
            raise ApiError(f"_switch_poe_local({ip}): poe is None")
        if self.protocol == 1:
            self._switch_poe_local_1(port, enable)
        else:
            self._switch_poe_local_0(port, enable)
        self.poe[port]["enable"] = str(int(enable))

    def _switch_poe_local_0(self, port: str, enable: bool) -> None:
        data = f"{port}/{str(int(enable))}/{self.poe[port]['ext']}/{self.poe[port]['watchdog']}/{self.poe[port]['force']}"
        if self.poe[port]["unknown"] is not None:
            data += "/0"
        for i in range(2):
            res, err = DahuaPOE_local_post(
                self._ip, self._uid, "/set_power_port.cgi", data
            )
            if res is not None:
                break
            if i > 0:
                raise ApiError(
                    f"DahuaPOE_local_post({self._ip},/set_power_port.cgi, {data}): {err or 'unknown'}"
                )
            self._uid, err = DahuaPOE_local_login(self._ip, self._password)
            if self._uid is None:
                raise ApiAuthError(
                    f"DahuaPOE_local_login({self._ip}): {err or 'unknown'}"
                )
            self._uid_write = True

    def _switch_poe_local_1(self, port: str, enable: bool):
        for i in range(2):
            info, err = DahuaPOE_local_post1(
                self._ip,
                self._uid,
                "thing.service.tspGetPoEPortCfg",
                {"offset": int(port) - 1, "len": 1},
            )
            if info is not None:
                break
            if i > 0:
                raise ApiError(
                    f"DahuaPOE_local_post1({self._ip}, thing.service.tspGetPoEPortCfg): {err or 'unknown'}"
                )
            self._uid, err = DahuaPOE_local_login1(self._ip, self._password)
            if self._uid is None:
                raise ApiAuthError(
                    f"DahuaPOE_local_login1({self._ip}): {err or 'unknown'}"
                )
            self._uid_write = True

        cfg = info["dataList"][0]
        res, err = DahuaPOE_local_post1(
            self._ip,
            self._uid,
            "thing.service.setPoePortCfgBatch",
            {
                "poePortInfo": [
                    {
                        "poePortCfg": {
                            "poeEnable": int(enable),
                            "longDistanceEnable": int(cfg["longDistanceEnable"]),
                            "watchDogEnable": int(cfg["watchDogEnable"]),
                            "forcePoeEnable": int(cfg["forcePoEEnable"]),
                            "enhancedPoeEnable": cfg["enhancedPoeEnable"],
                        },
                        "poePortListInfo": [
                            "00000000" + f"{int(port):b}".zfill(8) + "000000000000"
                        ],
                    }
                ]
            },
        )
        if res is None:
            raise ApiError(
                f"DahuaPOE_local_post1({self._ip}, thing.service.setPoePortCfgBatch): {err or 'unknown'}"
            )


class ApiError(HomeAssistantError):
    """ApiError"""


class ApiAuthError(HomeAssistantError):
    """ApiAuthError"""
