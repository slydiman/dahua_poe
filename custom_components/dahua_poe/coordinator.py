from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import (
    HomeAssistantError,
    ConfigEntryAuthFailed,
)
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.const import CONF_IP_ADDRESS, CONF_PASSWORD, CONF_PROTOCOL

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
        self._uid = None
        self.desc = None
        self.sn = None
        self.device_info = None
        self.poe = None
        self.tp = None
        # self.keepalive = 0
        # self.keepalive_init = 1

        super().__init__(
            hass,
            LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=30),  # 15
            config_entry=config_entry,
        )

    async def _async_update_data(self) -> None:
        try:
            async with asyncio.timeout(10):
                return await self.hass.async_add_executor_job(self._fetch_data)
        except ApiAuthError as err:
            self._uid = None
            # Raising ConfigEntryAuthFailed will cancel future updates
            # and start a config flow with SOURCE_REAUTH (async_step_reauth)
            raise ConfigEntryAuthFailed from err
        except ApiError as err:
            self._uid = None
            raise UpdateFailed(f"Error communicating with API: {err}")

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
        # POE8/DH-CS4010-8ET-110/AH08EBBPAJ00651/F8:CE:07:7B:51:86/V1.001.0000000.7.R/2024-09-28/12919/1/V2.4
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

    def _fetch_data_0(self):
        # if self.keepalive:
        #    self.keepalive = 0
        #    res, err = DahuaPOE_local_post(
        #        self._ip, self._uid, "/keepalive.cgi", self.keepalive_init
        #    )
        #    if res is not None:
        #        self.keepalive_init = 0
        #    return

        for i in range(2):
            info, err = DahuaPOE_local_get(
                self._ip,
                self._uid,
                "/mutil_call.cgi?mutilreqs=get_power_port.cgi/get_power_cfg.cgi",
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

    async def _async_switch_poe(self, port: str, enable: bool) -> None:
        try:
            async with asyncio.timeout(3):
                return await self.hass.async_add_executor_job(
                    self._switch_poe_local, port, enable
                )
        except ApiError as err:
            self._uid = None
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
