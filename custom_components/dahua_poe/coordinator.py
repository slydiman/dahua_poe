from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import (
    HomeAssistantError,
    ConfigEntryAuthFailed,
)
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
import async_timeout
from datetime import timedelta
from .const import DOMAIN, LOGGER
from .protocol import DahuaPOE_local_get, DahuaPOE_local_post, DahuaPOE_local_login


class DahuaPOE_Coordinator(DataUpdateCoordinator):

    def __init__(self, hass: HomeAssistant, ip: str, password: str):
        self._ip = ip
        self._password = password
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
        )

    async def _async_update_data(self) -> None:
        try:
            async with async_timeout.timeout(10):
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
            self._uid, err = DahuaPOE_local_login(self._ip, self._password)
            if self._uid is None:
                raise ApiAuthError(
                    f"DahuaPOE_local_login({self._ip}): {err or 'unknown'}"
                )
        if self.device_info is None:
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

        # if self.keepalive:
        #    self.keepalive = 0
        #    res, err = DahuaPOE_local_post(
        #        self._ip, self._uid, "/keepalive.cgi", self.keepalive_init
        #    )
        #    if res is not None:
        #        self.keepalive_init = 0
        #    return

        info, err = DahuaPOE_local_get(
            self._ip,
            self._uid,
            "/mutil_call.cgi?mutilreqs=get_power_port.cgi/get_power_cfg.cgi",
        )
        if info is None:
            self._uid, err = DahuaPOE_local_login(self._ip, self._password)
            if self._uid is None:
                raise ApiAuthError(
                    f"DahuaPOE_local_login({self._ip}): {err or 'unknown'}"
                )
            info, err = DahuaPOE_local_get(
                self._ip,
                self._uid,
                "/mutil_call.cgi?mutilreqs=get_power_port.cgi/get_power_cfg.cgi",
            )
            if info is None:
                raise ApiError(
                    f"DahuaPOE_local_get({self._ip}, /multi_call.cgi): {err or 'unknown'}"
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
            }

        # info[1] = DahuaPOE_local_get(self._ip, self._uid, "/get_power_cfg.cgi")
        # 1100/990/1100/207/0/893/0
        # Total/Available/Alert/Consumption/Reserved/Remaining/Perpetual
        power_cfg = info[1].split("/")
        self.tp = power_cfg[3]

        # self.keepalive = 1

    async def _async_switch_poe(self, port: str, enable: bool) -> None:
        try:
            async with async_timeout.timeout(2):
                return await self.hass.async_add_executor_job(
                    self._switch_poe_local, port, enable
                )
        except ApiError as err:
            self._uid = None
            raise UpdateFailed(f"Error communicating with API: {err}")

    def _switch_poe_local(self, port: str, enable: bool) -> None:
        if self.poe is None:
            raise ApiError(f"_switch_poe_local({ip}): poe is None")
        en = "1" if enable else "0"
        data = f"{port}/{en}/{self.poe[port]['ext']}/{self.poe[port]['watchdog']}/{self.poe[port]['force']}"
        res, err = DahuaPOE_local_post(self._ip, self._uid, "/set_power_port.cgi", data)
        if res is None:
            self._uid, err = DahuaPOE_local_login(self._ip, self._password)
            if self._uid is None:
                raise ApiAuthError(
                    f"DahuaPOE_local_login({self._ip}): {err or 'unknown'}"
                )
            res, err = DahuaPOE_local_post(
                self._ip, self._uid, "/set_power_port.cgi", data
            )
            if res is None:
                raise ApiError(
                    f"DahuaPOE_local_post({self._ip},/set_power_port.cgi, {data}): {err or 'unknown'}"
                )

        self.poe[port]["enable"] = en


class ApiError(HomeAssistantError):
    """ApiError"""


class ApiAuthError(HomeAssistantError):
    """ApiAuthError"""
