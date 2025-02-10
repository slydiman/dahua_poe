from __future__ import annotations

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigEntry
from homeassistant.const import CONF_IP_ADDRESS, CONF_PASSWORD
from .const import DOMAIN, LOGGER
from .protocol import (
    DahuaPOE_local_get,
    DahuaPOE_local_login,
)


class DahuaPOE_ConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 4

    async def async_step_user(self, user_input: dict[str, str] = None) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input:
            ip = user_input[CONF_IP_ADDRESS]
            password = user_input[CONF_PASSWORD]
            pass_len = len(password)
            if pass_len < 8:
                errors[CONF_PASSWORD] = "invalid_password"
            else:

                def login():
                    uid, err = DahuaPOE_local_login(ip, password)
                    if uid:
                        info = DahuaPOE_local_get(ip, uid, "/get_device_info.cgi")
                        if info:
                            # POE8/DH-CS4010-8ET-110/AH08EBBPAJ00651/F8:CE:07:7B:51:86/V1.001.0000000.7.R/2024-09-28/12919/1/V2.4
                            uid = info.split("/")[0]
                        else:
                            uid = ip
                    return uid, err

                title, err = await self.hass.async_add_executor_job(login)
                if title is None:
                    errors["base"] = err
                else:
                    return self.async_create_entry(title=title, data=user_input)

        # If there is no user input or there were errors,
        # show the form again, including any errors that were found with the input.
        data_schema = vol.Schema(
            {
                vol.Required(CONF_IP_ADDRESS, default=ip if user_input else None): str,
                vol.Required(
                    CONF_PASSWORD, default=password if user_input else None
                ): str,
            }
        )
        return self.async_show_form(
            step_id="user",
            data_schema=data_schema,
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> FlowResult:
        """Handle re-authentication."""
        self.entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, str] = None
    ) -> FlowResult:
        """Confirm re-authentication"""
        errors: dict[str, str] = {}
        ip = self.entry.data.get(CONF_IP_ADDRESS)
        password = self.entry.data.get(CONF_PASSWORD)
        if user_input:
            ip = user_input.get(CONF_IP_ADDRESS, ip)
            password = user_input.get(CONF_PASSWORD, password)
            pass_len = len(password)
            if pass_len < 8:
                errors[CONF_PASSWORD] = "invalid_password"
            else:

                def login():
                    return DahuaPOE_local_login(ip, password)

                uid, err = await self.hass.async_add_executor_job(login)
                if uid is None:
                    errors["base"] = err
                else:
                    assert self.entry is not None
                    self.hass.config_entries.async_update_entry(
                        self.entry,
                        data={
                            **self.entry.data,
                            CONF_IP_ADDRESS: ip,
                            CONF_PASSWORD: password,
                        },
                    )
                    await self.hass.config_entries.async_reload(self.entry.entry_id)
                    return self.async_abort(reason="reauth_successful")

        data_schema = vol.Schema(
            {
                vol.Required(CONF_IP_ADDRESS, default=ip if user_input else None): str,
                vol.Required(
                    CONF_PASSWORD, default=password if user_input else None
                ): str,
            }
        )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=data_schema,
            errors=errors,
        )
