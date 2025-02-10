from homeassistant.core import HomeAssistant, callback
from homeassistant.config_entries import ConfigEntry
from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, LOGGER
from .coordinator import DahuaPOE_Coordinator


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: DahuaPOE_Coordinator = hass.data[DOMAIN][config_entry.entry_id]
    new_devices = []

    if coordinator.device_info and coordinator.poe:
        for port in coordinator.poe:
            new_devices.append(POEPortSwitch(coordinator, port))

    if new_devices:
        async_add_entities(new_devices)


class POEPortSwitch(CoordinatorEntity[DahuaPOE_Coordinator], SwitchEntity):
    def __init__(self, coordinator: DahuaPOE_Coordinator, port: str):
        self._port = port
        super().__init__(coordinator, context=(coordinator.sn))
        self._attr_name = f"{coordinator.desc} Port {port} POE"
        self._attr_unique_id = f"{coordinator.sn}_{port}_switch".lower()
        self.entity_id = f"{DOMAIN}.{coordinator.sn}_{port}_switch".lower()
        self._attr_device_info = coordinator.device_info

    @property
    def icon(self):
        if self.is_on:
            return "mdi:ethernet"
        else:
            return "mdi:ethernet-off"

    @callback
    def _handle_coordinator_update(self) -> None:
        self._attr_is_on = self.coordinator.poe[self._port]["enable"] != "0"
        self.async_write_ha_state()
        super()._handle_coordinator_update()

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()

    async def async_turn_on(self, **kwargs):
        """Turn on."""
        await self.coordinator._async_switch_poe(self._port, True)
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs) -> None:
        """Turn off."""
        await self.coordinator._async_switch_poe(self._port, False)
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()
