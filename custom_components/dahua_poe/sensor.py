from homeassistant.core import HomeAssistant, callback
from homeassistant.const import (
    UnitOfElectricPotential,
    UnitOfPower,
    UnitOfDataRate,
    EntityCategory,
)
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
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
        new_devices.append(PortPowerSensor(coordinator, ""))

        for port in coordinator.poe:
            new_devices.append(PortPowerSensor(coordinator, port))

    if new_devices:
        async_add_entities(new_devices)


class PortBaseSensor(CoordinatorEntity[DahuaPOE_Coordinator], SensorEntity):
    _desc_name = None
    _id_name = None
    _total = False

    def __init__(self, coordinator: DahuaPOE_Coordinator, port: str):
        self._port = port
        super().__init__(coordinator, context=(coordinator.sn))
        # CoordinatorEntity.__init__(self, coordinator, context=(pid, sn))
        if port == "":
            Total = "Total " if self._total else ""
            total = "total_" if self._total else ""
            self._attr_name = f"{coordinator.desc} {Total}{self._desc_name}"
            self._attr_unique_id = f"{coordinator.sn}_{total}{self._id_name}".lower()
            self.entity_id = f"{DOMAIN}.{coordinator.sn}_{total}{self._id_name}".lower()
        else:
            self._attr_name = f"{coordinator.desc} Port {port} {self._desc_name}"
            self._attr_unique_id = f"{coordinator.sn}_{port}_{self._id_name}".lower()
            self.entity_id = f"{DOMAIN}.{coordinator.sn}_{port}_{self._id_name}".lower()
        self._attr_device_info = coordinator.device_info

    @callback
    def _handle_coordinator_update(self) -> None:
        self._attr_native_value = self._handle_coordinator_update_fix(self._port)
        self.async_write_ha_state()
        super()._handle_coordinator_update()

    def _handle_coordinator_update_fix(self, port: str):
        return ""

    #    def _kb2mb(self, val):
    #        return ("0." + val) if (isinstance(val, str) and val.find(".") < 0) else val

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()


class PortPowerSensor(PortBaseSensor):
    _attr_native_unit_of_measurement = UnitOfPower.WATT
    _attr_device_class = SensorDeviceClass.POWER
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:flash"

    _desc_name = "Power"
    _id_name = "power"
    _total = True

    def _handle_coordinator_update_fix(self, port: str):
        if port == "":
            return int(self.coordinator.tp) / 10.0
        else:
            return int(self.coordinator.poe[self._port]["power"]) / 10.0
