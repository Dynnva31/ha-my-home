"""Set-up: points the integration at the APNs key file. The key itself never leaves Home Assistant."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult

from .apns import KeyError_, load_key
from .const import (
    CONF_KEY_ID,
    CONF_KEY_PATH,
    CONF_TEAM_ID,
    CONF_TOPIC,
    DEFAULT_KEY_ID,
    DEFAULT_KEY_PATH,
    DEFAULT_TEAM_ID,
    DEFAULT_TOPIC,
    DOMAIN,
)


class MyHomeConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                await self.hass.async_add_executor_job(load_key, user_input[CONF_KEY_PATH])
            except KeyError_ as err:
                errors["base"] = f"key_{err}"
            else:
                return self.async_create_entry(title="My Home", data=user_input)
        schema = vol.Schema(
            {
                vol.Required(CONF_KEY_PATH, default=DEFAULT_KEY_PATH): str,
                vol.Required(CONF_KEY_ID, default=DEFAULT_KEY_ID): str,
                vol.Required(CONF_TEAM_ID, default=DEFAULT_TEAM_ID): str,
                vol.Required(CONF_TOPIC, default=DEFAULT_TOPIC): str,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)
