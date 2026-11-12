"""My Home: end-to-end encrypted notices from Home Assistant to the My Home iPhone app.

Each iPhone creates its own 256-bit key, keeps it in its keychain and hands it
to Home Assistant once, over the same TLS connection the app already uses.
Home Assistant encrypts every notice with that key; Apple only ever carries a
placeholder ("Aviso nuevo") plus ciphertext, and the app's notification
extension decrypts it on the phone.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import time
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError, Unauthorized
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.storage import Store
from homeassistant.util.ssl import client_context

from .apns import APNs, KeyError_, encrypt, load_key
from .const import (
    CONF_KEY_ID,
    CONF_KEY_PATH,
    CONF_TEAM_ID,
    CONF_TOPIC,
    DOMAIN,
    EVENT_ACTION,
    STORAGE_KEY,
    STORAGE_VERSION,
)

_LOGGER = logging.getLogger(__name__)

LEVELS = ["passive", "active", "time-sensitive"]

ACTION_SCHEMA = vol.Schema(
    {
        vol.Required("action"): cv.string,
        vol.Required("title"): cv.string,
        vol.Optional("destructive", default=False): cv.boolean,
        vol.Optional("auth", default=False): cv.boolean,
        vol.Optional("foreground", default=False): cv.boolean,
    }
)

REGISTER_SCHEMA = vol.Schema(
    {
        vol.Required("device_id"): vol.All(cv.string, vol.Length(min=8, max=64)),
        vol.Required("token"): vol.Match(r"^[0-9a-fA-F]{32,200}$"),
        vol.Required("key"): cv.string,
        vol.Optional("sandbox", default=False): cv.boolean,
        vol.Optional("name", default="iPhone"): vol.All(cv.string, vol.Length(max=60)),
    }
)

UNREGISTER_SCHEMA = vol.Schema({vol.Required("device_id"): cv.string})

NOTIFY_SCHEMA = vol.Schema(
    {
        vol.Required("message"): cv.string,
        vol.Optional("title"): cv.string,
        vol.Optional("subtitle"): cv.string,
        vol.Optional("person"): cv.entity_ids,
        vol.Optional("open"): cv.string,
        vol.Optional("thread"): cv.string,
        vol.Optional("tag"): cv.string,
        vol.Optional("level", default="active"): vol.In(LEVELS),
        vol.Optional("sound", default=True): cv.boolean,
        vol.Optional("actions", default=[]): vol.All(cv.ensure_list, [ACTION_SCHEMA], vol.Length(max=4)),
    }
)

ACTION_SERVICE_SCHEMA = vol.Schema(
    {
        vol.Required("action"): cv.string,
        vol.Optional("tag"): cv.string,
    }
)


ACTIVITY_REGISTER_SCHEMA = vol.Schema(
    {
        vol.Required("device_id"): vol.All(cv.string, vol.Length(min=8, max=64)),
        vol.Optional("start_token"): vol.Match(r"^[0-9a-fA-F]{32,400}$"),
        vol.Optional("kind"): vol.All(cv.string, vol.Length(max=40)),
        vol.Optional("token"): vol.Match(r"^[0-9a-fA-F]{32,400}$"),
    }
)

LIVE_ACTIVITY_SCHEMA = vol.Schema(
    {
        vol.Optional("person"): cv.entity_ids,
        vol.Required("kind"): vol.All(cv.string, vol.Length(max=40)),
        vol.Optional("action", default="start"): vol.In(["start", "update", "end"]),
        vol.Optional("title", default=""): cv.string,
        vol.Optional("detail"): cv.string,
        vol.Optional("ends"): cv.datetime,
        vol.Optional("icon", default="house.fill"): cv.string,
        vol.Optional("tint"): cv.string,
        vol.Optional("sound", default=False): cv.boolean,
        vol.Optional("dismiss", default=0): vol.All(vol.Coerce(int), vol.Range(min=0, max=4 * 3600)),
    }
)

# ActivityKit decodes dates the Swift way: seconds since 2001-01-01.
APPLE_EPOCH = 978307200


class Hub:
    """Registered phones and the APNs client."""

    def __init__(self, hass: HomeAssistant, apns: APNs) -> None:
        self.hass = hass
        self.apns = apns
        self.store: Store[dict[str, Any]] = Store(hass, STORAGE_VERSION, STORAGE_KEY, private=True)
        self.devices: dict[str, dict[str, Any]] = {}

    async def load(self) -> None:
        data = await self.store.async_load() or {}
        self.devices = data.get("devices", {})

    async def save(self) -> None:
        await self.store.async_save({"devices": self.devices})


async def _is_admin(hass: HomeAssistant, user_id: str | None) -> bool:
    if user_id is None:
        return True  # automations and scripts run as the system
    user = await hass.auth.async_get_user(user_id)
    return bool(user and user.is_admin)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    try:
        key = await hass.async_add_executor_job(load_key, entry.data[CONF_KEY_PATH])
    except KeyError_ as err:
        raise HomeAssistantError(f"APNs key {err}: {entry.data[CONF_KEY_PATH]}") from err

    apns = await hass.async_add_executor_job(
        APNs, key, entry.data[CONF_KEY_ID], entry.data[CONF_TEAM_ID], entry.data[CONF_TOPIC], client_context()
    )
    hub = Hub(hass, apns)
    await hub.load()
    entry.runtime_data = hub

    async def register(call: ServiceCall) -> ServiceResponse:
        user_id = call.context.user_id
        if user_id is None:
            raise ServiceValidationError("Only the My Home app registers phones")
        try:
            raw = base64.b64decode(call.data["key"], validate=True)
        except ValueError as err:
            raise ServiceValidationError("Bad key") from err
        if len(raw) != 32:
            raise ServiceValidationError("Bad key")
        dev_id = call.data["device_id"]
        old = hub.devices.get(dev_id)
        if old and old.get("user_id") != user_id and not await _is_admin(hass, user_id):
            raise Unauthorized(context=call.context)
        keep = {k: old[k] for k in ("start_token", "activity_tokens") if old and k in old}
        hub.devices[dev_id] = {
            **keep,
            "token": call.data["token"].lower(),
            "key": call.data["key"],
            "sandbox": call.data["sandbox"],
            "name": call.data["name"],
            "user_id": user_id,
            "updated": time.time(),
        }
        await hub.save()
        return {"ok": True}

    async def unregister(call: ServiceCall) -> None:
        dev = hub.devices.get(call.data["device_id"])
        if not dev:
            return
        if dev.get("user_id") != call.context.user_id and not await _is_admin(hass, call.context.user_id):
            raise Unauthorized(context=call.context)
        hub.devices.pop(call.data["device_id"], None)
        await hub.save()

    async def notify(call: ServiceCall) -> ServiceResponse:
        d = call.data
        targets = list(hub.devices.items())
        if d.get("person"):
            users = set()
            for pid in d["person"]:
                st = hass.states.get(pid)
                if st and st.attributes.get("user_id"):
                    users.add(st.attributes["user_id"])
            targets = [(k, v) for k, v in targets if v.get("user_id") in users]

        secret = {"b": d["message"]}
        for src, dst in (("title", "t"), ("subtitle", "s"), ("open", "o"), ("thread", "th"), ("tag", "tag")):
            if d.get(src):
                secret[dst] = d[src]
        if d["actions"]:
            secret["a"] = [
                {"id": a["action"], "t": a["title"], "d": a["destructive"], "u": a["auth"], "f": a["foreground"]}
                for a in d["actions"]
            ]

        aps: dict[str, Any] = {
            "alert": {"title": "My Home", "body": "Aviso nuevo"},
            "mutable-content": 1,
            "interruption-level": d["level"],
        }
        if d["sound"]:
            aps["sound"] = "default"
        # Apple sees the collapse id, so it carries a hash of the tag, never the tag itself.
        collapse = hashlib.sha256(d["tag"].encode()).hexdigest()[:32] if d.get("tag") else None

        sent, failed, changed = 0, [], False
        for dev_id, dev in targets:
            payload = {"aps": aps, "v": 1, "e": encrypt(dev["key"], secret)}
            res = await hub.apns.send(dev["token"], payload, sandbox=dev["sandbox"], collapse_id=collapse,
                                      priority=5 if d["level"] == "passive" else 10)
            if not res.ok and res.reason == "BadDeviceToken":
                # Token from the other Apple environment (Xcode build vs TestFlight): try it once.
                retry = await hub.apns.send(dev["token"], payload, sandbox=not dev["sandbox"], collapse_id=collapse)
                if retry.ok:
                    dev["sandbox"] = not dev["sandbox"]
                    changed, res = True, retry
            if res.ok:
                sent += 1
            elif res.gone:
                hub.devices.pop(dev_id, None)
                changed = True
                failed.append({"device": dev.get("name"), "reason": res.reason})
            else:
                _LOGGER.warning("APNs refused a notice for %s: %s %s", dev.get("name"), res.status, res.reason)
                failed.append({"device": dev.get("name"), "reason": res.reason or str(res.status)})
        if changed:
            await hub.save()
        return {"sent": sent, "failed": failed}

    def _targets(person: list[str] | None) -> list[tuple[str, dict[str, Any]]]:
        targets = list(hub.devices.items())
        if person:
            users = set()
            for pid in person:
                st = hass.states.get(pid)
                if st and st.attributes.get("user_id"):
                    users.add(st.attributes["user_id"])
            targets = [(k, v) for k, v in targets if v.get("user_id") in users]
        return targets

    async def activity_register(call: ServiceCall) -> None:
        """The app hands over its Live Activity tokens (start, and one per running activity)."""
        dev = hub.devices.get(call.data["device_id"])
        if not dev:
            raise ServiceValidationError("Unknown phone")
        if dev.get("user_id") != call.context.user_id and not await _is_admin(hass, call.context.user_id):
            raise Unauthorized(context=call.context)
        if call.data.get("start_token"):
            dev["start_token"] = call.data["start_token"].lower()
        if call.data.get("kind") and call.data.get("token"):
            dev.setdefault("activity_tokens", {})[call.data["kind"]] = call.data["token"].lower()
        await hub.save()

    async def live_activity(call: ServiceCall) -> ServiceResponse:
        """Start, update or end a Live Activity (lock screen, Dynamic Island, CarPlay).

        Unlike notices these cannot be end-to-end encrypted (iOS draws them
        without running app code), so keep them to plain, non-private words.
        """
        d = call.data
        now = int(time.time())
        state: dict[str, Any] = {"title": d["title"]}
        if d.get("detail"):
            state["detail"] = d["detail"]
        if d.get("tint"):
            state["tint"] = d["tint"]
        if d.get("ends"):
            state["ends"] = d["ends"].timestamp() - APPLE_EPOCH
        aps: dict[str, Any] = {"timestamp": now, "event": d["action"], "content-state": state}
        if d["action"] == "start":
            aps["attributes-type"] = "HomeActivityAttributes"
            aps["attributes"] = {"kind": d["kind"], "icon": d["icon"]}
            alert: dict[str, Any] = {"title": d["title"], "body": d.get("detail") or ""}
            if d["sound"]:
                alert["sound"] = "default"
            aps["alert"] = alert
            if d.get("ends"):
                aps["stale-date"] = int(d["ends"].timestamp())
        if d["action"] == "end":
            aps["dismissal-date"] = now + d["dismiss"]
        topic = f"{hub.apns.topic}.push-type.liveactivity"

        sent, failed, changed = 0, [], False
        for _, dev in _targets(d.get("person")):
            token = dev.get("start_token") if d["action"] == "start" else dev.get("activity_tokens", {}).get(d["kind"])
            if not token:
                failed.append({"device": dev.get("name"), "reason": "no token yet"})
                continue
            res = await hub.apns.send(token, {"aps": aps}, sandbox=dev["sandbox"], push_type="liveactivity", topic=topic)
            if res.ok:
                sent += 1
                if d["action"] == "end":
                    dev.get("activity_tokens", {}).pop(d["kind"], None)
                    changed = True
            else:
                _LOGGER.warning("APNs refused a live activity for %s: %s %s", dev.get("name"), res.status, res.reason)
                failed.append({"device": dev.get("name"), "reason": res.reason or str(res.status)})
        if changed:
            await hub.save()
        return {"sent": sent, "failed": failed}

    async def action(call: ServiceCall) -> None:
        data = {"action": call.data["action"], "source": DOMAIN}
        if call.data.get("tag"):
            data["tag"] = call.data["tag"]
        hass.bus.async_fire(EVENT_ACTION, data, context=call.context)

    async def devices(call: ServiceCall) -> ServiceResponse:
        out = []
        for dev in hub.devices.values():
            user = await hass.auth.async_get_user(dev.get("user_id") or "")
            out.append({
                "name": dev.get("name"),
                "user": user.name if user else None,
                "environment": "sandbox" if dev.get("sandbox") else "production",
                "registered": time.strftime("%Y-%m-%d %H:%M", time.localtime(dev.get("updated", 0))),
                "live_activities": bool(dev.get("start_token")),
            })
        return {"devices": out}

    hass.services.async_register(DOMAIN, "register", register, REGISTER_SCHEMA, supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "unregister", unregister, UNREGISTER_SCHEMA)
    hass.services.async_register(DOMAIN, "notify", notify, NOTIFY_SCHEMA, supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "action", action, ACTION_SERVICE_SCHEMA)
    hass.services.async_register(DOMAIN, "devices", devices, vol.Schema({}), supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, "activity_register", activity_register, ACTIVITY_REGISTER_SCHEMA)
    hass.services.async_register(DOMAIN, "live_activity", live_activity, LIVE_ACTIVITY_SCHEMA,
                                 supports_response=SupportsResponse.OPTIONAL)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    for service in ("register", "unregister", "notify", "action", "devices", "activity_register", "live_activity"):
        hass.services.async_remove(DOMAIN, service)
    await entry.runtime_data.apns.close()
    return True
