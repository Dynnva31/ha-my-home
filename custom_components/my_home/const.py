"""Constants for My Home (end-to-end encrypted notices to the My Home iPhone app)."""

DOMAIN = "my_home"

CONF_KEY_PATH = "key_path"
CONF_KEY_ID = "key_id"
CONF_TEAM_ID = "team_id"
CONF_TOPIC = "topic"

DEFAULT_KEY_PATH = "/config/my_home_apns.p8"
DEFAULT_KEY_ID = "6ZY7RQBGQT"
DEFAULT_TEAM_ID = "Q5TVAPEVHM"
DEFAULT_TOPIC = "com.danival.home"

STORAGE_KEY = "my_home.devices"
STORAGE_VERSION = 1

# Fired when someone taps a button on a notice. Same event the Home Assistant
# companion app fires, so existing automations keep working unchanged.
EVENT_ACTION = "mobile_app_notification_action"
