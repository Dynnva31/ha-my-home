# My Home for Home Assistant

End-to-end encrypted notices from Home Assistant to the private **My Home** iPhone app.

- Each iPhone creates its own AES-256 key and registers it once (`my_home.register`).
- `my_home.notify` encrypts the notice for each phone; Apple only carries ciphertext.
- Taps on notice buttons fire `mobile_app_notification_action`.

The APNs signing key (.p8) stays in Home Assistant; this repository holds no secrets.
