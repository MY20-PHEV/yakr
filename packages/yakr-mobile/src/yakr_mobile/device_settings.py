from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DeviceSettings:
    on_wifi: bool = True
    charging: bool = False
    battery_percent: int = 100
    relay_enabled: bool = False
    relay_wifi_only: bool = True
    relay_charging_only: bool = True
    fetch_interval_secs_battery: int = 300
    fetch_interval_secs_charging: int = 30
    fetch_interval_secs_low_battery: int = 900
    low_battery_threshold: int = 20


def fetch_poll_interval(settings: DeviceSettings) -> int:
    if settings.charging:
        return settings.fetch_interval_secs_charging
    if settings.battery_percent <= settings.low_battery_threshold:
        return settings.fetch_interval_secs_low_battery
    return settings.fetch_interval_secs_battery


def relay_may_run(settings: DeviceSettings) -> bool:
    if not settings.relay_enabled:
        return False
    if settings.relay_wifi_only and not settings.on_wifi:
        return False
    if settings.relay_charging_only and not settings.charging:
        return False
    return True
