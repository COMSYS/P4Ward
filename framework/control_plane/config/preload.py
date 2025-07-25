"""Preload config"""

from __future__ import annotations
from typing import Any, Union
from pydantic import ConfigDict, BaseModel, Field

from framework.control_plane.config.preloads.l2_preload import L2Preload
from framework.control_plane.config.preloads.l3_preload import L3Preload
from framework.control_plane.config.preloads.arp_preload import ArpPreload
from framework.control_plane.config.preloads.mud_preload import MudPreload
from framework.control_plane.config.preloads.device_preload import DevicePreload


class PreloadConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    l2: L2Preload = Field(
        alias="l2",
        default=L2Preload(),
    )
    l3: L3Preload = Field(
        alias="l3",
        default=L3Preload(),
    )
    arp: ArpPreload = Field(
        alias="arp",
        default=ArpPreload(),
    )
    mud: MudPreload = Field(
        alias="mud",
        default=MudPreload(),
    )
    device: DevicePreload = Field(
        alias="device",
        default=DevicePreload(),
    )
