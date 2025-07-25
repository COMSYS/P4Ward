"""Switch config"""

from __future__ import annotations
from typing import Any, Union

from pydantic import BaseModel, ConfigDict, Field

from framework.control_plane.config.configs.data_plane_config import DataPlaneConfig
from framework.control_plane.config.configs.features_config import FeaturesConfig
from framework.control_plane.config.configs.router_hello_config import RouterHelloConfig
from framework.control_plane.config.configs.bandwidth_config import BandwidthConfig
from framework.control_plane.config.configs.networks_config import NetworksConfig
from framework.control_plane.config.configs.dns_config import DnsConfig
from framework.control_plane.config.configs.auth_config import AuthConfig
from framework.control_plane.config.configs.mud_config import MudConfig


class SwitchConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    data_plane: DataPlaneConfig = Field(
        alias="data-plane",
        default=DataPlaneConfig(),
    )

    router_hello: RouterHelloConfig = Field(
        alias="router-hello",
        default=RouterHelloConfig(),
    )
    bandwidth: BandwidthConfig = Field(
        alias="bandwidth",
        default=BandwidthConfig(),
    )
    networks: NetworksConfig = Field(
        alias="networks",
        default=NetworksConfig(),
    )
    dns: DnsConfig = Field(
        alias="dns",
        default=DnsConfig(),
    )
    auth: AuthConfig = Field(
        alias="auth",
        default=AuthConfig(),
    )
    mud: MudConfig = Field(
        alias="mud",
        default=MudConfig(),
    )

    features: FeaturesConfig = Field(
        alias="features",
        default=FeaturesConfig(),
    )
