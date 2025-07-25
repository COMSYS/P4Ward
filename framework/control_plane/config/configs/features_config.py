"""Features configuration"""

from __future__ import annotations
from typing import Any, Union

from pydantic import BaseModel, ConfigDict, Field


class FeaturesConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    enable_monitoring: bool = Field(
        alias="enable-monitoring",
        default=False,
    )

    enable_cli: bool = Field(
        alias="enable-cli",
        default=True,
    )