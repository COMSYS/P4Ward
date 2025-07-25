"""Router Hello configuration"""

from __future__ import annotations
from typing import Any, Union, Dict

from pydantic import BaseModel, ConfigDict, Field
from pydantic_extra_types.mac_address import MacAddress


class RouterHelloConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    addresses: Dict[MacAddress, int] = Field(
        alias="addresses",
        default={},
    )
