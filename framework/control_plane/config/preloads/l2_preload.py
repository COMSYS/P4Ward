"""L2 Preload config"""

from __future__ import annotations
from typing import Any, Union, List
from pydantic import BaseModel, ConfigDict, Field
from pydantic_extra_types.mac_address import MacAddress

class RouteEntry(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    mac_address: MacAddress = Field(
        alias="mac-address",
    )
    port: int = Field(
        alias="port",
    )

class L2Preload(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    routes: List[RouteEntry] = Field(
        alias="routes",
        default=[],
    )
