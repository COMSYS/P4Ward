"""Protocol config"""

from __future__ import annotations
from typing import Any, Union
from pydantic import ConfigDict, BaseModel, Field

from framework.control_plane.config.protocols.modbus_protocol import ModbusProtocol


class ProtocolConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    modbus: ModbusProtocol = Field(
        alias="modbus",
        default=ModbusProtocol(),
    )
