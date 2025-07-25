"""Preload config"""

from __future__ import annotations
from typing import Any, Union, List
from ipaddress import IPv4Address, IPv6Address
from pydantic import BaseModel, ConfigDict, Field, field_serializer
from pydantic_extra_types.mac_address import MacAddress


class FunctionCode(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    value: int = Field(
        alias="value",
    )

    set_disable_write_flag: bool = Field(
        alias="disable-write-flag",
        default=False,
    )

    set_disable_extensions_flag: bool = Field(
        alias="disable-extensions-flag",
        default=True,
    )
    set_disable_coils_flag: bool = Field(
        alias="disable-coils-flag",
        default=False,
    )
    set_disable_discrete_inputs_flag: bool = Field(
        alias="disable-discrete-inputs-flag",
        default=False,
    )
    set_disable_holding_registers_flag: bool = Field(
        alias="disable-holding-registers-flag",
        default=False,
    )
    set_disable_input_registers_flag: bool = Field(
        alias="disable-input-registers-flag",
        default=False,
    )
    set_disable_file_record_flag: bool = Field(
        alias="disable-file-record-flag",
        default=False,
    )
    set_disable_fifo_flag: bool = Field(
        alias="disable-fifo-flag",
        default=False,
    )
    set_disable_device_identification_flag: bool = Field(
        alias="disable-device-identification-flag",
        default=False,
    )

class ExceptionCode(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    value: int = Field(
        alias="value",
    )

class ModbusProtocol(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    load_defaults: bool = Field(
        alias="load-defaults",
        default=True,
    )

    function_codes: List[FunctionCode] = Field(
        alias="functions",
        default=[],
    )

    exception_codes: List[ExceptionCode] = Field(
        alias="exceptions",
        default=[],
    )
