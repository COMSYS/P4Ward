from __future__ import annotations
from typing import Any
import socket
import os
import sys


verstr=str(sys.version_info.major)+'.'+str(sys.version_info.minor)
sys.path.append(os.path.expandvars('$SDE/install/lib/python'+verstr+'/site-packages/'))
sys.path.append(os.path.expandvars('$SDE/install/lib/python'+verstr+'/site-packages/tofino/'))
sys.path.append(os.path.expandvars('$SDE/install/lib/python'+verstr+'/site-packages/tofino/bfrt_grpc/'))
from bfrt_grpc import client
# import tm_api_rpc.tm as tm

from framework.control_plane.data_plane.table import DPTable
from framework.control_plane.data_plane.register import DPRegister

class DataPlane:
    """Data plane manager"""

    _bf_client: client.ClientInterface
    _bf_runtime_info: client._BfRtInfo
    _socket: socket.socket
    _mock: bool

    def __init__(self, push: str, pull: str, mock: bool = False) -> None:
        self._mock = mock

        if self._mock:
            return
        
        # Connect to push service
        try:
            self._bf_client = client.ClientInterface(
                grpc_addr=push, client_id=0, device_id=0
            )
            self._bf_runtime_info = self._bf_client.bfrt_info_get(p4_name=None)
            self._bf_client.bind_pipeline_config(
                p4_name=self._bf_runtime_info.p4_name
            )
        except Exception as error:
            raise Exception(f"Failed to connect to data plane push service.") from error

        # Connect to pull service
        try:
            self._socket = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)
            )
            self._socket.bind((pull, 0))
            self._socket.setblocking(False)
        except Exception as error:
            raise Exception(f"Failed to connect to data plane pull service.") from error

    def __del__(self) -> None:
        self._bf_client.__del__()

    def get_table(self, name: str, mock: bool = False) -> DPTable:
        """Get data plane table

        Args:
            name (str): Table name

        Raises:
            Exception: Table does not exist

        Returns:
            DPTable: Data plane table
        """

        if self._mock or mock:
            return DPTable(None)

        table: client._Table | None = self._bf_runtime_info.table_dict.get(name)
        if table is None:
            raise Exception(f"Table '{name}' does not exist.")

        return DPTable(table)

    def get_register(self, name: str, mock: bool = False) -> DPRegister:
        """Get data plane register

        Args:
            name (str): Register name

        Raises:
            Exception: Register does not exist

        Returns:
            DPRegister: Data plane register
        """

        if self._mock or mock:
            return DPRegister(None)

        table: client._Table | None = self._bf_runtime_info.table_dict.get(name)
        if table is None:
            raise Exception(f"Register '{name}' does not exist.")

        return DPRegister(table)

    def get_socket(self) -> socket.socket:
        return self._socket
