from __future__ import annotations
from typing import Any, Union
from bfrt_grpc import client, bfruntime_pb2


class DPRegister:
    """Data plane register connection"""

    _name: str
    _table: Union[client._Table, None]

    def __init__(self, table: Union[client._Table, None]) -> None:
        # Table will be None when it is being mocked
        self._table = table

        if self._table is None:
            return

        self._name = self._table.info.name.split('.', 1)[1]
        self._table.entry_del(client.Target(device_id=0, pipe_id=0xFFFF))

    def set(
        self,
        index: Union[int, bytearray],
        value: Union[str, int, bytearray],
    ) -> bool:
        """Set value

        Args:
            index (Union[int, bytearray]): value index
            value (Union[str, int, bytearray]): value

        Returns:
            bool: Successfulness
        """

        if self._table is None:
            return True

        # Prepare key list
        key: client._Key = self._table.make_key(
            [client.KeyTuple("$REGISTER_INDEX", index)]
        )

        # Prepare data list
        data: client._Data = self._table.make_data([client.DataTuple(f"{self._name}.f1", value)])

        # Add entry
        try:
            self._table.entry_add(client.Target(), [key], [data])
            return True
        except:
            return False

    def set_multiple(
        self,
        values: list[tuple[Union[int, bytearray], Union[str, int, bytearray]]],
    ) -> bool:
        """Set multiple values

        Args:
            values (list[tuple[Union[int, bytearray], Union[str, int, bytearray]]]): List of index value pairs

        Returns:
            bool: Successfulness
        """

        if self._table is None:
            return True

        # Prepare key and data lists
        key_list: list[client._Key] = []
        data_list: list[client._Data] = []
        for index, value in values:
            key_list.append(
                self._table.make_key(
                    [client.KeyTuple("$REGISTER_INDEX", index)],
                ),
            )
            data_list.append(
                self._table.make_data(
                    [client.DataTuple(f"{self._name}.f1", value)],
                ),
            )

        # Add entry
        try:
            self._table.entry_add(client.Target(), key_list, data_list)
            return True
        except:
            return False
