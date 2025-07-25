from __future__ import annotations
from typing import Any, Union
from bfrt_grpc import client


class DPTable:
    """Data plane table connection"""

    _table: Union[client._Table, None]

    def __init__(self, table: Union[client._Table, None]) -> None:
        # Table will be None when it is being mocked
        self._table = table

        if self._table is None:
            return

        self._table.entry_del(client.Target(device_id=0, pipe_id=0xFFFF))

    def _make_tuple(
        self,
        name: str,
        value: Any = None,
        prefix_length: Any = None,
        mask: Any = None,
        low: Any = None,
        high: Any = None,
    ) -> client.KeyTuple:
        return client.KeyTuple(
            name, value=value, prefix_len=prefix_length, mask=mask, low=low, high=high
        )

    def entry_add(
        self,
        match_list: dict[str, Any],
        action_name: Union[str, None],
        argument_list: dict[str, Any],
    ) -> bool:
        """Add data plane table entry

        Args:
            match_list (dict[str, Any]): match values
            action_name (str): name of the action that will be called
            argument_list (dict[str, Any]): arguments passed to the action
        """

        if self._table is None:
            return True

        # Prepare key list
        key_list: list[client.KeyTuple] = []
        for name, value in match_list.items():
            if isinstance(value, dict):
                key_list.append(self._make_tuple(name=name, **value))
            else:
                key_list.append(client.KeyTuple(name, value))
        key: client._Key = self._table.make_key(key_list)

        # Prepare data list
        data_list: list[client.DataTuple] = []
        for name, value in argument_list.items():
            data_list.append(client.DataTuple(name, value))
        data: client._Data = self._table.make_data(data_list, action_name=action_name)

        # Add entry
        try:
            self._table.entry_add(client.Target(), [key], [data])
            return True
        except Exception as error:
            return False

    def entry_update(
        self,
        match_list: dict[str, Any],
        action_name: Union[str, None],
        argument_list: dict[str, Any],
    ) -> bool:
        """Update data plane table entry

        Args:
            match_list (dict[str, Any]): match values
            action_name (str): name of the action that will be called
            argument_list (dict[str, Any]): arguments passed to the action
        """

        if self._table is None:
            return True

        # Prepare key list
        key_list: list[client.KeyTuple] = []
        for name, value in match_list.items():
            if isinstance(value, dict):
                key_list.append(self._make_tuple(name=name, **value))
            else:
                key_list.append(client.KeyTuple(name, value))
        key: client._Key = self._table.make_key(key_list)

        # Prepare data list
        data_list: list[client.DataTuple] = []
        for name, value in argument_list.items():
            data_list.append(client.DataTuple(name, value))
        data: client._Data = self._table.make_data(data_list, action_name=action_name)

        # Add entry
        try:
            self._table.entry_mod(client.Target(), [key], [data])
            return True
        except Exception as error:
            return False

    def entry_del(self, match_list: dict[str, Any]) -> bool:
        """Delete data plane table entry

        Args:
            match_list (list[tuple[str, str]]): match values
        """

        if self._table is None:
            return True

        # Prepare key list
        key_list: list[client.KeyTuple] = []
        for name, value in match_list.items():
            if isinstance(value, dict):
                key_list.append(self._make_tuple(name=name, **value))
            else:
                key_list.append(client.KeyTuple(name, value))
        key: client._Key = self._table.make_key(key_list)

        # Add entry
        try:
            self._table.entry_del(client.Target(), [key])
            return True
        except Exception as error:
            return False

    def entry_get(
        self,
        match_list: dict[str, Any],
        argument_list: list[str],
        out_argument_list: list[Any],
    ) -> bool:
        """Add data plane table entry

        Args:
            match_list (dict[str, Any]): match values
            action_name (str): name of the action that will be called
            argument_list (dict[str, Any]): arguments passed to the action
        """

        if self._table is None:
            return True

        # Prepare key list
        key_list: list[client.KeyTuple] = []
        for name, value in match_list.items():
            if isinstance(value, dict):
                key_list.append(self._make_tuple(name=name, **value))
            else:
                key_list.append(client.KeyTuple(name, value))
        key: client._Key = self._table.make_key(key_list)

        # # Prepare data list
        # data_list: list[client.DataTuple] = []
        # for name, value in argument_list.items():
        #     data_list.append(client.DataTuple(name, value))
        # data: client._Data = self._table.make_data(data_list, action_name=action_name)

        # Add entry
        try:
            response = self._table.entry_get(client.Target(), [key])
            for entry in response:
                for name in argument_list:
                    out_argument_list.append(entry[0].field_dict[name].val)

            return True
        except Exception as error:
            return False
