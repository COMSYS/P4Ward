"""Device controller"""

from __future__ import annotations
from typing import Any, Union
import logging
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
import typing

from framework.control_plane.helper import *
from framework.control_plane.data_plane.table import DPTable
from framework.control_plane.controllers.controller import Controller
from framework.control_plane.controllers.ac.ac_entry import (
    AcEntry,
    AcAction,
    AcDirection,
    AcProtocolValidatorId,
)
from framework.control_plane.controllers.ac.extensions import AcGooseExtension
from framework.control_plane.controllers.ac.protocols.modbus_protocol import configure_modbus_protocol

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch

ACL_TABLE_ACTIONS = [
    ["allow_from", "allow_filtered_from"],
    ["allow_to", "allow_filtered_to"],
]


class AcController(Controller):
    """Access Control Controller"""

    logger: logging.Logger

    _acl_tables: tuple[DPTable, DPTable]

    _entries: dict[int, AcEntry] = {}

    # Extensions
    _validator_goose_app_ids_table: DPTable

    def __init__(self, switch: "Switch") -> None:
        super().__init__(switch)

        self.logger = logging.getLogger("acl")
        self.logger.setLevel(logging.DEBUG)

        handler = logging.FileHandler("switch-ac.log", mode="w")
        handler.setFormatter(logging.getLogger().handlers[0].formatter)
        self.logger.addHandler(handler)

        self._acl_tables = (
            switch.data_plane.get_table("Ingress.acl.acl_from_device"),
            switch.data_plane.get_table("Ingress.acl.acl_to_device"),
        )

        self._validator_goose_app_ids_table = switch.data_plane.get_table(
            "Egress.goose_validator.goose_app_ids"
        )

        # Initialize protocol packet validators
        configure_modbus_protocol(switch)

    def add_entry(self, entry: AcEntry):
        """Add acl entry

        Args:
            entry (AclEntry): ACL entry
        """

        self.logger.info("Add ACL entry.")

        update: bool = False

        if old_entry := self._entries.get(entry.__hash__()):
            update = old_entry.update(entry)
            if update == False:
                return

        ######## MATCH LIST ########
        match_list: dict[str, Any] = {}

        if entry.src_network is not None:
            if entry.direction == AcDirection.TO and (
                entry.src_network is IPv4Network or entry.src_network is IPv6Network
            ):
                match_list["src_ip_address"] = {
                    "value": bytearray(ip_to_128(entry.src_network.network_address)),
                    "mask": bytearray(ip_to_128_mask(entry.src_network)),
                }
            elif entry.direction == AcDirection.FROM and isinstance(
                entry.src_network, int
            ):
                match_list["src_id"] = entry.src_network

        if entry.dst_network is not None:
            if entry.direction == AcDirection.FROM and (
                entry.dst_network is IPv4Network or entry.dst_network is IPv6Network
            ):
                match_list["dst_ip_address"] = {
                    "value": bytearray(ip_to_128(entry.dst_network.network_address)),
                    "mask": bytearray(ip_to_128_mask(entry.dst_network)),
                }
            elif entry.direction == AcDirection.TO and isinstance(
                entry.dst_network, int
            ):
                match_list["dst_id"] = entry.dst_network

        if entry.src_controller_name is not None:
            match_list["src_controller"] = bytearray(
                entry.get_src_controller_id_bytes()
            )

        if entry.src_manufacturer_name is not None:
            match_list["src_manufacturer"] = bytearray(
                entry.get_src_manufacturer_id_bytes()
            )

        if entry.src_model_name is not None:
            match_list["src_model"] = bytearray(entry.get_src_model_id_bytes())

        # if entry.src_port is not None:
        #     match_list["src_port"] = {
        #         "low": entry.src_port.min,
        #         "high": entry.src_port.max,
        #     }
        # else:
        #     match_list["src_port"] = {
        #         "low": 0,
        #         "high": 65535,
        #     }
        if entry.src_port is not None:
            match_list["src_port"] = {"value": entry.src_port.min}

        if entry.dst_controller_name is not None:
            match_list["dst_controller"] = bytearray(
                entry.get_dst_controller_id_bytes()
            )

        if entry.dst_manufacturer_name is not None:
            match_list["dst_manufacturer"] = bytearray(
                entry.get_dst_manufacturer_id_bytes()
            )

        if entry.dst_model_name is not None:
            match_list["dst_model"] = bytearray(entry.get_dst_model_id_bytes())

        # if entry.dst_port is not None:
        #     match_list["dst_port"] = {
        #         "low": entry.dst_port.min,
        #         "high": entry.dst_port.max,
        #     }
        # else:
        #     match_list["dst_port"] = {
        #         "low": 0,
        #         "high": 65535,
        #     }
        if entry.dst_port is not None:
            match_list["dst_port"] = {"value": entry.dst_port.min}

        if entry.protocol_mask is not None:
            mask = bytearray(entry.get_protocol_mask_bytes())
            match_list["protocol"] = {
                "value": mask,
                "mask": mask,
            }

        ######## ARGUMENT LIST ########
        argument_list: dict[str, Any] = {
            "ace_id": bytearray(entry.get_id_bytes()),
        }

        # Validator
        argument_list["protocol_validator"] = (
            entry.protocol_validator_id
            if entry.protocol_validator_id is not None
            else AcProtocolValidatorId.NO_PROTOCOL
        ).value
        argument_list["validator_flags"] = entry.validator_flags
        argument_list["protocol_validator_flags"] = entry.protocol_validator_flags

        set: bool = False
        if entry.tcp_initiation_direction is not None:
            set = True
            argument_list["direction"] = entry.tcp_initiation_direction.value

        action_name: str = (
            ACL_TABLE_ACTIONS[entry.direction.value][int(set)]
            if entry.action == AcAction.ACCEPT
            else "deny"
        )

        if update:
            if not self._acl_tables[entry.direction.value].entry_update(
                match_list=match_list,
                action_name=action_name,
                argument_list=argument_list,
            ):
                self.logger.debug("Failed to add to table 'acl entry'.")
        else:
            if not self._acl_tables[entry.direction.value].entry_add(
                match_list=match_list,
                action_name=action_name,
                argument_list=argument_list,
            ):
                self.logger.debug("Failed to add to table 'acl entry'.")

            # Handle extensions
            if entry.goose_ext is not None:
                self._add_goose_entry(entry, entry.goose_ext)

            # Add entry only after adding it to the data plane
            # This ensures the data plane always has more restriction than control plane
            self._entries[entry.__hash__()] = entry

        self.logger.info("ACL entry was successfully added.\n%s", entry)

    def _add_goose_entry(self, entry: AcEntry, ext: AcGooseExtension):
        if entry.direction == AcDirection.FROM:
            ace_id = bytearray(entry.get_id_bytes())

            if ext.app_id is not None:
                self._validator_goose_app_ids_table.entry_add(
                    match_list={
                        "ace_id": ace_id,
                        "app_id": ext.app_id & 0xFFFF,
                    },
                    action_name="NoAction",
                    argument_list={},
                )

    def _remove_entry(self, entry: AcEntry) -> bool:
        """Remove acl entry

        Args:
            entry (AclEntry): ACL entry
        """

        self.logger.info("Remove ACL entry.")

        id: int = entry.__hash__()

        if id in self._entries:
            # Remove entry before removing it from the data plane
            # This ensures the data plane always has more restriction than control plane
            self._entries.pop(id)

            match_list: dict[str, Any] = {}

            if entry.src_network is not None:
                if entry.direction == AcDirection.TO and (
                    entry.src_network is IPv4Network or entry.src_network is IPv6Network
                ):
                    match_list["src_ip_address"] = {
                        "value": bytearray(
                            ip_to_128(entry.src_network.network_address)
                        ),
                        "mask": bytearray(ip_to_128_mask(entry.src_network)),
                    }
                elif entry.direction == AcDirection.FROM and isinstance(
                    entry.src_network, int
                ):
                    match_list["src_id"] = entry.src_network

            if entry.dst_network is not None:
                if entry.direction == AcDirection.FROM and (
                    entry.dst_network is IPv4Network or entry.dst_network is IPv6Network
                ):
                    match_list["dst_ip_address"] = {
                        "value": bytearray(
                            ip_to_128(entry.dst_network.network_address)
                        ),
                        "mask": bytearray(ip_to_128_mask(entry.dst_network)),
                    }
                elif entry.direction == AcDirection.TO and isinstance(
                    entry.dst_network, int
                ):
                    match_list["dst_id"] = entry.dst_network

            if entry.src_controller_name is not None:
                match_list["src_controller"] = bytearray(
                    entry.get_src_controller_id_bytes()
                )

            if entry.src_manufacturer_name is not None:
                match_list["src_manufacturer"] = bytearray(
                    entry.get_src_manufacturer_id_bytes()
                )

            if entry.src_model_name is not None:
                match_list["src_model"] = bytearray(entry.get_src_model_id_bytes())

            # if entry.src_port is not None:
            #     match_list["src_port"] = {
            #         "low": entry.src_port.min,
            #         "high": entry.src_port.max,
            #     }
            # else:
            #     match_list["src_port"] = {
            #         "low": 0,
            #         "high": 65535,
            #     }
            if entry.src_port is not None:
                match_list["src_port"] = {"value": entry.src_port.min}

            if entry.dst_controller_name is not None:
                match_list["dst_controller"] = bytearray(
                    entry.get_dst_controller_id_bytes()
                )

            if entry.dst_manufacturer_name is not None:
                match_list["dst_manufacturer"] = bytearray(
                    entry.get_dst_manufacturer_id_bytes()
                )

            if entry.dst_model_name is not None:
                match_list["dst_model"] = bytearray(entry.get_dst_model_id_bytes())

            # if entry.dst_port is not None:
            #     match_list["dst_port"] = {
            #         "low": entry.dst_port.min,
            #         "high": entry.dst_port.max,
            #     }
            # else:
            #     match_list["dst_port"] = {
            #         "low": 0,
            #         "high": 65535,
            #     }
            if entry.dst_port is not None:
                match_list["dst_port"] = {"value": entry.dst_port.min}

            if entry.protocol_mask is not None:
                mask = bytearray(entry.get_protocol_mask_bytes())
                match_list["protocol"] = {
                    "value": mask,
                    "mask": mask,
                }

            if not self._acl_tables[entry.direction.value].entry_del(
                match_list,
            ):
                self.logger.debug("Failed to remove from table 'acl entry'.")

            # Handle extensions
            if entry.goose_ext is not None:
                self._remove_goose_entry(entry, entry.goose_ext)

            self.logger.info("ACL entry was successfully removed.\n%s", entry)

            return True
        else:
            logging.error("ACL entry does not exist.\n%s", entry)
            return False

    def _remove_goose_entry(self, entry: AcEntry, ext: AcGooseExtension):
        if entry.direction == AcDirection.FROM:
            ace_id = entry.get_id_bytes()

            if ext.app_id is not None:
                self._validator_goose_app_ids_table.entry_del(
                    match_list={
                        "ace_id": ace_id,
                        "app_id": ext.app_id & 0xFFFF,
                    }
                )

    def remove_entries(self, group: str, sub_group: str) -> bool:
        """Remove acl entries using group and sub group

        Args:
            group (str): Group name
            sub_group (Union[str, None], optional): Sub group name
        """
        result: bool = True

        entries = list(
            filter(
                lambda a: any(
                    (g == group and (sub_group is None or sub_group in s))
                    for (g, s) in a.groups.items()
                ),
                self._entries.values(),
            )
        )
        for entry in entries:
            if isinstance(g := entry.groups.get(group), set):
                g.remove(sub_group)
                if len(g) == 0:
                    entry.groups.pop(group)

            if len(entry.groups) == 0:
                result = result & self._remove_entry(entry)
        return result
