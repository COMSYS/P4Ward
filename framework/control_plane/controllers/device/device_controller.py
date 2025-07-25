"""Device controller"""

from __future__ import annotations
from typing import Any, Union
import logging
from macaddress import EUI48
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
import typing
import asyncio

from framework.control_plane.tracing import TRACER
from framework.control_plane.helper import *
from framework.control_plane.data_plane.table import DPTable
from framework.control_plane.controllers.controller import Controller
from framework.control_plane.controllers.device.device import Device, Ignore

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch

DEVICE_TABLE_ACTIONS = [
    ["match_src_device", "match_src_device_limit"],
    ["match_dst_device", "match_dst_device_limit"],
]


class DeviceController(Controller):
    """Device Controller"""

    logger: logging.Logger

    _src_device_table: DPTable
    _dst_device_tables: tuple[DPTable, DPTable]
    _meter_tables: tuple[DPTable, DPTable]

    _unique_ids: set[int]
    _devices: dict[EUI48, Device]
    _src_ignores: dict[EUI48, Ignore]
    _dst_ignores: dict[EUI48, Ignore]

    def __init__(self, switch: "Switch") -> None:
        super().__init__(switch)

        self.logger = logging.getLogger("device")
        self.logger.setLevel(logging.DEBUG)

        handler = logging.FileHandler("switch-device.log", mode="w")
        handler.setFormatter(logging.getLogger().handlers[0].formatter)
        self.logger.addHandler(handler)

        self._src_device_table = switch.data_plane.get_table(
            "Ingress.device_validator.device_src",
        )

        self._dst_device_tables = (
            switch.data_plane.get_table(
                "Ingress.device_validator.device_dst_mac",
            ),
            switch.data_plane.get_table(
                "Ingress.device_validator.device_dst_ip",
            ),
        )

        self._meter_tables = (
            switch.data_plane.get_table("Ingress.device_validator.src_traffic_meter"),
            switch.data_plane.get_table("Ingress.device_validator.dst_traffic_meter"),
        )

        self._unique_ids = set()
        self._devices = {}
        self._src_ignores = {}
        self._dst_ignores = {}

    async def load_preload(self):
        for entry in self._switch.preload.device.devices:
            if profile := await self._switch.mud.get_profile(entry.profile):
                self.add_device(
                    Device(
                        port=entry.port,
                        mac_address=EUI48(entry.mac_address),
                        ip_addresses=entry.ip_addresses,
                        profile=profile,
                        independent=entry.independent,
                    )
                )

    ############ DEVICE ############

    def add_device(self, device: Device) -> bool:
        """Add device

        Args:
            device (Device): Device

        Returns:
            bool: Successfulness
        """

        self.logger.info("Add device '%s'", device.mac_address)

        # Check source ignore list
        if device.mac_address in self._src_ignores:
            self.logger.error(
                "Device '%s' is already marked as a src ignore.",
                device.mac_address,
            )
            return False

        # Check destination ignore list
        if device.mac_address in self._dst_ignores:
            self.logger.error(
                "Device '%s' is already marked as a dst ignore.",
                device.mac_address,
            )
            return False

        TRACER.info(f"Adding device '{device.mac_address}': start")

        ip_addresses = device.ip_addresses

        if (device2 := self._devices.get(device.mac_address)) is not None:
            if (
                device.port != device2.port
                or device.profile.url != device2.profile.url
                or device.controller_name != device2.controller_name
                or device.manufacturer_name != device2.manufacturer_name
                or device.model_name != device2.model_name
            ):
                self.logger.error(
                    "Device '%s' has two different definitions",
                    device.mac_address,
                )
                return False

            device = device2
        else:
            device.ip_addresses = []

            try:
                device.local_id = next(
                    id for id in range(1, 1024) if id not in self._unique_ids
                )
            except:
                self.logger.error(
                    "Failed to allocate unique id for device '%s'.",
                    device.mac_address,
                )
                return False

            self._unique_ids.add(device.local_id)
            self._devices[device.mac_address] = device

            self._switch.l2.add_route(device.mac_address, device.port)

        # Add ip addresses if they are not already defined
        try:
            if device.independent:
                self._switch.mud.enable_profile(None, None, None, device.profile)

            for ip_address in ip_addresses:
                if self._add_ip_address(device, ip_address):
                    self._switch.l3.add_route(
                        ip_address, device.mac_address, device.port
                    )

                    if not device.independent:
                        self._switch.mud.enable_profile(
                            device.port,
                            device.get_id(ip_address),
                            ip_address,
                            device.profile,
                        )
        except Exception as error:
            self.logger.error(
                "Failed to apply access and routing rules for device '%s'.\n%s",
                device.mac_address,
                error,
            )
            return False

        self.logger.info(
            "Device '%s' was successfully added:\n%s",
            device.mac_address,
            device,
        )

        TRACER.info(f"Adding device '{device.mac_address}': end")

        return True

    def _add_ip_address(
        self, device: Device, ip_address: Union[IPv4Address, IPv6Address]
    ) -> bool:
        """Add IP address to existing device

        Args:
            mac_address (EUI48): MAC address
            ip_address (Union[IPv4Address, IPv6Address]): IP address
        """

        # Initialize "from" metering
        src_pps: Union[int, None] = (
            self._switch.max_bandwidth[0]
            if self._switch.config.bandwidth.enforce_max_bandwidth
            else None
        )
        src_pbs: Union[int, None] = (
            self._switch.max_bandwidth[1]
            if self._switch.config.bandwidth.enforce_max_bandwidth
            else None
        )

        if device.profile.from_device_policy.rate_limit is not None:
            if device.profile.from_device_policy.rate_limit.bandwidth.pps is not None:
                src_pps = device.profile.from_device_policy.rate_limit.bandwidth.pps
            if device.profile.from_device_policy.rate_limit.bandwidth.pbs is not None:
                src_pbs = device.profile.from_device_policy.rate_limit.bandwidth.pbs

        if src_pps is not None and self._switch.max_bandwidth[0] is not None:
            src_pps = min(self._switch.max_bandwidth[0], src_pps)
        if src_pbs is not None and self._switch.max_bandwidth[1] is not None:
            src_pbs = min(self._switch.max_bandwidth[1], src_pbs)

        src_metering: bool = src_pps is not None and src_pbs is not None

        if src_metering:
            if not self._meter_tables[0].entry_add(
                {
                    "$METER_INDEX": device.local_id,
                },
                None,
                {
                    "$METER_SPEC_PIR_PPS": src_pps,
                    "$METER_SPEC_PBS_PKTS": src_pbs,
                    "$METER_SPEC_CIR_PPS": 0,
                    "$METER_SPEC_CBS_PKTS": 1,
                },
            ):
                self.logger.debug("Failed to add to meter 'device src'.")

        # Initialize "to" metering
        dst_pps: Union[int, None] = (
            self._switch.max_bandwidth[0]
            if self._switch.config.bandwidth.enforce_max_bandwidth
            else None
        )
        dst_pbs: Union[int, None] = (
            self._switch.max_bandwidth[1]
            if self._switch.config.bandwidth.enforce_max_bandwidth
            else None
        )

        if device.profile.to_device_policy.rate_limit is not None:
            if device.profile.to_device_policy.rate_limit.bandwidth.pps is not None:
                dst_pps = device.profile.to_device_policy.rate_limit.bandwidth.pps
            if device.profile.to_device_policy.rate_limit.bandwidth.pbs is not None:
                dst_pbs = device.profile.to_device_policy.rate_limit.bandwidth.pbs

        if dst_pps is not None and self._switch.max_bandwidth[0] is not None:
            dst_pps = min(self._switch.max_bandwidth[0], dst_pps)
        if dst_pbs is not None and self._switch.max_bandwidth[1] is not None:
            dst_pbs = min(self._switch.max_bandwidth[1], dst_pbs)
        dst_metering: bool = dst_pps is not None and dst_pbs is not None

        if dst_metering:
            if not self._meter_tables[1].entry_add(
                {
                    "$METER_INDEX": device.local_id,
                },
                None,
                {
                    "$METER_SPEC_PIR_PPS": dst_pps,
                    "$METER_SPEC_PBS_PKTS": dst_pbs,
                    "$METER_SPEC_CIR_PPS": 0,
                    "$METER_SPEC_CBS_PKTS": 1,
                },
            ):
                self.logger.debug("Failed to add to meter 'device dst'.")

        if ip_address not in device.ip_addresses:
            argument_list = {
                "id": bytearray(device.get_id_bytes(ip_address)),
                "sub_id": bytearray(device.get_sub_id_bytes()),
                "manufacturer_id": bytearray(device.get_manufacturer_id_bytes()),
                "model_id": bytearray(device.get_model_id_bytes()),
            }

            ######## Source Entries ########
            src_argument_list = argument_list
            if src_metering:
                src_argument_list = {
                    "meter_id": device.local_id,
                    **argument_list,
                }

            if not self._src_device_table.entry_add(
                {
                    "port": device.port,
                    "mac_address": bytearray(bytes(device.mac_address)),
                    "ip_address": bytearray(ip_to_128(ip_address)),
                },
                DEVICE_TABLE_ACTIONS[0][int(src_metering)],
                src_argument_list,
            ):
                self.logger.debug("Failed to add to table 'device src'.")

            if not self._src_device_table.entry_add(
                {
                    "port": device.port,
                    "mac_address": bytearray(bytes(device.mac_address)),
                    "ip_address": bytearray(bytes([0x00] * 16)),
                },
                DEVICE_TABLE_ACTIONS[0][int(src_metering)],
                src_argument_list,
            ):
                self.logger.debug("Failed to add local only to table 'device src'.")

            ######## Destination Entries ########
            dst_argument_list = argument_list
            if dst_metering:
                dst_argument_list = {
                    "meter_id": device.local_id,
                    **argument_list,
                }

            if not self._dst_device_tables[0].entry_add(
                {
                    "mac_address": bytearray(bytes(device.mac_address)),
                },
                DEVICE_TABLE_ACTIONS[1][int(src_metering)],
                dst_argument_list,
            ):
                self.logger.debug("Failed to add to table 'device dst'.")

            if not self._dst_device_tables[1].entry_add(
                {
                    # "mac_address": bytearray(bytes(device.mac_address)),
                    "ip_address": bytearray(ip_to_128(ip_address)),
                },
                DEVICE_TABLE_ACTIONS[1][int(src_metering)],
                dst_argument_list,
            ):
                self.logger.debug("Failed to add to table 'device dst ip'.")

            ######## Add test ports ########
            for test_port in self._switch.get_test_ports(device.port):
                if not self._src_device_table.entry_add(
                    {
                        "port": test_port,
                        "mac_address": bytearray(bytes(device.mac_address)),
                        "ip_address": bytearray(ip_to_128(ip_address)),
                    },
                    "match_device_src",
                    {
                        "id": bytearray(device.get_id_bytes(ip_address)),
                        "sub_id": bytearray(device.get_sub_id_bytes()),
                        "manufacturer_id": bytearray(
                            device.get_manufacturer_id_bytes()
                        ),
                        "model_id": bytearray(device.get_model_id_bytes()),
                    },
                ):
                    logging.debug("Failed to add test entry to table 'device src'.")

            device.ip_addresses.append(ip_address)

            return True
        else:
            return False

    def get_device(self, mac_address: EUI48) -> Union[Device, None]:
        """Get device

        Args:
            mac_address (EUI48): MAC address

        Returns:
            Union[Device, None]: Device or None
        """
        return self._devices.get(mac_address)

    def remove_device(
        self,
        mac_address: EUI48,
        group: Union[str, None] = None,
        sub_group: Union[str, None] = None,
    ) -> bool:
        """Remove device

        Args:
            device (Device): Device description
        """

        if (device := self._devices.get(mac_address)) is not None:
            if (group is None or device.group == group) and (
                sub_group is None or device.sub_group == sub_group
            ):
                self.logger.info("Remove device '%s'.", mac_address)

                # Remove entry before removing it from the data plane
                # This ensures the data plane always has more restriction than control plane
                try:
                    self._devices.pop(device.mac_address)
                    self._unique_ids.remove(device.local_id)
                except:
                    pass

                self._switch.l2.remove_route(device.mac_address)

                for ip_address in device.ip_addresses:
                    self._switch.mud.disable_profile(ip_address)
                    self._switch.l3.remove_route(ip_address)

                    if not self._src_device_table.entry_del(
                        {
                            "port": device.port,
                            "mac_address": bytearray(bytes(device.mac_address)),
                            "ip_address": bytearray(ip_to_128(ip_address)),
                        },
                    ):
                        self.logger.debug("Failed to remove from table 'device src'.")

                    if not self._src_device_table.entry_del(
                        {
                            "port": device.port,
                            "mac_address": bytearray(bytes(device.mac_address)),
                            "ip_address": bytearray(bytes([0x00] * 16)),
                        },
                    ):
                        self.logger.debug(
                            "Failed to remove local only from table 'device src'."
                        )

                    if not self._dst_device_tables[0].entry_del(
                        {
                            "mac_address": bytearray(bytes(device.mac_address)),
                        },
                    ):
                        self.logger.debug("Failed to remove from table 'device dst'.")

                    if not self._dst_device_tables[1].entry_del(
                        {
                            # "mac_address": bytearray(bytes(device.mac_address)),
                            "ip_address": bytearray(ip_to_128(ip_address)),
                        },
                    ):
                        self.logger.debug(
                            "Failed to remove local only from table 'device dst ip'."
                        )

                    # Remove test ports
                    for test_port in self._switch.get_test_ports(device.port):
                        if not self._src_device_table.entry_del(
                            {
                                "port": test_port,
                                "mac_address": bytearray(bytes(device.mac_address)),
                                "ip_address": bytearray(ip_to_128(ip_address)),
                            },
                        ):
                            self.logger.debug(
                                "Failed to remove test entry from table 'device src'."
                            )

                self.logger.info("Device '%s' was successfully removed.", device)

            return True
        else:
            self.logger.error("Device '%s' does not exist.", mac_address)
            return False

    ############ SOURCE IGNORE ############

    def add_src_ignore(self, ignore: Ignore) -> bool:
        """Add source ignore

        Args:
            ignore (Ignore): Ignore

        Returns:
            bool: Successfulness
        """

        self.logger.info("Add src ignore '%s'", ignore.mac_address)

        # Check source ignore list
        if ignore.mac_address in self._src_ignores:
            self.logger.error(
                "Ignore '%s' is already marked as a src ignore.",
                ignore.mac_address,
            )
            return False

        # Check check device list
        if ignore.mac_address in self._dst_ignores:
            self.logger.error(
                "Ignore '%s' is already marked as a device.",
                ignore.mac_address,
            )
            return False

        self._src_ignores[ignore.mac_address] = ignore

        # Add ip addresses if they are not already defined

        if ignore.ip_address is not None:
            if not self._src_device_table.entry_add(
                {
                    "port": ignore.port,
                    "mac_address": bytearray(bytes(ignore.mac_address)),
                    "ip_address": bytearray(ip_to_128(ignore.ip_address)),
                },
                "ignore_src",
                {
                    "id": bytearray(ignore.get_id_bytes(ignore.ip_address)),
                    "sub_id": bytearray(ignore.get_sub_id_bytes()),
                    "manufacturer_id": bytearray(ignore.get_manufacturer_id_bytes()),
                    "model_id": bytearray(ignore.get_model_id_bytes()),
                },
            ):
                self.logger.debug("Failed to add to table 'device src'.")

        if not self._src_device_table.entry_add(
            {
                "port": ignore.port,
                "mac_address": bytearray(bytes(ignore.mac_address)),
                "ip_address": bytearray(bytes([0x00] * 16)),
            },
            "ignore_src",
            {
                "id": bytearray(ignore.get_id_bytes(ignore.ip_address)),
                "sub_id": bytearray(ignore.get_sub_id_bytes()),
                "manufacturer_id": bytearray(ignore.get_manufacturer_id_bytes()),
                "model_id": bytearray(ignore.get_model_id_bytes()),
            },
        ):
            self.logger.debug("Failed to add local only to table 'device src'.")

        self.logger.info(
            "Source ignore '%s' was successfully added:\n%s",
            ignore.mac_address,
            ignore,
        )

        return True

    def remove_src_ignore(
        self,
        mac_address: EUI48,
        group: Union[str, None] = None,
        sub_group: Union[str, None] = None,
    ) -> bool:
        """Remove source ignore

        Args:
            mac_address (EUI48): MAC address
            group (Union[str, None], optional): Ignore group
            sub_group (Union[str, None], optional): Ignore sub group

        Returns:
            bool: Successfulness
        """

        if (ignore := self._src_ignores.get(mac_address)) is not None:
            if (group is None or ignore.group == group) and (
                sub_group is None or ignore.sub_group == sub_group
            ):
                self.logger.info("Remove src ignore '%s'.", mac_address)

                # Remove entry before removing it from the data plane
                # This ensures the data plane always has more restriction than control plane
                try:
                    self._src_ignores.pop(ignore.mac_address)
                except:
                    pass

                if ignore.ip_address is not None:
                    if not self._src_device_table.entry_del(
                        {
                            "port": ignore.port,
                            "mac_address": bytearray(bytes(ignore.mac_address)),
                            "ip_address": bytearray(ip_to_128(ignore.ip_address)),
                        },
                    ):
                        self.logger.debug("Failed to remove from table 'device src'.")

                if not self._src_device_table.entry_del(
                    {
                        "port": ignore.port,
                        "mac_address": bytearray(bytes(ignore.mac_address)),
                        "ip_address": bytearray(bytes([0x00] * 16)),
                    },
                ):
                    self.logger.debug(
                        "Failed to remove local only from table 'device src'."
                    )

                self.logger.info("Source ignore '%s' was successfully removed.", ignore)

            return True
        else:
            self.logger.error("Source ignore '%s' does not exist.", mac_address)
            return False

    ############ DESTINATION IGNORE ############

    def add_dst_ignore(self, ignore: Ignore) -> bool:
        """Add destination ignore

        Args:
            ignore (Ignore): Ignore

        Returns:
            bool: Successfulness
        """

        self.logger.info("Add dst ignore '%s'", ignore.mac_address)

        # Check destination ignore list
        if ignore.mac_address in self._dst_ignores:
            self.logger.error(
                "Ignore '%s' is already marked as a dst ignore.",
                ignore.mac_address,
            )
            return False

        # Check check device list
        if ignore.mac_address in self._dst_ignores:
            self.logger.error(
                "Ignore '%s' is already marked as a device.",
                ignore.mac_address,
            )
            return False

        self._dst_ignores[ignore.mac_address] = ignore

        argument_list = {
            "id": bytearray(ignore.get_id_bytes(ignore.ip_address)),
            "sub_id": bytearray(ignore.get_sub_id_bytes()),
            "manufacturer_id": bytearray(ignore.get_manufacturer_id_bytes()),
            "model_id": bytearray(ignore.get_model_id_bytes()),
        }

        # Add ip addresses if they are not already defined
        if not self._dst_device_tables[0].entry_add(
            {
                "mac_address": bytearray(bytes(ignore.mac_address)),
            },
            "ignore_dst",
            argument_list,
        ):
            self.logger.debug("Failed to add to table 'device dst'.")

        if ignore.ip_address is not None:
            if not self._dst_device_tables[1].entry_add(
                {
                    # "mac_address": bytearray(bytes(ignore.mac_address)),
                    "ip_address": bytearray(ip_to_128(ignore.ip_address)),
                },
                "ignore_dst",
                argument_list,
            ):
                self.logger.debug("Failed to add to table 'device dst ip'.")

        self.logger.info(
            "Destination ignore '%s' was successfully added:\n%s",
            ignore.mac_address,
            ignore,
        )

        return True

    def remove_dst_ignore(
        self,
        mac_address: EUI48,
        group: Union[str, None] = None,
        sub_group: Union[str, None] = None,
    ) -> bool:
        """Remove destination ignore

        Args:
            mac_address (EUI48): MAC address
            group (Union[str, None], optional): Ignore group
            sub_group (Union[str, None], optional): Ignore sub group

        Returns:
            bool: Successfulness
        """

        if (ignore := self._dst_ignores.get(mac_address)) is not None:
            if (group is None or ignore.group == group) and (
                sub_group is None or ignore.sub_group == sub_group
            ):
                self.logger.info("Remove dst ignore '%s'.", mac_address)

                # Remove entry before removing it from the data plane
                # This ensures the data plane always has more restriction than control plane
                try:
                    self._dst_ignores.pop(ignore.mac_address)
                except:
                    pass

                if not self._dst_device_tables[0].entry_del(
                    {
                        "mac_address": bytearray(bytes(ignore.mac_address)),
                    },
                ):
                    self.logger.debug("Failed to remove from table 'device dst'.")

                if ignore.ip_address is not None:
                    if not self._dst_device_tables[1].entry_del(
                        {
                            # "mac_address": bytearray(bytes(ignore.mac_address)),
                            "ip_address": bytearray(ip_to_128(ignore.ip_address)),
                        },
                    ):
                        self.logger.debug(
                            "Failed to remove from table 'device dst ip'."
                        )

                self.logger.info(
                    "Destination ignore '%s' was successfully removed.", ignore
                )

            return True
        else:
            self.logger.error("Destination ignore '%s' does not exist.", mac_address)
            return False
