"""Layer 2 controller"""

from __future__ import annotations
from typing import Any, Union
import typing
import logging
from macaddress import EUI48

from framework.control_plane.data_plane.table import DPTable
from framework.control_plane.controllers.controller import Controller

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class L2Controller(Controller):
    """Layer 2 Controller"""

    logger: logging.Logger

    _network_table: DPTable
    _routes_table: DPTable

    _network_entries: dict[int, int] = {}  # Port -> Network ID
    _entries: dict[EUI48, tuple[int, int]] = {}  # MAC -> (Port, Network ID)

    def __init__(self, switch: "Switch") -> None:
        super().__init__(switch)

        self.logger = logging.getLogger("l2")
        self.logger.setLevel(logging.DEBUG)

        handler = logging.FileHandler("switch-l2.log", mode="w")
        handler.setFormatter(logging.getLogger().handlers[0].formatter)
        self.logger.addHandler(handler)

        self._network_table = switch.data_plane.get_table(
            "Ingress.routing.l2_network_id",
        )
        self._routes_table = switch.data_plane.get_table(
            "Ingress.routing.l2_routing",
        )

        if not self._routes_table.entry_add(
            {
                "dst_mac_address": 0xFFFFFFFFFFFF,
            },
            "l2_broadcast",
            {},
        ):
            self.logger.debug(
                "Failed to add default broadcast entry to table 'l2 routes'."
            )

    def load_preload(self):
        for route in self._switch.preload.l2.routes:
            self.add_route(EUI48(route.mac_address), route.port)

    def add_network(self, port: int, network_id: int) -> bool:
        """Add L2 to L3 pass

        Args:
            port (int): Ingress port
            network_id (int): Corresponding network id

        Returns:
            bool: Successfulness
        """

        self.logger.info("Add L2 network '%s' -> '%s'.", port, network_id)

        if port not in self._network_entries:
            if not self._network_table.entry_add(
                {
                    "port": port,
                },
                "l2_network",
                {"id": network_id},
            ):
                self.logger.debug("Failed to add to table 'l2 routing'.")

            # Add entry only after adding it to the data plane
            # This ensures the data plane always has more restriction than control plane
            self._network_entries[port] = network_id

            self.logger.info(
                "L2 network '%s' -> '%s' was successfully added.", port, network_id
            )

            return True
        else:
            self.logger.error(
                "L2 network '%s' -> '%s' already exists.", port, network_id
            )
            return False

    def remove_network(self, port: int) -> bool:
        """Remove L2 route

        Args:
            port (int): Ingress port

        Returns:
            bool: Successfulness
        """

        self.logger.info("Remove L2 network '%s'.", port)

        if port in self._network_entries:
            # Remove entry before removing it from the data plane
            # This ensures the data plane always has more restriction than control plane
            self._network_entries.pop(port)

            if not self._routes_table.entry_del(
                {
                    "port": port,
                },
            ):
                self.logger.debug("Failed to remove from table 'l2 network'.")

            self.logger.info("L2 network '%s' was successfully removed.", port)

            return True
        else:
            self.logger.error("L2 network '%s' does not exist.", port)
            return False

    def add_l3_pass(self, mac_address: EUI48) -> bool:
        """Add L2 to L3 pass

        Args:
            network_id (int): Network Identifier
            mac_address (EUI48): MAC address

        Returns:
            bool: Successfulness
        """

        self.logger.info("Add L2 to L3 pass '%s'.", mac_address)

        if mac_address not in self._entries:
            if not self._routes_table.entry_add(
                {
                    "dst_mac_address": bytearray(bytes(mac_address)),
                },
                "pass_to_l3",
                {},
            ):
                self.logger.debug("Failed to add to table 'l2 routing'.")

            # Add entry only after adding it to the data plane
            # This ensures the data plane always has more restriction than control plane
            self._entries[mac_address] = (-1, -1)

            self.logger.info("L2 to L3 pass '%s' was successfully added.", mac_address)

            return True
        else:
            self.logger.error("L2 to L3 pass '%s' already exists.", mac_address)
            return False

    def remove_l3_pass(self, mac_address: EUI48) -> bool:
        """Remove L2 route

        Args:
            mac_address (EUI48): MAC address

        Returns:
            bool: Successfulness
        """

        self.logger.info("Remove L2 to L3 pass '%s'.", mac_address)

        if mac_address in self._entries:
            # Remove entry before removing it from the data plane
            # This ensures the data plane always has more restriction than control plane
            self._entries.pop(mac_address)

            if not self._routes_table.entry_del(
                {
                    "dst_mac_address": bytearray(bytes(mac_address)),
                },
            ):
                self.logger.debug("Failed to remove from table 'l2 routing'.")

            self.logger.info(
                "L2 to L3 pass '%s' was successfully removed.", mac_address
            )

            return True
        else:
            self.logger.error("L2 to L3 pass '%s' does not exist.", mac_address)
            return False

    def add_route(self, mac_address: EUI48, port: int) -> bool:
        """Add L2 route

        Args:
            mac_address (EUI48): MAC address
            port (int): Egress port

        Returns:
            bool: Successfulness
        """

        # Get network identifier
        network_id = self._switch.get_network_id(port)

        self.logger.info(
            "Add L2 route '%s', '%s' -> '%s'.", network_id, mac_address, port
        )

        if mac_address not in self._entries:
            if not self._routes_table.entry_add(
                {
                    "dst_mac_address": bytearray(bytes(mac_address)),
                },
                "l2_route",
                {
                    "port": port,
                    "network_id": network_id,
                },
            ):
                self.logger.debug("Failed to add to table 'l2 routing'.")

            # Add entry only after adding it to the data plane
            # This ensures the data plane always has more restriction than control plane
            self._entries[mac_address] = (port, network_id)

            self.logger.info(
                "L2 route '%s', '%s' -> '%s' was successfully added.",
                network_id,
                mac_address,
                port,
            )

            return True
        else:
            self.logger.error(
                "L2 route '%s', '%s' already exists.", network_id, mac_address
            )
            return False

    def remove_route(self, mac_address: EUI48) -> bool:
        """Remove L2 route

        Args:
            mac_address (EUI48): MAC address

        Returns:
            bool: Successfulness
        """

        self.logger.info("Remove L2 route '%s'.", mac_address)

        if mac_address in self._entries:
            # Remove entry before removing it from the data plane
            # This ensures the data plane always has more restriction than control plane
            self._entries.pop(mac_address)

            if not self._routes_table.entry_del(
                {
                    "dst_mac_address": bytearray(bytes(mac_address)),
                },
            ):
                self.logger.debug("Failed to remove from table 'l2 routes'.")

            self.logger.info("L2 route '%s' was successfully removed.", mac_address)

            return True
        else:
            self.logger.error("L2 route '%s' does not exist.", mac_address)
            return False

    # def add_broadcast(
    #     self, network_id: int, mac_address: EUI48, multicast_group: int
    # ) -> bool:
    #     """Add L2 broadcast

    #     Args:
    #         mac_address (EUI48): MAC address
    #         multicast_group (int): Multicast Group

    #     Returns:
    #         bool: Successfulness
    #     """

    #     self.logger.info(
    #         "Add L2 broadcast '%s', '%s' -> '%s'.",
    #         network_id,
    #         mac_address,
    #         multicast_group,
    #     )

    #     if not self._routes_table.entry_add(
    #         {
    #             "dst_mac_address": bytearray(bytes(mac_address)),
    #         },
    #         "l2_broadcast",
    #         {
    #             "group": multicast_group,
    #             "network_id": network_id,
    #         },
    #     ):
    #         self.logger.debug("Failed to add to table 'l2 routes'.")

    #     self.logger.info(
    #         "L2 broadcast '%s', '%s' -> '%s' was successfully added.",
    #         network_id,
    #         mac_address,
    #         multicast_group,
    #     )

    #     return True
