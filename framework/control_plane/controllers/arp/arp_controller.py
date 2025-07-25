"""ARP controller"""

from __future__ import annotations
from typing import Any, Union
import typing
import logging
from ipaddress import IPv4Address, IPv6Address
from macaddress import EUI48

from framework.control_plane.helper import *
from framework.control_plane.data_plane.table import DPTable
from framework.control_plane.controllers.controller import Controller

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class ArpReply:
    """Arp entry"""

    port: int
    mac_address: EUI48

    def __init__(self, port: int, mac_address: EUI48) -> None:
        self.port = port
        self.mac_address = mac_address


class ArpController(Controller):
    """Arp Controller"""

    _arp_reply_table: DPTable
    _arp_broadcast_table: DPTable

    _replies: dict[tuple[int, IPv4Address], ArpReply] = {}
    _broadcasts: dict[int, int] = {}

    def __init__(self, switch: "Switch") -> None:
        super().__init__(switch)

        self._arp_reply_table = switch.data_plane.get_table("Ingress.arp.arp_replies")

    def load_preload(self):
        for entry in self._switch.preload.arp.replies:
            self.add_reply(entry.port, entry.ipv4_address, EUI48(entry.mac_address))

    def add_reply(
        self,
        port: int,
        ip_address: IPv4Address,
        mac_address: EUI48,
    ) -> bool:
        """Add ARP entry

        Args:
            port (int): Switch port
            ip_address (IPv4Address): Destination IP address
            mac_address (EUI48): Destination MAC address

        Returns:
            bool: Successfulness
        """

        logging.info(
            "Add ARP entry '%s' '%s' -> '%s'.",
            port,
            ip_address,
            mac_address,
        )

        if (port, ip_address) not in self._replies:
            if not self._arp_reply_table.entry_add(
                {
                    "port": {
                        "value": bytearray((port & 0x1FF).to_bytes(2, "big")),
                    },
                    "ip_address": {
                        "value": bytearray(ip_address.packed),
                    },
                },
                "arp_reply",
                argument_list={
                    "device_mac_address": bytearray(bytes(mac_address)),
                },
            ):
                logging.debug("Failed to add to table 'arp reply'.")

            # Add entry only after adding it to the data plane
            # This ensures the data plane always has more restriction than control plane
            self._replies[(port, ip_address)] = ArpReply(port, mac_address)

            logging.info(
                "ARP entry '%s' '%s' -> '%s' was successfully added.",
                port,
                ip_address,
                mac_address,
            )

            return True
        else:
            logging.error("ARP entry '%s' already exist.", ip_address)
            return False

    def remove_reply(self, port: int, ip_address: IPv4Address) -> bool:
        """Remove ARP reply

        Args:
            src_ip_address (IPv4Address): Source IP address

        Returns:
            bool: Successfulness
        """

        logging.info("Remove ARP reply '%s'.", ip_address)

        if (port, ip_address) in self._replies:
            # Remove entry before removing it from the data plane
            # This ensures the data plane always has more restriction than control plane
            entry = self._replies.pop((port, ip_address))

            if not self._arp_reply_table.entry_del(
                {
                    "port": {
                        "value": bytearray((port & 0x1FF).to_bytes(2, "big")),
                    },
                    "ip_address": {
                        "value": bytearray(ip_address.packed),
                    },
                },
            ):
                logging.debug("Failed to remove from table 'arp reply'.")

            logging.info("ARP reply '%s' was successfully added.", ip_address)

            return True
        else:
            logging.error("ARP reply '%s' does not exist.", ip_address)
            return False