"""Layer 3 controller"""

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


class L3Controller(Controller):
    """Layer 3 Controller"""

    logging: logging.Logger

    _routes_table: DPTable

    _routes: dict[Union[IPv4Network, IPv6Network], tuple[EUI48, int]] = {}

    def __init__(self, switch: "Switch") -> None:
        super().__init__(switch)

        self.logger = logging.getLogger("l3")
        self.logger.setLevel(logging.DEBUG)

        handler = logging.FileHandler("switch-l3.log", mode='w')        
        handler.setFormatter(logging.getLogger().handlers[0].formatter)
        self.logger.addHandler(handler)

        self._routes_table = switch.data_plane.get_table("Ingress.routing.l3_routing")
    
    def load_preload(self):
        for route in self._switch.preload.l3.routes:
            self.add_route(route.ip_address, EUI48(route.mac_address), route.port)

    def add_route(self, ip_address: Union[IPv4Address, IPv6Address], mac_address: EUI48, port: int) -> bool:
        """Add L3 route

        Args:
            ip_address (Union[IPv4Address, IPv6Address]): IP address
            mac_address (EUI48): MAC address
            port (int): Port

        Returns:
            bool: Successfulness
        """

        if isinstance(ip_address, IPv4Address):
            return self.add_network_route(IPv4Network(ip_address), mac_address, port)
        elif isinstance(ip_address, IPv6Address):
            return self.add_network_route(IPv6Network(ip_address), mac_address, port)
        else:
            raise Exception("Internal type error")
    
    def add_network_route(self, ip_network: Union[IPv4Network, IPv6Network], mac_address: EUI48, port: int) -> bool:
        """Add L3 route

        Args:
            ip_address (Union[IPv4Address, IPv6Address]): IP address
            mac_address (EUI48): MAC address
            port (int): Port

        Returns:
            bool: Successfulness
        """

        self.logger.info("Add L3 route '%s' -> '%s'.", ip_network, mac_address)

        if ip_network not in self._routes:
            action: str
            if isinstance(ip_network, IPv4Network):
                action = "l3_ipv4_route"
            elif isinstance(ip_network, IPv6Network):
                action = "l3_ipv6_route"
            else:
                self.logger.error("Invalid L3 route network.")
                return False

            self._routes_table.entry_add(
                {
                    "dst_ip_address": {
                        "value": bytearray(ip_to_128(ip_network.network_address)),
                        "prefix_length": ip_to_128_prefix_length(ip_network),
                    }
                },
                action,
                argument_list={
                    "src_mac_address": bytearray(bytes(self._switch.get_port_address(port))),
                    "dst_mac_address": bytearray(bytes(mac_address)),
                    "port": port,
                },
            )

            # Add entry only after adding it to the data plane
            # This ensures the data plane always has more restriction than control plane
            self._routes[ip_network] = (mac_address, port)

            self.logger.info("L3 route '%s' -> '%s' was successfully added.", ip_network, mac_address)

            return True
        else:
            self.logger.error("L3 route '%s' already exist.", ip_network)
            return False

    def remove_route(self, ip_address: Union[IPv4Address, IPv6Address]) -> bool:
        """Remove L3 route

        Args:
            ip_address (Union[IPv4Address, IPv6Address]): IP address

        Returns:
            bool: Successfulness
        """

        if isinstance(ip_address, IPv4Address):
            return self.remove_network_route(IPv4Network(ip_address))
        elif isinstance(ip_address, IPv6Address):
            return self.remove_network_route(IPv6Network(ip_address))
        else:
            raise Exception("Internal type error")

    def remove_network_route(self, ip_network: Union[IPv4Network, IPv6Network]) -> bool:
        """Remove L4 route

        Args:
            ip_address (Union[IPv4Address, IPv6Address]): IP address

        Returns:
            bool: Successfulness
        """

        self.logger.info("Remove L3 route '%s'.", ip_network)
        
        if ip_network in self._routes:
            # Remove entry before removing it from the data plane
            # This ensures the data plane always has more restriction than control plane
            self._routes.pop(ip_network)

            self._routes_table.entry_del(
                {
                    "dst_ip_address": {
                        "value": bytearray(ip_to_128(ip_network.network_address)),
                        "prefix_length": ip_to_128_prefix_length(ip_network),
                    }
                },
            )

            self.logger.info("L3 route '%s' was successfully added.", ip_network)

            return True
        else:
            self.logger.error("L3 route '%s' does not exist.", ip_network)
            return False
