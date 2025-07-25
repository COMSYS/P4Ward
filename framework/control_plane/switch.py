from __future__ import annotations
from typing import Union
import os
import asyncio
from macaddress import EUI48
from ipaddress import (
    IPv4Interface,
    IPv4Network,
    IPv4Address,
    IPv6Interface,
    IPv6Network,
    IPv6Address,
)
import logging
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from framework.control_plane.config.protocol import ProtocolConfig
from framework.control_plane.controllers.device.device import Ignore

from framework.control_plane.tracing import TRACER
from framework.control_plane.config.switch import SwitchConfig
from framework.control_plane.config.preload import PreloadConfig
from framework.control_plane.data_plane import DataPlane
from framework.control_plane.controllers.ac.ac_controller import AcController
from framework.control_plane.controllers.filter.filter_controller import (
    FilterController,
)
from framework.control_plane.controllers.mud.mud_controller import MudController
from framework.control_plane.controllers.mud.local.mud_controller import (
    LocalMudController,
)
from framework.control_plane.controllers.mud.remote.mud_controller import (
    RemoteMudController,
)
from framework.control_plane.controllers.device.device_controller import (
    DeviceController,
)
from framework.control_plane.controllers.auth.auth_controller import AuthController
from framework.control_plane.controllers.auth.local.auth_controller import (
    LocalAuthController,
)
from framework.control_plane.controllers.auth.remote.auth_controller import (
    RemoteAuthController,
    AuthenticationProcedure,
)
from framework.control_plane.controllers.l2.l2_controller import L2Controller
from framework.control_plane.controllers.l3.l3_controller import L3Controller
from framework.control_plane.controllers.arp.arp_controller import ArpController
from framework.control_plane.controllers.monitoring.monitoring_controller import (
    MonitoringController,
)
from framework.control_plane.controllers.cli.cli_contoller import CliController


class Switch:
    """Switch manager"""

    config: SwitchConfig
    preload: PreloadConfig
    protocol: ProtocolConfig

    data_plane: DataPlane

    #### Global State ####

    max_bandwidth: tuple[
        Union[int, None], Union[int, None]
    ]  # Packets Per Second (PPS), Packet Burst Size (PBS)
    networks: list[PortNetwork]
    port_networks: dict[int, PortNetwork]

    #### Controllers ####
    acl: AcController
    filter: FilterController
    mud: MudController

    device: DeviceController

    auth: AuthController

    l2: L2Controller
    l3: L3Controller

    arp: ArpController

    # monitoring: Union[MonitoringController, None]
    cli: Union[CliController, None]

    def __init__(self, config: SwitchConfig, preload: PreloadConfig, protocol: ProtocolConfig) -> None:
        self.config = config
        self.preload = preload
        self.protocol = protocol

        TRACER.info("Initializating switch: start")

        # Initialize data plane connection
        self.data_plane = DataPlane(
            config.data_plane.push,
            config.data_plane.pull,
            mock=True if config.data_plane.mock == True else False,
        )

        # Initialize global state
        self.max_bandwidth = (
            self.config.bandwidth.pps,
            self.config.bandwidth.pbs,
        )

        # Initialize switch networks
        self.port_networks = {}
        self.networks = []
        for network in self.config.networks.networks:
            port_network = PortNetwork()
            port_network.id = len(self.networks) + 1

            if network.mac_address is not None:
                port_network.mac_address = EUI48(network.mac_address)
            else:
                port_network.mac_address = EUI48(os.urandom(6))

            if network.ipv4_interface is not None:
                port_network.ipv4 = network.ipv4_interface
            else:
                port_network.ipv4 = IPv4Interface("0.0.0.0/0")

            if network.ipv6_interface is not None:
                port_network.ipv6 = network.ipv6_interface
            else:
                port_network.ipv6 = IPv6Interface("::/0")

            port_network.ports = list(network.ports)
            port_network.test_ports = list(network.test_ports)

            self.networks.append(port_network)

            for port in port_network.ports:
                self.port_networks[port] = port_network

        # Initialize L2 and L3 controllers
        self.l2 = L2Controller(self)
        self.l3 = L3Controller(self)
        self.arp = ArpController(self)

        # Initialize network multicasting/broadcasting
        # Note: The multicast groups are configured using the configure.g.py script
        # that can be generated using the --gen-configure flag
        # This is automatically done when using the make file to activate the control plane
        multicast_group = 0
        for network in self.networks:
            multicast_group += 1
            for port in network.ports:
                # self.arp.add_broadcast(port, multicast_group)

                if network.ipv4 is not None:
                    self.arp.add_reply(port, network.ipv4.ip, network.mac_address)

        for port, network in self.port_networks.items():
            self.l2.add_network(port, network.id)

        for network in self.networks:
            self.l2.add_l3_pass(network.mac_address)

        self.acl = AcController(self)
        self.filter = FilterController(self)

        # Initialize MUD Manager
        if self.config.mud.use_remote:
            self.mud = RemoteMudController(self, self.config.mud.origin)
        else:
            self.mud = LocalMudController(self, self.config.mud.origin)

        # Initialize Device Manager
        self.device = DeviceController(self)
        self.device.add_dst_ignore(
            Ignore(
                port=0,
                mac_address=EUI48(0xFFFFFFFFFFFF),
                ip_address=None,
                controller_name="features:broadcast"
            )
        )

        # Initialize Authentication Manager
        if self.config.auth.use_remote:
            method = AuthenticationProcedure.PASSWORD
            if self.config.auth.method == "password":
                method = AuthenticationProcedure.PASSWORD
            elif self.config.auth.method == "challenge":
                method = AuthenticationProcedure.CHALLENGE
            elif self.config.auth.method == "remote":
                method = AuthenticationProcedure.REMOTE
            self.auth = RemoteAuthController(self, self.config.auth.host, method)
        else:
            self.auth = LocalAuthController(self)

        # # Initialize Monitoring
        # if self.config.features.enable_monitoring:
        #     self.monitoring = MonitoringController(self)
        # else:
        #     self.monitoring = None

        # Initialize CLI Tool
        if self.config.features.enable_cli:
            self.cli = CliController(self)
        else:
            self.cli = None

        # Load preload
        async def exec_preload():
            await self.mud.load_preload()

            self.l2.load_preload()
            self.l3.load_preload()

            await self.device.load_preload()

        asyncio.get_event_loop().run_until_complete(exec_preload())

        TRACER.info("Initializating switch: end")

    def get_network(self, port: int) -> PortNetwork:
        if (port_network := self.port_networks.get(port)) is not None:
            return port_network
        else:
            port_network = PortNetwork()
            port_network.id = len(self.networks)
            port_network.mac_address = EUI48(os.urandom(6))
            port_network.ipv4 = IPv4Interface("0.0.0.0/0")
            port_network.ipv6 = IPv6Interface("::/0")
            port_network.ports = [port]
            port_network.test_ports = []

            self.networks.append(port_network)
            self.port_networks[port] = port_network

            return port_network

    def get_network_id(self, port: int) -> int:
        return self.get_network(port).id

    def get_port_address(self, port: int) -> EUI48:
        return self.get_network(port).mac_address

    def get_port_ipv4_address(self, port: int) -> IPv4Address:
        return self.get_network(port).ipv4

    def get_port_ipv4_network(self, port: int) -> IPv4Network:
        return IPv4Network(self.get_network(port).ipv4, strict=False)

    def get_port_ipv6_address(self, port: int) -> IPv6Address:
        return self.get_network(port).ipv6

    def get_port_ipv6_network(self, port: int) -> IPv6Network:
        return IPv6Network(self.get_network(port).ipv6, strict=False)

    def get_test_ports(self, port: int) -> list[int]:
        return self.get_network(port).test_ports

    async def _read_socket(self):
        socket = self.data_plane.get_socket()
        loop = asyncio.get_event_loop()

        while True:
            buffer = bytearray(4096)
            byte_count = await loop.sock_recv_into(socket, buffer)

            ether_packet: Ether = Ether(buffer)

            if hasattr(ether_packet, "type"):
                if ether_packet.type == 0xFF01:  # Custom EAP
                    loop.create_task(self.auth.handle_eap_packet(ether_packet))
                    continue
                elif ether_packet.type == 0x0800 or ether_packet.type == 0x86DD:
                    loop.create_task(self.filter.handle_tcp_packet(ether_packet))
                    continue

            logging.warn("Undefined packet behaviour.")

    def run(self) -> None:
        """Run controller"""

        loop = asyncio.get_event_loop()

        if self.cli is not None:
            loop.create_task(self.cli.run())
        loop.create_task(self._read_socket())
        loop.run_forever()


class PortNetwork:
    """Switch Port Configuration"""

    id: int

    mac_address: EUI48
    ipv4: IPv4Interface
    ipv6: IPv6Interface

    ports: list[int]
    test_ports: list[int]
