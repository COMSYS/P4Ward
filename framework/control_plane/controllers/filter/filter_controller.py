"""Filter controller"""

from __future__ import annotations
from typing import Any, Union
import typing
import logging
import asyncio
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
import zlib
import time
from ipaddress import IPv4Address, IPv6Address
from macaddress import EUI48

from framework.control_plane.data_plane.table import DPTable
from framework.control_plane.data_plane.register import DPRegister
from framework.control_plane.helper import ip_to_128
from framework.control_plane.controllers.controller import Controller
from framework.control_plane.controllers.auth.eap_ext import *

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch

FILTER_UPDATE_COUNT = 4
BLOOM_CHECK_INTERVAL = 5
BLOOM_AGING_INTERVAL = 20


class FilterEntry:
    id: int

    flow_bits_1: tuple[int, int]
    flow_bits_2: tuple[int, int]

    update_counter: int
    update_counter_response: int

    last_refresh: int

    def __init__(
        self, flow_bits_1: tuple[int, int], flow_bits_2: tuple[int, int]
    ) -> None:
        self.flow_bits_1 = flow_bits_1
        self.flow_bits_2 = flow_bits_2

        self.id = int.from_bytes(
            (
                a ^ b
                for a, b in zip(
                    flow_bits_1[0].to_bytes(16, "big")
                    + flow_bits_2[0].to_bytes(16, "big"),
                    flow_bits_1[1].to_bytes(16, "big")
                    + flow_bits_2[1].to_bytes(16, "big"),
                )
            ),
            "big",
        )

    def check_direction(self, new_entry: FilterEntry):
        return self.flow_bits_1 == new_entry.flow_bits_1


class FilterController(Controller):
    """TCP Filter Controller"""

    _bloom_filter_registers: tuple[DPRegister, DPRegister]
    _update_bloom_filter_register: DPRegister

    _sessions: dict[int, FilterEntry]

    def __init__(self, switch: "Switch") -> None:
        super().__init__(switch)

        # Reset bloom filter
        self._bloom_filter_registers = (
            switch.data_plane.get_register(
                "Ingress.acl.bloom_filter_1",
            ),
            switch.data_plane.get_register(
                "Ingress.acl.bloom_filter_2",
            ),
        )
        self._update_bloom_filter_register = switch.data_plane.get_register(
            "Ingress.acl.update_bloom_filter",
        )

        self._sessions = {}

        asyncio.get_event_loop().create_task(self._handle_bloom_regen())

    async def _handle_bloom_regen(self):
        await asyncio.sleep(
            delay=BLOOM_CHECK_INTERVAL,
            loop=asyncio.get_event_loop(),
        )

        update_bits_1: set[int] = set()
        bits_1: set[int] = set()
        bits_2: set[int] = set()

        current_time = int(time.time())

        # Add bits that should be cleared
        outdated = [
            (id, entry)
            for id, entry in self._sessions.items()
            if (current_time - entry.last_refresh) > BLOOM_AGING_INTERVAL
        ]
        for id, entry in outdated:
            print(
                f"Update {id} -> {entry.update_counter}, {entry.update_counter_response}"
            )
            if entry.update_counter > 0 and entry.update_counter_response > 0:
                print("Request update")
                entry.update_counter -= 1
                entry.update_counter_response -= 1

                update_bits_1.add(entry.flow_bits_1[0])
                update_bits_1.add(entry.flow_bits_1[1])
            else:
                print("Remove connection")
                bits_1.add(entry.flow_bits_1[0])
                bits_1.add(entry.flow_bits_1[1])

                bits_2.add(entry.flow_bits_2[0])
                bits_2.add(entry.flow_bits_2[1])

                self._sessions.pop(id)

        # Remove bits that should not be cleared
        for id, entry in self._sessions.items():
            bits_1.discard(entry.flow_bits_1[0])
            bits_1.discard(entry.flow_bits_1[1])

            bits_2.discard(entry.flow_bits_2[0])
            bits_2.discard(entry.flow_bits_2[1])

        self._update_bloom_filter_register.set_multiple(
            [(id, 1) for id in update_bits_1]
        )
        self._bloom_filter_registers[0].set_multiple([(id, 0) for id in bits_1])
        self._bloom_filter_registers[1].set_multiple([(id, 0) for id in bits_2])

        asyncio.get_event_loop().create_task(self._handle_bloom_regen())

    async def handle_tcp_packet(self, ether_packet: Ether):
        src_ip_address: bytes
        src_port: bytes

        dst_ip_address: bytes
        dst_port: bytes

        open: bool = False
        close: bool = False

        ip_packet: Union[IP, IPv6]
        if ether_packet.haslayer(IP):
            ip_packet = ether_packet[IP]
            src_ip_address = ip_to_128(IPv4Address(ip_packet.src))
            dst_ip_address = ip_to_128(IPv4Address(ip_packet.dst))
        elif ether_packet.haslayer(IPv6):
            ip_packet = ether_packet[IPv6]
            src_ip_address = ip_to_128(IPv6Address(ip_packet.src))
            dst_ip_address = ip_to_128(IPv6Address(ip_packet.dst))
        else:
            return

        if ip_packet.haslayer(TCP):
            tcp_packet = ip_packet[TCP]
            src_port = tcp_packet.sport.to_bytes(2, "big")
            dst_port = tcp_packet.dport.to_bytes(2, "big")

            if tcp_packet.flags & 0x02:  # SYN
                open = True

            if tcp_packet.flags & 0x01:  # FIN
                close = True
        else:
            return

        hash_1 = zlib.crc32(dst_ip_address + src_ip_address + dst_port + src_port)
        hash_2 = zlib.crc32(src_ip_address + dst_ip_address + src_port + dst_port)

        new_entry = FilterEntry(
            (
                (hash_1 >> 16) & 0xFFFF,
                (hash_2 >> 16) & 0xFFFF,
            ),
            (
                hash_1 & 0xFFFF,
                hash_2 & 0xFFFF,
            ),
        )

        if open:
            print("Open connection")
            new_entry.update_counter = FILTER_UPDATE_COUNT
            new_entry.update_counter_response = 0
            new_entry.last_refresh = int(time.time())
            self._sessions[new_entry.id] = new_entry

            self._update_bloom_filter_register.set(new_entry.flow_bits_1[1], 1)
        else:
            if entry := self._sessions.get(new_entry.id):
                if close:
                    if entry.update_counter == 0 or entry.update_counter_response == 0:
                        print("Close connection")
                    entry.update_counter = 0
                    entry.update_counter_response = 0
                else:
                    print("Refresh connection")
                    entry.last_refresh = int(time.time())

                    if entry.check_direction(new_entry):
                        entry.update_counter = FILTER_UPDATE_COUNT
                    else:
                        entry.update_counter_response = FILTER_UPDATE_COUNT
