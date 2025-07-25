"""Layer 2 controller"""

from __future__ import annotations
from typing import Any, Union
import typing
import logging
from macaddress import EUI48
import time
import asyncio

from framework.control_plane.data_plane.table import DPTable
from framework.control_plane.controllers.controller import Controller

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch

MONITORING_INTERVAL = 2000  # ms


class MonitoringController(Controller):
    """Monitoring Controller"""

    logger: logging.Logger

    _in_counter: DPTable
    _out_counter: DPTable

    def __init__(self, switch: "Switch") -> None:
        super().__init__(switch)

        self.logger = logging.getLogger("monitoring")
        self.logger.setLevel(logging.DEBUG)

        handler = logging.FileHandler("switch-monitoring.log", mode="w")
        handler.setFormatter(logging.getLogger().handlers[0].formatter)
        self.logger.addHandler(handler)

        self._in_counter = switch.data_plane.get_table(
            "Ingress.in_counter",
        )
        self._out_counter = switch.data_plane.get_table(
            "Egress.out_counter",
        )

        last_time = int(time.time() * 1000)
        for network in self._switch.config.networks.networks:
            for port in network.ports:
                asyncio.get_event_loop().create_task(
                    self._handle_monitoring(last_time, port)
                )

        asyncio.get_event_loop().create_task(
            self._handle_monitoring(last_time, port=192)  # CPU PORT
        )

    async def _handle_monitoring(
        self,
        last_time: int,
        port: int,
        last_in: int = 0,
        last_out: int = 0,
    ):
        """_summary_

        Args:
            last_time (int): Last update time
            port (int): Port
            last_in (int, optional): Last in_counter value
            last_out (int, optional): Last out_counter value
        """

        await asyncio.sleep(
            delay=MONITORING_INTERVAL / 1000.0,
            loop=asyncio.get_event_loop(),
        )

        current_time = int(time.time() * 1000)

        out_argument_list = []
        self._in_counter.entry_get(
            {
                "$COUNTER_INDEX": port,
            },
            ["$COUNTER_SPEC_PKTS"],
            out_argument_list,
        )
        self._out_counter.entry_get(
            {
                "$COUNTER_INDEX": port,
            },
            ["$COUNTER_SPEC_PKTS"],
            out_argument_list,
        )

        current_in = int.from_bytes(bytes(out_argument_list[0]), "big")
        current_out = int.from_bytes(bytes(out_argument_list[1]), "big")
        delta_in = current_in - last_in
        delta_out = current_out - last_out

        if delta_in > 0:
            if delta_in == delta_out:
                self.logger.info(f"{port} -> {delta_in} packets")
            else:
                self.logger.info(
                    f"{port} -> {delta_in} packets and {delta_in - delta_out} dropped"
                )

        asyncio.get_event_loop().create_task(
            self._handle_monitoring(
                current_time,
                port,
                current_in,
                current_out,
            )
        )
