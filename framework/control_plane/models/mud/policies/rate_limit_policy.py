"""Quality Of Service Policy"""

from __future__ import annotations
from typing import Any, Union

from framework.control_plane.models.mud import InvalidMudProfileError


class MudRateLimitPolicy:
    """QoS Policy"""

    bandwidth: MudQualityOfServiceBandwidth

    def __init__(self) -> None:
        self.bandwidth = MudQualityOfServiceBandwidth()

    def load_from_json(self, json: dict[str, Any]):
        """Load QoS

        Args:
            json (dict[str, Any]): JSON

        Raises:
            InvalidMudProfileError: MUD qos is not valid
        """
        try:
            if isinstance((bandwidth := json["bandwidth"]), dict):
                if isinstance((pps := bandwidth["pps"]), int):
                    self.bandwidth.pps = pps
                else:
                    raise TypeError("pps")

                if isinstance((pbs := bandwidth["pbs"]), int):
                    self.bandwidth.pbs = pbs
                else:
                    raise TypeError("pbs")
            else:
                raise TypeError("bandwidth")

        except KeyError as error:
            raise InvalidMudProfileError(
                f"MUD Profile QoS {error} entry is missing."
            ) from error
        except TypeError as error:
            raise InvalidMudProfileError(
                f"MUD Profile QoS {error} entry is invalid."
            ) from error


class MudQualityOfServiceBandwidth:
    """QoS bandwidth"""

    # Packets Per Second
    pps: Union[int, None]

    # Packet Burst Size
    pbs: Union[int, None]

    def __init__(self) -> None:
        self.pps = None
        self.pbs = None
