"""Device Policy"""

from __future__ import annotations
from typing import Any, Union

from framework.control_plane.models.mud import InvalidMudProfileError
from framework.control_plane.models.mud.policies.access_list_policy import MudAccessListPolicy
from framework.control_plane.models.mud.policies.rate_limit_policy import MudRateLimitPolicy

class MudDevicePolicy:
    """Device from/to policy"""

    acl: Union[MudAccessListPolicy, None]
    rate_limit: Union[MudRateLimitPolicy, None]

    def __init__(self) -> None:
        self.acl = None
        self.rate_limit = None

    def load_from_json(self, json: dict[str, Any], extensions: list[str]):
        """Load MUD device policy from JSON

        Args:
            json (dict[str, Any]): JSON
            extensions (list[str]): Enabled Extensions

        Raises:
            InvalidMudProfileError: MUD device policy is not valid
        """
        try:
            if isinstance(acl := json.get("access-lists"), dict):
                self.acl = MudAccessListPolicy()
                self.acl.load_from_json(acl)
            elif acl is not None:
                raise TypeError("access-lists")
            
            if isinstance(rate_limit := json.get("rate-limit"), dict):
                if "rate-limit" not in extensions:
                    raise InvalidMudProfileError("Rate limit extension is not registered. Consider adding the 'rate-limit' extension.")

                self.rate_limit = MudRateLimitPolicy()
                self.rate_limit.load_from_json(rate_limit)
            elif rate_limit is not None:
                raise TypeError("rate-limit")
            
        except KeyError as error:
            raise InvalidMudProfileError(
                f"MUD Profile policy {error} entry is missing."
            ) from error
        except TypeError as error:
            raise InvalidMudProfileError(
                f"MUD Profile policy {error} entry is invalid."
            ) from error