"""Access List Policy"""

from __future__ import annotations
from typing import Any

from framework.control_plane.models.mud import InvalidMudProfileError


class MudAccessListPolicy:
    """Access List Policy"""

    # Access Control List names
    access_lists: list[str]

    def __init__(self) -> None:
        self.access_lists = []

    def load_from_json(self, json: dict[str, Any]):
        """Load ACL

        Args:
            json (dict[str, Any]): JSON

        Raises:
            InvalidMudProfileError: MUD Access List policy is not valid
        """
        try:
            if isinstance(json_access_lists := json.get("access-list"), list):
                for json_access_list in json_access_lists:
                    if isinstance(json_access_list, dict):
                        if isinstance((name := json_access_list["name"]), str):
                            self.access_lists.append(name)
                        else:
                            raise TypeError("name")
                    else:
                        raise TypeError("access-list")
            elif json_access_lists is not None:
                raise TypeError("access-list")
            
        except KeyError as error:
            raise InvalidMudProfileError(
                f"MUD Profile Access List policy {error} entry is missing."
            ) from error
        except TypeError as error:
            raise InvalidMudProfileError(
                f"MUD Profile Access List policy {error} entry is invalid."
            ) from error
