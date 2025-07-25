"""Local MUD controller"""

from __future__ import annotations
from typing import Any, Union
import typing
import os
import json
import time
import math
import logging

from framework.control_plane.models.mud.mud_profile import MudProfile
from framework.control_plane.controllers.mud.mud_controller import MudController

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class LocalMudController(MudController):
    """Local MUD management controller"""

    _mud_profiles: dict[str, Union[MudProfile, None]]

    def __init__(self, switch: 'Switch', origin: str) -> None:
        super().__init__(switch)

        logging.info("Using local MUD controller.")

        self._mud_profiles = {}

        if not os.path.isdir(origin):
            origin = "mud_profiles"

        for root, dirpaths, filepaths in os.walk(origin):
            for filepath in filepaths:
                try:
                    filepath = os.path.abspath(os.path.join(root, filepath))
                    file = open(filepath, "r", encoding="UTF-8")
                    profile = MudProfile()
                    profile.load_from_json(dict(json.load(file)))
                    self._mud_profiles[profile.url] = profile
                except Exception as exc:
                    logging.error(f"Failed to read mud profile '{filepath}':\n{exc}")

    async def get_profile_from_cache(self, url: str) -> Union[MudProfile, None]:
        """Get mud profile using mud url

        Args:
            url (str): URL of the mud profile

        Returns:
            Union[MudProfile, None]: MUD Profile or none if it does not exist
        """

        mud_profile = self._mud_profiles.get(url)
        if mud_profile is None:
            return None
        
        if mud_profile.cache_time is not None:
            current_time = int(time.time()) # Seconds
            cache_time = current_time - mud_profile.cache_time
            if cache_time > mud_profile.cache_time:
                return None 
        
        return mud_profile

    async def get_profile(self, url: str) -> Union[MudProfile, None]:
        """Get mud profile using mud url

        Args:
            url (str): URL of the mud profile

        Returns:
            Union[MudProfile, None]: MUD Profile or none if it does not exist
        """

        mud_profile = await self.get_profile_from_cache(url)
        if mud_profile is None:
            logging.error(f"Mud profile '{url}' is either invalid or nonexistent")
        
        return mud_profile