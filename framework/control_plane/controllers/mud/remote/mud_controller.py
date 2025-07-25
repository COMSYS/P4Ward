"""Local MUD controller"""

from __future__ import annotations
from typing import Any, Union
import typing
import os
import json
import time
import math
import logging
from urllib import request, parse

from framework.control_plane.tracing import TRACER
from framework.control_plane.models.mud.mud_profile import MudProfile
from framework.control_plane.controllers.mud.mud_controller import MudController
from framework.control_plane.controllers.mud.local.mud_controller import LocalMudController

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class RemoteMudController(LocalMudController):
    """Remote MUD management controller"""

    _origin_scheme: Union[str, None]
    _origin_host: Union[str, None]

    def __init__(self, switch: "Switch", origin: str = "") -> None:
        super(LocalMudController, self).__init__(switch)

        self._mud_profiles = {}
        origin_parsed = parse.urlparse(origin)
        self._origin_scheme = origin_parsed.scheme if origin_parsed.scheme else None
        self._origin_host = origin_parsed.netloc if origin_parsed.netloc else None

        logging.info("Using remote MUD controller.")

    async def get_profile(self, url: str) -> Union[MudProfile, None]:
        """Get mud profile using mud url

        Args:
            url (str): URL of the mud profile

        Returns:
            Union[MudProfile, None]: MUD Profile or none if it does not exist
        """

        TRACER.info(f"Fetching MUD profile '{url}': start")

        url_parsed = parse.urlparse(url)
        if self._origin_scheme is not None:
            url_parsed = url_parsed._replace(scheme=self._origin_scheme)
        if self._origin_host is not None:
            url_parsed = url_parsed._replace(netloc=self._origin_host)
        url2 = url_parsed.geturl()

        profile = await super().get_profile_from_cache(url)
        if profile is None:
            content: str = ""
            try:
                content = request.urlopen(url2).read()
            except Exception as exc:
                logging.error(f"Failed to read mud profile '{url}' from '{url2}':\n{exc}")
                TRACER.info(f"Fetching MUD profile '{url}': end (failed)")
                return None

            try:
                profile = MudProfile()
                profile.load_from_json(dict(json.loads(content)))
                profile.cache_time = int(time.time())

                if self._switch.config.mud.enable_cache:
                    self._mud_profiles[url] = profile
            except Exception as exc:
                logging.error(f"Failed to read mud profile '{url}':\n{exc}")
                TRACER.info(f"Fetching MUD profile '{url}': end (failed)")
                return None
            
        TRACER.info(f"Fetching MUD profile '{url}': end")

        return profile
