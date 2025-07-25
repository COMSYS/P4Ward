"""MUD Profile"""

from __future__ import annotations
from typing import Any, Union
from datetime import datetime

from framework.control_plane.models.mud import InvalidMudProfileError
from framework.control_plane.models.mud.device_policy import MudDevicePolicy
from framework.control_plane.models.mud.access_control import MudAccessControlList


class MudProfile:
    """Mud profile model"""

    # Mud version
    version: int

    # Profile url
    url: str

    # Last mud profile update
    last_update: datetime

    # In cache profile validity in hours
    cache_validity: int
    cache_time: Union[int, None]

    is_supported: bool

    # Short description of the profile
    system_info: Union[str, None]

    controller_name: Union[str, None]
    manufacturer_name: Union[str, None]
    model_name: Union[str, None]
    firmware_revision: Union[str, None]
    software_revision: Union[str, None]

    # URL to profile and/or device documentation
    documentation_url: str

    # Profile independence
    independent: Union[bool, None]

    # Profile extensions
    extension_names: list[str]

    from_device_policy: MudDevicePolicy
    to_device_policy: MudDevicePolicy

    access_control_lists: dict[str, MudAccessControlList]

    def __init__(self) -> None:
        self.version = 1
        self.url = ""
        self.last_update = datetime.min
        self.cache_validity = 48
        self.cache_time = None
        self.is_supported = True
        self.system_info = None
        self.controller_name = None
        self.manufacturer_name = None
        self.model_name = None
        self.firmware_revision = None
        self.software_revision = None
        self.documentation_url = ""
        self.independent = None
        self.extension_names = []
        self.from_device_policy = MudDevicePolicy()
        self.to_device_policy = MudDevicePolicy()
        self.access_control_lists = {}

    def get_controller_id(self) -> int:
        return self.controller_name.__hash__() & 0xFFFFFFFF

    def get_controller_id_bytes(self) -> bytes:
        return self.get_controller_id().to_bytes(4, "big")

    def get_manufacturer_id(self) -> int:
        return self.manufacturer_name.__hash__() & 0xFFFF

    def get_manufacturer_id_bytes(self) -> bytes:
        return self.get_manufacturer_id().to_bytes(2, "big")

    def get_model_id(self) -> int:
        return self.model_name.__hash__() & 0xFFFF

    def get_model_id_bytes(self) -> bytes:
        return self.get_model_id().to_bytes(2, "big")

    def load_from_json(self, json: dict[str, Any]):
        """Load MUD profile from JSON

        Args:
            json (dict[str, Any]): JSON

        Raises:
            InvalidMudProfileError: MUD profile is not valid
        """

        # Parse descriptor
        json_mud = dict(json.get("ietf-mud:mud", None))
        if json_mud is None:
            raise InvalidMudProfileError(
                "MUD Profile descriptor is missing. Consider adding a 'ietf-mud:mud' object to the mud profile."
            )

        try:
            if isinstance((version := json_mud["mud-version"]), int):
                self.version = version
            else:
                raise TypeError("mud-version")

            if isinstance((url := json_mud["mud-url"]), str):
                self.url = url
            else:
                raise TypeError("mud-url")

            if isinstance((last_update := json_mud["last-update"]), str):
                self.last_update = datetime.fromisoformat(last_update)
            else:
                raise TypeError("last-update")

            if isinstance((cache_validity := json_mud.get("cache-validity")), int):
                self.cache_validity = cache_validity
            elif cache_validity is not None:
                raise TypeError("cache-validity")

            if isinstance((is_supported := json_mud.get("is-supported")), bool):
                self.is_supported = is_supported
            elif is_supported is not None:
                raise TypeError("is-supported")

            if isinstance((system_info := json_mud.get("systeminfo")), str):
                self.system_info = system_info
            elif system_info is not None:
                raise TypeError("systeminfo")

            if isinstance((independent := json_mud.get("independent")), bool):
                self.independent = independent
            elif independent is not None:
                raise TypeError("independent")

            if isinstance((controller_name := json_mud.get("controller-name")), str):
                self.controller_name = controller_name
            elif controller_name is not None:
                raise TypeError("controller-name")

            if isinstance((manufacturer_name := json_mud.get("mfg-name")), str):
                self.manufacturer_name = manufacturer_name
            elif manufacturer_name is not None:
                raise TypeError("mfg-name")

            if isinstance((model_name := json_mud.get("model-name")), str):
                self.model_name = model_name
            elif model_name is not None:
                raise TypeError("model-name")

            if isinstance((firmware_revision := json_mud.get("firmware-rev")), str):
                self.firmware_revision = firmware_revision
            elif firmware_revision is not None:
                raise TypeError("firmware-rev")

            if isinstance((software_revision := json_mud.get("software-rev")), str):
                self.software_revision = software_revision
            elif software_revision is not None:
                raise TypeError("software-rev")

            if isinstance((documentation_url := json_mud.get("documentation")), str):
                self.documentation_url = documentation_url
            elif documentation_url is not None:
                raise TypeError("documentation")

            for extension_name in json_mud.get("extensions", []):
                self.extension_names.append(extension_name)

            self.to_device_policy.load_from_json(dict(json_mud["to-device-policy"]), self.extension_names)
            self.from_device_policy.load_from_json(dict(json_mud["from-device-policy"]), self.extension_names)
        except KeyError as error:
            raise InvalidMudProfileError(
                f"MUD Profile descriptor {error} entry is missing."
            ) from error
        except TypeError as error:
            raise InvalidMudProfileError(
                f"MUD Profile descriptor {error} entry is invalid."
            ) from error

        # Parse access control lists
        json_acls = dict(json.get("ietf-access-control-list:acls", None))
        if json_acls is None:
            raise InvalidMudProfileError(
                "MUD Profile acl is missing. Consider adding a 'ietf-access-control-list:acls' object to the mud profile."
            )

        try:
            for json_acl in list(json_acls.get("acl", [])):
                access_control_list = MudAccessControlList()
                access_control_list.load_from_json(dict(json_acl), self.extension_names)
                self.access_control_lists[
                    access_control_list.name
                ] = access_control_list
        except KeyError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACLs {error} entry is missing."
            ) from error
        except TypeError as error:
            raise InvalidMudProfileError(
                f"MUD Profile ACLs {error} entry is invalid."
            ) from error