"""Base controller"""

import typing

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch

class Controller:
    """Controller base class"""

    _switch: 'Switch'

    def __init__(self, switch: 'Switch') -> None:
        self._switch = switch
