"""ACL Goose Extension"""

from __future__ import annotations
from typing import Union


class AcGooseExtension:
    """Access Control Goose Extension"""

    # Specify allowed app ids
    app_id: Union[int, None]

    def __init__(self, app_id: Union[int, None] = None) -> None:
        self.app_id = app_id
