"""Authentication metadata"""

from __future__ import annotations
from typing import Union
import os
import random
import hashlib

import framework.control_plane.controllers.auth.auth_session as base
from framework.control_plane.controllers.auth.auth_session import (
    AuthSession,
    AuthOTPAlgo,
)


class AuthMD5Challenge(base.AuthMD5Challenge):
    """Local MD5 authentication challenge"""

    def __init__(self, session: AuthSession) -> None:
        super().__init__(session)

        self.challenge = None

    async def prepare(self) -> None:
        self.challenge = os.urandom(16)

    async def check(self, value: bytes) -> bool:
        if self._session.name is None or self._session.password is None:
            return False

        if self.challenge is None:
            return False

        expected_value = hashlib.md5(
            self._session.name.encode("utf-8")
            + self._session.password.encode("utf-8")
            + self.challenge
        ).digest()

        self.challenge = None

        return value == expected_value


SEED_CHARACTERS = [
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
]


class AuthOTPChallenge(base.AuthOTPChallenge):
    """Local OTP authentication challenge"""

    def __init__(
        self,
        session: AuthSession,
        algo: AuthOTPAlgo,
        per_auth: int,
        storing_factor: int,
    ) -> None:
        super().__init__(session, algo, per_auth, storing_factor)

    async def prepare(self) -> None:
        if self._session.password is None:
            raise ValueError()

        self.seed = "".join(
            map(
                lambda a: SEED_CHARACTERS[a],
                random.sample(range(0, len(SEED_CHARACTERS)), 4),
            )
        )
        self.challenge = self._hash_step(
            (self._session.password + self.seed).encode("utf-8")
        )

        # Generate chain
        await super().prepare()
