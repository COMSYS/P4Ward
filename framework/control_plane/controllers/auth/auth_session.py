"""Authentication metadata"""

from __future__ import annotations
from typing import Union
import typing
from enum import Enum
import asyncio
import time
import hashlib
import zlib
from ipaddress import IPv4Address, IPv6Address
from macaddress import EUI48

from framework.control_plane.controllers.device.device import Device

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class AuthChallengeType(Enum):
    MD5 = "md5-challenge"
    OTP = "otp-challenge"


class AuthChallenge:
    """Authentication challenge"""

    _session: AuthSession

    def __init__(self, session: AuthSession) -> None:
        self._session = session

    async def prepare(self) -> None:
        raise NotImplementedError()


class AuthMD5Challenge(AuthChallenge):
    """MD5 Authentication challenge"""

    challenge: Union[bytes, None]

    def __init__(self, session: AuthSession) -> None:
        super().__init__(session)

        self.challenge = None

    async def check(self, value: bytes) -> bool:
        raise NotImplementedError()


# OTP_MAX_NUMBER = OTP_PER_AUTH * OTP_STORING_FACTOR
OTP_REGISTER_SIZE = 65000


class AuthOTPStatus(Enum):
    PENDING = 0
    AUTHENTICATED = 1
    REAUTHENTICATION_PENDING = 2


class AuthOTPAlgo(Enum):
    MD5 = 1
    SHA1 = 2
    SHA2 = 3
    SHA3 = 4


class AuthOTPChallenge(AuthChallenge):
    """OTP authentication challenge"""

    algo: AuthOTPAlgo

    status: AuthOTPStatus

    seed: str

    per_auth: int
    storing_factor: int

    challenge: bytes
    challenges: list[bytes]  # Challenges
    ready: list[bool]  # Challenge ready on hardware

    sequence_id: int

    slot_pos: Union[int, None]
    otp_read_index: int
    otp_write_index: int

    stored_until: int

    def __init__(
        self,
        session: AuthSession,
        algo: AuthOTPAlgo,
        per_auth: int,
        storing_factor: int,
    ) -> None:
        super().__init__(session)

        self.algo = algo
        self.status = AuthOTPStatus.PENDING

        self.seed = "aaaa"
        self.per_auth = per_auth
        self.storing_factor = storing_factor
        self.challenges = [bytes()] * self.per_auth * self.storing_factor
        self.ready = [False] * storing_factor

        self.sequence_id = 0

        self.slot_pos = None
        self.otp_read_index = storing_factor
        self.otp_write_index = storing_factor

    def _hash_step(self, value: bytes) -> bytes:
        if self.algo == AuthOTPAlgo.MD5:
            value = hashlib.md5(value).digest()
            return bytes([_a ^ _b for _a, _b in zip(value[0:8], value[8:16])])
        elif self.algo == AuthOTPAlgo.SHA1:
            value = hashlib.sha1(value).digest()
            return bytes(
                [
                    _a ^ _b ^ _c
                    for _a, _b, _c in zip(
                        value[0:8],
                        value[8:16],
                        value[16:20] + bytes([0x00, 0x00, 0x00, 0x00]),
                    )
                ]
            )
        elif self.algo == AuthOTPAlgo.SHA2:
            value = hashlib.sha256(value).digest()
            return bytes(
                [
                    _a ^ _b ^ _c ^ _d
                    for _a, _b, _c, _d in zip(
                        value[0:8], value[8:16], value[16:24], value[24:32]
                    )
                ]
            )
        elif self.algo == AuthOTPAlgo.SHA3:
            value = hashlib.sha3_256(value).digest()
            return bytes(
                [
                    _a ^ _b ^ _c ^ _d
                    for _a, _b, _c, _d in zip(
                        value[0:8], value[8:16], value[16:24], value[24:32]
                    )
                ]
            )
        else:
            return bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

    async def prepare(self) -> None:
        self.challenges[0] = self.challenge
        self.ready = [False] * self.storing_factor  # Reset data plane ready flags
        for index in range(1, self.per_auth * self.storing_factor):
            self.challenges[index] = self._hash_step(self.challenges[index - 1])


class AuthSession:
    """Authentication session"""

    _switch: "Switch"

    port: int
    mac_address: EUI48
    name: str
    password: Union[str, None]

    ip_address: Union[IPv4Address, IPv6Address, None]
    profile_url: Union[str, None]

    challenge: Union[AuthChallenge, None]

    is_logged_in: bool
    terminated: bool
    login_event: asyncio.Event

    # Last login time in milliseconds
    last_login: int

    authentication_counter: int

    def __init__(self, switch: "Switch", port: int, mac_address: EUI48) -> None:
        self._switch = switch
        self.port = port
        self.mac_address = mac_address
        self.name = ""
        self.password = None
        self.challenge = None
        self.is_logged_in = False
        self.terminated = False
        self.login_event = asyncio.Event()
        self.last_login = 0
        self.authentication_counter = 0

    def get_id(self) -> int:
        return zlib.crc32(bytes(self.mac_address)) & 0xFFFF

    def initialize(self):
        self.name = ""
        self.password = None
        self.challenge = None

        # Add L2 route
        self._switch.l2.add_route(mac_address=self.mac_address, port=self.port)

    async def login(self):
        if not self.is_logged_in:
            if self.ip_address is not None and self.profile_url is not None:
                profile = await self._switch.mud.get_profile(self.profile_url)
                if profile is not None:
                    self._switch.device.add_device(
                        Device(
                            port=self.port,
                            mac_address=self.mac_address,
                            ip_addresses=[self.ip_address],
                            profile=profile,
                            group="AUTH",
                        )
                    )

        self.last_login = int(time.time() * 1000)
        self.authentication_counter += 1
        self.is_logged_in = True
        self.login_event.set()

    def terminate(self):
        # Remove device
        self._switch.device.remove_device(
            mac_address=self.mac_address,
            group="AUTH",
        )

        # Remove L2 route
        self._switch.l2.remove_route(mac_address=self.mac_address)

        self.is_logged_in = False
        self.terminated = True
