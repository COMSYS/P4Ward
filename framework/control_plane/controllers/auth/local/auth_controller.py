"""Local Auth controller"""

from __future__ import annotations
from typing import Any, Coroutine, Union
import typing
from ipaddress import IPv4Address, IPv6Address
import logging

from framework.control_plane.controllers.auth.auth_session import (
    AuthChallengeType,
    AuthSession,
)
from framework.control_plane.controllers.auth.local.auth_session import *
from framework.control_plane.controllers.auth.auth_controller import AuthController

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class LocalUser:
    name: str
    password: str
    ip_address: Union[IPv4Address, IPv6Address]
    profile: str

    challenge_type: AuthChallengeType
    otp_algorithm: AuthOTPAlgo

    def __init__(
        self,
        name: str,
        password: str,
        ip_address: Union[IPv4Address, IPv6Address],
        profile: str,
        challenge_type: AuthChallengeType,
        otp_algorithm: AuthOTPAlgo = AuthOTPAlgo.MD5,
    ) -> None:
        self.name = name
        self.password = password
        self.ip_address = ip_address
        self.profile = profile
        self.challenge_type = challenge_type
        self.otp_algorithm = otp_algorithm


class LocalAuthController(AuthController):
    """Local Auth controller"""

    _users: dict[str, LocalUser]

    def __init__(self, switch: "Switch") -> None:
        super().__init__(switch)

        logging.info("Using local authentication controller.")

        self._users = {}

        for user_config in self._switch.config.auth.users:
            challenge_type: AuthChallengeType
            otp_algorithm: AuthOTPAlgo = AuthOTPAlgo.MD5
            if user_config.authentication_method == "eap-md5":
                challenge_type = AuthChallengeType.MD5
            elif user_config.authentication_method == "eap-otp-md5":
                challenge_type = AuthChallengeType.OTP
                otp_algorithm = AuthOTPAlgo.MD5
            elif user_config.authentication_method == "eap-otp-sha1":
                challenge_type = AuthChallengeType.OTP
                otp_algorithm = AuthOTPAlgo.SHA1
            elif user_config.authentication_method == "eap-otp-sha2":
                challenge_type = AuthChallengeType.OTP
                otp_algorithm = AuthOTPAlgo.SHA2
            elif user_config.authentication_method == "eap-otp-sha3":
                challenge_type = AuthChallengeType.OTP
                otp_algorithm = AuthOTPAlgo.SHA3
            else:
                raise ValueError("Invalid 'auth-method' attribute.")

            self._users[user_config.name] = LocalUser(
                user_config.name,
                user_config.password,
                user_config.ip_address,
                user_config.profile,
                challenge_type,
                otp_algorithm,
            )

    async def _identify_session(self, session: AuthSession) -> bool:
        if (user := self._users.get(session.name)) is not None:
            session.password = user.password
            session.ip_address = user.ip_address
            session.profile_url = user.profile

            if user.challenge_type == AuthChallengeType.MD5:
                session.challenge = AuthMD5Challenge(session)
            elif user.challenge_type == AuthChallengeType.OTP:
                session.challenge = AuthOTPChallenge(
                    session,
                    user.otp_algorithm,
                    self._otp_per_auth,
                    self._otp_storing_factor,
                )

            return True
        else:
            return False
