"""Remote Auth controller"""

from __future__ import annotations
from enum import Enum
import typing
from grpc import aio
from ipaddress import ip_address
import logging

from framework.control_plane.tracing import TRACER
from framework.control_plane.controllers.auth.auth_session import (
    AuthSession,
    AuthOTPAlgo,
)
import framework.control_plane.controllers.auth.local.auth_session as local
import framework.control_plane.controllers.auth.remote.auth_session as remote
from framework.control_plane.controllers.auth.auth_controller import AuthController

from proto.authentication_access_pb2 import *
import proto.authentication_access_pb2_grpc as authentication_access_grpc

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class AuthenticationProcedure(Enum):
    PASSWORD = 1
    CHALLENGE = 2
    REMOTE = 3


class RemoteAuthController(AuthController):
    """Remote Auth controller"""

    _procedure: AuthenticationProcedure
    _stub: authentication_access_grpc.AuthenticationAccessStub

    def __init__(
        self, switch: "Switch", host: str, procedure: AuthenticationProcedure
    ) -> None:
        super().__init__(switch)

        logging.info("Using remote authentication controller.")

        self._procedure = procedure

        # Connect authentication server
        channel = aio.insecure_channel(host)
        self._stub = authentication_access_grpc.AuthenticationAccessStub(channel)

    async def _identify_session(self, session: AuthSession) -> bool:

        TRACER.info(
            f"Identify authentication session for '{session.mac_address}': start"
        )

        try:
            identify_request = IdentifyUserRequest(Name=session.name)
            identify_response = await self._stub.IdentifyUser(identify_request)

            session.profile_url = identify_response.ProfileUrl
            session.ip_address = ip_address(identify_response.IpAddress)

            if self._procedure == AuthenticationProcedure.PASSWORD:
                authentication_request = PasswordAuthenticationRequest(
                    Name=session.name
                )
                authentication_response = await self._stub.PasswordAuthentication(
                    authentication_request
                )

                session.password = authentication_response.Password

                if identify_response.Type == AuthenticationType.EAP_MD5:
                    session.challenge = local.AuthMD5Challenge(session)
                elif identify_response.Type == AuthenticationType.EAP_OTP_MD5:
                    session.challenge = local.AuthOTPChallenge(
                        session,
                        AuthOTPAlgo.MD5,
                        self._otp_per_auth,
                        self._otp_storing_factor,
                    )
                elif identify_response.Type == AuthenticationType.EAP_OTP_SHA1:
                    session.challenge = local.AuthOTPChallenge(
                        session,
                        AuthOTPAlgo.SHA1,
                        self._otp_per_auth,
                        self._otp_storing_factor,
                    )
                elif identify_response.Type == AuthenticationType.EAP_OTP_SHA2:
                    session.challenge = local.AuthOTPChallenge(
                        session,
                        AuthOTPAlgo.SHA2,
                        self._otp_per_auth,
                        self._otp_storing_factor,
                    )
                elif identify_response.Type == AuthenticationType.EAP_OTP_SHA3:
                    session.challenge = local.AuthOTPChallenge(
                        session,
                        AuthOTPAlgo.SHA3,
                        self._otp_per_auth,
                        self._otp_storing_factor,
                    )

            elif self._procedure == AuthenticationProcedure.CHALLENGE:
                if identify_response.Type == AuthenticationType.EAP_MD5:
                    session.challenge = remote.ChallengeAuthMD5Challenge(
                        session, self._stub
                    )
                elif identify_response.Type == AuthenticationType.EAP_OTP_MD5:
                    session.challenge = remote.ChallengeAuthOTPChallenge(
                        session,
                        AuthOTPAlgo.MD5,
                        self._otp_per_auth,
                        self._otp_storing_factor,
                        self._stub,
                    )
                elif identify_response.Type == AuthenticationType.EAP_OTP_SHA1:
                    session.challenge = remote.ChallengeAuthOTPChallenge(
                        session,
                        AuthOTPAlgo.SHA1,
                        self._otp_per_auth,
                        self._otp_storing_factor,
                        self._stub,
                    )
                elif identify_response.Type == AuthenticationType.EAP_OTP_SHA2:
                    session.challenge = remote.ChallengeAuthOTPChallenge(
                        session,
                        AuthOTPAlgo.SHA2,
                        self._otp_per_auth,
                        self._otp_storing_factor,
                        self._stub,
                    )
                elif identify_response.Type == AuthenticationType.EAP_OTP_SHA3:
                    session.challenge = remote.ChallengeAuthOTPChallenge(
                        session,
                        AuthOTPAlgo.SHA3,
                        self._otp_per_auth,
                        self._otp_storing_factor,
                        self._stub,
                    )
            elif self._procedure == AuthenticationProcedure.REMOTE:
                if identify_response.Type == AuthenticationType.EAP_MD5:
                    session.challenge = remote.RemoteAuthMD5Challenge(
                        session, self._stub
                    )

            TRACER.info(
                f"Identify authentication session for '{session.mac_address}': end"
            )

            return True
        except Exception as error:
            TRACER.info(
                f"Identify authentication session for '{session.mac_address}': end (failed)"
            )
            return False
