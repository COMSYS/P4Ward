"""Authentication metadata"""

from __future__ import annotations
from typing import Union
import time

from framework.control_plane.controllers.auth.auth_session import *
from framework.control_plane.controllers.auth.auth_session import AuthSession
from proto.authentication_access_pb2 import *
from proto.authentication_access_pb2_grpc import AuthenticationAccessStub


class ChallengeAuthMD5Challenge(AuthMD5Challenge):
    """Challenge MD5 authentication challenge"""

    _stub: AuthenticationAccessStub

    expected_value: Union[bytes, None]

    def __init__(self, session: AuthSession, stub: AuthenticationAccessStub) -> None:
        super().__init__(session)

        self._stub = stub
        self.expected_value = None

    async def prepare(self) -> None:
        try:
            request = ChallengeAuthenticationRequest(Name=self._session.name)
            response = await self._stub.ChallengeAuthentication(request)

            self.challenge = response.MD5.Challenge
            self.expected_value = response.MD5.Value
        except Exception as error:
            pass

    async def check(self, value: bytes) -> bool:
        if self._session.name is None:
            return False

        if self.challenge is None:
            return False

        return value == self.expected_value


class RemoteAuthMD5Challenge(AuthMD5Challenge):
    """Remote MD5 authentication challenge"""

    _stub: AuthenticationAccessStub

    def __init__(self, session: AuthSession, stub: AuthenticationAccessStub) -> None:
        super().__init__(session)

        self._stub = stub

    async def prepare(self) -> None:
        try:
            request = RemoteAuthenticationRequest(Name=self._session.name)
            response = await self._stub.RemoteAuthentication(request)

            self.challenge = response.MD5.Challenge
        except Exception as error:
            pass

    async def check(self, value: bytes) -> bool:
        if self._session.name is None:
            return False

        if self.challenge is None:
            return False

        try:
            request = RemoteAuthenticationCheckRequest(
                Name=self._session.name, MD5=RemoteMD5Check(Value=value)
            )
            response = await self._stub.RemoteAuthenticationCheck(request)

            return response.Result
        except Exception as error:
            return False


class ChallengeAuthOTPChallenge(AuthOTPChallenge):
    """Remote OTP authentication challenge"""

    _stub: AuthenticationAccessStub

    def __init__(
        self,
        session: AuthSession,
        algo: AuthOTPAlgo,
        per_auth: int,
        storing_factor: int,
        stub: AuthenticationAccessStub,
    ) -> None:
        super().__init__(session, algo, per_auth, storing_factor)

        self._stub = stub

    async def prepare(self) -> None:
        try:
            request = ChallengeAuthenticationRequest(Name=self._session.name)
            response = await self._stub.ChallengeAuthentication(request)

            self.seed = response.OTP.Seed
            self.challenge = response.OTP.Primer

            # Generate chain
            await super().prepare()
        except Exception as error:
            pass
