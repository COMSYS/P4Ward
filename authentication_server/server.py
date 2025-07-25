from __future__ import annotations
from typing import Union
import os
import asyncio
import logging
import grpc
import hashlib
import random
from concurrent import futures
from ipaddress import IPv4Address

from authentication_server.config.server import ServerConfig
from authentication_server.user import AuthenticationMethod, User
from proto.authentication_access_pb2 import *
import proto.authentication_access_pb2_grpc as authentication_access_grpc

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


class Server:
    """Server manager"""

    config: ServerConfig

    users: dict[str, User]

    def __init__(self, config: ServerConfig) -> None:
        self.config = config

        # Initialize users
        self.users = {}
        for user_config in config.users.users:
            auth_method: AuthenticationMethod
            if user_config.authentication_method == "eap-md5":
                auth_method = AuthenticationMethod.MD5
            elif user_config.authentication_method == "eap-otp-md5":
                auth_method = AuthenticationMethod.OTP_MD5
            elif user_config.authentication_method == "eap-otp-sha1":
                auth_method = AuthenticationMethod.OTP_SHA1
            elif user_config.authentication_method == "eap-otp-sha2":
                auth_method = AuthenticationMethod.OTP_SHA2
            elif user_config.authentication_method == "eap-otp-sha3":
                auth_method = AuthenticationMethod.OTP_SHA3
            else:
                raise ValueError("Invalid 'auth-method' attribute.")

            user = User(
                user_config.name,
                user_config.password,
                auth_method,
                user_config.ip_address,
                user_config.profile,
                user_config.attributes,
            )
            self.users[user.name] = user
            logging.info(f"Added user '{user.name}'")

    def run(self) -> None:
        """Run controller"""

        address = f"{self.config.bind.address}:{self.config.bind.port}"
        logging.info(f"Binding to {address}")

        server = grpc.server(futures.ThreadPoolExecutor(max_workers=3))
        authentication_access_grpc.add_AuthenticationAccessServicer_to_server(
            AccessService(self), server
        )
        server.add_insecure_port(address)
        server.start()
        server.wait_for_termination()


class AccessService(authentication_access_grpc.AuthenticationAccessServicer):
    """GRPC Service"""

    _server: Server

    def __init__(self, server: Server) -> None:
        super().__init__()

        self._server = server

    def IdentifyUser(self, request, context):
        logging.info(f"Identify user {request.Name}")
        if (user := self._server.users.get(request.Name)) is not None:

            def convert_authentication_type(type: AuthenticationMethod):
                """Convert auth. algorithm to GRPC auth. type"""
                if type == AuthenticationMethod.MD5:
                    return AuthenticationType.EAP_MD5
                elif type == AuthenticationMethod.OTP_MD5:
                    return AuthenticationType.EAP_OTP_MD5
                elif type == AuthenticationMethod.OTP_SHA1:
                    return AuthenticationType.EAP_OTP_SHA1
                elif type == AuthenticationMethod.OTP_SHA2:
                    return AuthenticationType.EAP_OTP_SHA2
                elif type == AuthenticationMethod.OTP_SHA3:
                    return AuthenticationType.EAP_OTP_SHA3
                else:
                    logging.warn(f"Invalid authentication algorithm '{type}'")
                    return AuthenticationType.EAP_OTP_MD5

            return IdentifyUserResponse(
                Type=convert_authentication_type(user.auth_method),
                ProfileUrl=user.mud_profile,
                IpAddress=str(user.ip_address),
                Attributes=user.attributes,
            )
        else:
            logging.error("Invalid username")
            raise grpc.RpcError("Invalid username")

    def PasswordAuthentication(self, request, context):
        logging.info(f"Authenticate user {request.Name} (password)")
        if (user := self._server.users.get(request.Name)) is not None:
            return PasswordAuthenticationResponse(Password=user.password)
        else:
            logging.error("Invalid username")
            raise grpc.RpcError("Invalid username")

    def _hash_step(self, algo: AuthenticationMethod, value: bytes) -> bytes:
        if algo == AuthenticationMethod.OTP_MD5:
            value = hashlib.md5(value).digest()
            return bytes([_a ^ _b for _a, _b in zip(value[0:8], value[8:16])])
        elif algo == AuthenticationMethod.OTP_SHA1:
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
        elif algo == AuthenticationMethod.OTP_SHA2:
            value = hashlib.sha256(value).digest()
            return bytes(
                [
                    _a ^ _b ^ _c ^ _d
                    for _a, _b, _c, _d in zip(
                        value[0:8], value[8:16], value[16:24], value[24:32]
                    )
                ]
            )
        elif algo == AuthenticationMethod.OTP_SHA3:
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

    def ChallengeAuthentication(self, request, context):
        logging.info(f"Authenticate user {request.Name} (challenge)")
        if (user := self._server.users.get(request.Name)) is not None:
            if user.auth_method == AuthenticationMethod.MD5:
                # Generate challenge and calculate value
                challenge = os.urandom(16)
                value = hashlib.md5(
                    user.name.encode("utf-8")
                    + user.password.encode("utf-8")
                    + challenge
                ).digest()

                # Send MD5 challenge and expected value
                return ChallengeAuthenticationResponse(
                    MD5=ChallengeMD5(Challenge=challenge, Value=value)
                )
            elif (
                user.auth_method == AuthenticationMethod.OTP_MD5
                or user.auth_method == AuthenticationMethod.OTP_SHA1
                or user.auth_method == AuthenticationMethod.OTP_SHA2
                or user.auth_method == AuthenticationMethod.OTP_SHA3
            ):
                # Generate seed and calculate primer
                seed = "".join(
                    map(
                        lambda a: SEED_CHARACTERS[a],
                        random.sample(range(0, len(SEED_CHARACTERS)), 4),
                    )
                )
                primer = self._hash_step(
                    user.auth_method, (user.password + seed).encode("utf-8")
                )

                # Send OPT seed and chain primer
                return ChallengeAuthenticationResponse(
                    OTP=ChallengeOTP(Seed=seed, Primer=primer)
                )
            else:
                raise grpc.RpcError("Invalid or unsupported authentication algorithm")
        else:
            logging.error("Invalid username")
            raise grpc.RpcError("Invalid username")

    def RemoteAuthentication(self, request, context):
        if (user := self._server.users.get(request.Name)) is not None:
            if user.auth_method == AuthenticationMethod.MD5:
                # Generate challenge and calculate value
                challenge = os.urandom(16)
                user.value = hashlib.md5(
                    user.name.encode("utf-8")
                    + user.password.encode("utf-8")
                    + challenge
                ).digest()

                # Send MD5 challenge
                return RemoteAuthenticationResponse(MD5=RemoteMD5(Challenge=challenge))
            else:
                raise grpc.RpcError("Invalid or unsupported authentication algorithm")
        else:
            logging.error("Invalid username")
            raise grpc.RpcError("Invalid username")

    def RemoteAuthenticationCheck(self, request, context):
        logging.info(f"Authenticate user {request.Name} (remote)")
        if (user := self._server.users.get(request.Name)) is not None:
            if user.auth_method == AuthenticationMethod.MD5:
                return RemoteAuthenticationCheckResponse(
                    Result=request.MD5.Value == user.value
                )
            else:
                raise grpc.RpcError("Invalid or unsupported authentication algorithm")
        else:
            logging.error("Invalid username")
            raise grpc.RpcError("Invalid username")
