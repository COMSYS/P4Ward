"""Auth controller"""

from __future__ import annotations
from typing import Any, Union
import typing
import logging
from ipaddress import IPv4Address
from macaddress import EUI48
import hashlib
import asyncio
import types
from scapy.packet import Padding
from scapy.layers.l2 import Ether
from scapy.layers.eap import EAPOL, EAP, EAP_MD5

from framework.control_plane.tracing import TRACER
from framework.control_plane.controllers.controller import Controller
from framework.control_plane.data_plane.register import DPRegister
from framework.control_plane.controllers.auth.eap_ext import *
from framework.control_plane.controllers.auth.auth_session import *
from framework.control_plane.controllers.device.device import Device

if typing.TYPE_CHECKING:
    from framework.control_plane.switch import Switch


class EAPError(Exception):
    """EAP protocol error"""


class EAPAuthenticationError(Exception):
    """EAP authentication error"""


class AuthController(Controller):
    """Auth Controller"""

    _devices: dict[EUI48, AuthSession]

    _otp_per_auth: int
    _otp_storing_factor: int

    _otp_mapping: list[bool]

    _otp_kdf_type_register: DPRegister
    _otp_seed_register: DPRegister
    _otp_position_register: DPRegister
    _otp_remaining_steps_register: DPRegister

    _otp_sequence_id_register: DPRegister
    _otp_first_register: DPRegister
    _otp_second_register: DPRegister

    def __init__(self, switch: "Switch") -> None:
        super().__init__(switch)

        self._devices = {}

        self._otp_per_auth = self._switch.config.auth.otp.per_auth
        self._otp_storing_factor = self._switch.config.auth.otp.storing_factor

        self._otp_mapping = [False] * int(OTP_REGISTER_SIZE / (self._otp_per_auth * self._otp_storing_factor))

        self._otp_kdf_type_register = self._switch.data_plane.get_register(
            "Ingress.auth.kdf_type_register"
        )
        self._otp_seed_register = self._switch.data_plane.get_register(
            "Ingress.auth.seed_register"
        )
        self._otp_position_register = self._switch.data_plane.get_register(
            "Ingress.auth.position_register"
        )
        self._otp_remaining_steps_register = self._switch.data_plane.get_register(
            "Ingress.auth.remaining_steps_register"
        )

        self._otp_sequence_id_register = self._switch.data_plane.get_register(
            "Ingress.auth.sequence_id_register"
        )
        self._otp_first_register = self._switch.data_plane.get_register(
            "Ingress.auth.otp_first_register"
        )
        self._otp_second_register = self._switch.data_plane.get_register(
            "Ingress.auth.otp_second_register"
        )

        # Send router hello
        for mac_address, port in self._switch.config.router_hello.addresses.items():
            # Add layer 2 route
            self._switch.l2.add_route(EUI48(mac_address), port)

            # Send custom router hello packet
            self._switch.data_plane.get_socket().send(
                bytes(
                    Ether(
                        src=bytes(self._switch.get_port_address(port)),
                        dst=bytes(EUI48(mac_address)),
                        type=0xFFFF,
                    )
                ),
            )

    async def _identify_session(self, session: AuthSession) -> bool:
        raise NotImplementedError()

    def _initialize_session(
        self, port: int, mac_address: EUI48
    ) -> Union[AuthSession, None]:
        if (device := self._devices.get(mac_address)) is not None:
            # Check port
            if not device.is_logged_in or device.port == port:
                return device
            else:
                self._terminate_session(mac_address)

        # Add device
        device = self._devices[mac_address] = AuthSession(
            switch=self._switch,
            port=port,
            mac_address=mac_address,
        )
        device.initialize()

        return device

    def _terminate_session(self, mac_address: EUI48):
        try:
            session: AuthSession = self._devices.pop(mac_address)
            session.terminate()

            if isinstance(session.challenge, AuthOTPChallenge):
                if session.challenge.slot_pos is not None:
                    self._otp_mapping[session.challenge.slot_pos] = False
        except Exception as error:
            pass

    async def _handle_login_timeout(self, session: AuthSession):
        last_login = session.last_login
        session.login_event.clear()

        try:
            await asyncio.wait_for(
                session.login_event.wait(),
                timeout=self._switch.config.auth.timeout,
                loop=asyncio.get_event_loop(),
            )
        except asyncio.TimeoutError:
            if session.last_login <= last_login and not session.terminated:
                logging.info(
                    "EAP authentication of '%s' failed due to login timeout.",
                    session.mac_address,
                )
                self._terminate_session(session.mac_address)

                await self._send_eap_failure(session.port, session.mac_address, 1)

    async def _handle_relogin_interval(self, session: AuthSession):
        await asyncio.sleep(
            delay=self._switch.config.auth.reauth,
            loop=asyncio.get_event_loop(),
        )

        if session.is_logged_in:
            logging.info(
                "EAP reauthentication of '%s'",
                session.mac_address,
            )

            if isinstance(session.challenge, AuthMD5Challenge):
                await self._handle_eap_request_md5(
                    port=session.port,
                    eap_id=1,  # TODO check eap ip handling
                    session=session,
                )
            elif isinstance(session.challenge, AuthOTPChallenge):
                await self._handle_eap_request_otp(
                    port=session.port,
                    eap_id=1,  # TODO check eap ip handling
                    session=session,
                )

            asyncio.get_event_loop().create_task(self._handle_login_timeout(session))

    ######## Basic EAP handling ########

    async def _send_eap_packet(
        self,
        port: int,
        dst_mac_address: EUI48,
        eap_packet: EAP,
    ):
        await asyncio.get_event_loop().sock_sendall(
            self._switch.data_plane.get_socket(),
            bytes(
                Ether(
                    src=bytes(self._switch.get_port_address(port)),
                    dst=bytes(dst_mac_address),
                    type=0x888E,  # EAPoL
                )
                / EAPOL(
                    version=1,
                    type=EAPoLType.EAP_PACKET,
                )
                / eap_packet
            ),
        )

    async def _send_eap_success(
        self,
        port: int,
        dst_mac_address: EUI48,
        eap_id: int,
    ):
        await self._send_eap_packet(
            port=port,
            dst_mac_address=dst_mac_address,
            eap_packet=EAP(
                code=EAPCode.SUCCESS,
                id=eap_id,
            ),
        )

    async def _send_eap_failure(
        self,
        port: int,
        dst_mac_address: EUI48,
        eap_id: int,
    ):
        await self._send_eap_packet(
            port=port,
            dst_mac_address=dst_mac_address,
            eap_packet=EAP(
                code=EAPCode.FAILURE,
                id=eap_id,
            ),
        )

    async def handle_eap_packet(self, ether_packet: Ether):
        # Parse EAP Metadata
        eap_meta_packet: EAP_META = ether_packet[EAP_META]

        src_mac_address = EUI48(ether_packet.src)

        # Parse EAPoL packet
        eapol_packet: EAPOL = eap_meta_packet[EAPOL]

        if eapol_packet.type == 0x0:  # EAP-Packet
            # Parse EAP packet
            eap_packet: EAP = eapol_packet[EAP]

            try:
                # Add/get device
                session = self._devices.get(src_mac_address)
                if session is None:
                    raise EAPError("Authentication session does not exist.")

                if eap_packet.code == EAPCode.RESPONSE:
                    if eap_meta_packet.type == EAPMetadataType.MESSAGE:
                        if eap_packet.type == EAPType.IDENTITY:
                            await self._handle_eap_identity(
                                port=eap_meta_packet.port,
                                ether_packet=ether_packet,
                                session=session,
                                eap_packet=eap_packet,
                            )
                        elif eap_packet.type == EAPType.MD5:
                            await self._handle_eap_response_md5(
                                port=eap_meta_packet.port,
                                eap_id=eap_packet.id,
                                eap_value=bytes(eapol_packet[EAP_MD5].value),
                                session=session,
                            )
                        else:
                            raise EAPError("Invalid eap type (Internal Error).")
                    elif eap_meta_packet.type == EAPMetadataType.SUCCESS:
                        if eap_packet.type == EAPType.OTP:
                            await self._handle_eap_response_otp(
                                port=eap_meta_packet.port,
                                eap_id=eap_packet.id,
                                eap_value=bytes(eap_packet[Padding].load),
                                session=session,
                            )
                        else:
                            raise EAPError("Invalid eap type (Internal Error).")
                    elif eap_meta_packet.type == EAPMetadataType.FAILURE:
                        raise EAPAuthenticationError("Authentication failed.")
                    else:
                        raise EAPError("Invalid packet (Internal Error).")
                else:
                    logging.error("Invalid EAP code '%s'.", eap_packet.type)
            except EAPAuthenticationError as error:
                logging.info(
                    "EAP authentication error on port '%s'. %s",
                    eap_meta_packet.port,
                    error,
                )
                await self._send_eap_failure(
                    port=eap_meta_packet.port,
                    dst_mac_address=src_mac_address,
                    eap_id=eap_packet.id,
                )
                self._terminate_session(src_mac_address)
            except EAPError as error:
                logging.info(
                    "EAP protocol error on port '%s'. %s", eap_meta_packet.port, error
                )
                await self._send_eap_failure(
                    port=eap_meta_packet.port,
                    dst_mac_address=src_mac_address,
                    eap_id=eap_packet.id,
                )
                self._terminate_session(src_mac_address)
        elif eapol_packet.type == 0x1:  # EAPoL-Start
            await self._handle_eap_start(
                eap_meta_packet.port, ether_packet, eap_meta_packet
            )
        elif eapol_packet.type == 0x2:  # EAPoL-Logoff
            await self._handle_eap_logoff(ether_packet)
        else:
            logging.error("Invalid EAPoL type '%s'", eapol_packet.type)

    async def _handle_eap_start(
        self,
        port: int,
        ether_packet: Ether,
        eap_meta_packet: EAP_META,
    ):
        mac_address = EUI48(ether_packet.src)

        logging.info("EAP start from '%s'.", mac_address)

        TRACER.info(f"Authenticating (first) device '{mac_address}': start")

        session = self._initialize_session(
            int(eap_meta_packet.port),
            mac_address,
        )
        if session is None:
            return None

        await self._send_eap_packet(
            port=port,
            dst_mac_address=session.mac_address,
            eap_packet=EAP(
                code=EAPCode.REQUEST,
                id=1,
                type=EAPType.IDENTITY,
            ),
        )
        asyncio.get_event_loop().create_task(self._handle_login_timeout(session))

    async def _handle_eap_identity(
        self,
        port: int,
        ether_packet: Ether,
        session: AuthSession,
        eap_packet: EAP,
    ) -> Union[Packet, None]:
        logging.info("EAP identity from '%s'.", session.mac_address)

        TRACER.info(
            f"Authenticating ({'re' if session.is_logged_in else 'first'}) device '{session.mac_address}': identity"
        )

        session.name = eap_packet.identity.decode("utf-8")

        if await self._identify_session(session):
            if isinstance(session.challenge, AuthMD5Challenge):
                await self._handle_eap_request_md5(
                    port=port,
                    eap_id=eap_packet.id,
                    session=session,
                )
            elif isinstance(session.challenge, AuthOTPChallenge):
                await self._handle_eap_request_otp(
                    port=port,
                    eap_id=eap_packet.id,
                    session=session,
                )
            else:
                raise EAPError("Invalid EAP challenge.")
        else:
            raise EAPError("User does not exist.")

    async def _handle_eap_logoff(
        self,
        ether_packet: Ether,
    ) -> Union[Packet, None]:
        mac_address = EUI48(ether_packet.src)

        logging.info("EAP logoff '%s'.", mac_address)

        # Remove session
        self._terminate_session(mac_address)

    ######## MD5 Challenge ########

    async def _handle_eap_request_md5(
        self,
        port: int,
        eap_id: int,
        session: AuthSession,
    ) -> Union[Packet, None]:
        if not isinstance(session.challenge, AuthMD5Challenge):
            raise EAPAuthenticationError("Wrong authentication procedure.")

        TRACER.info(
            msg=f"Authenticating ({'re' if session.is_logged_in else 'first'}) device '{session.mac_address}': eap-md5 challenge"
        )

        await session.challenge.prepare()

        await self._send_eap_packet(
            port=port,
            dst_mac_address=session.mac_address,
            eap_packet=EAP_MD5(
                type=EAPType.MD5,
                id=eap_id + 1,  # TODO check EAP IP handling
                value=session.challenge.challenge,
            ),
        )

    async def _handle_eap_response_md5(
        self,
        port: int,
        eap_id: int,
        eap_value: bytes,
        session: AuthSession,
    ):
        logging.info("EAP MD5 response from '%s'.", session.mac_address)

        if isinstance(session.challenge, AuthMD5Challenge):
            if await session.challenge.check(eap_value):
                logging.info(
                    "EAP-MD5 authentication of '%s' succeeded.", session.mac_address
                )

                is_logged_in = session.is_logged_in
                TRACER.info(
                    f"Authenticating ({'re' if is_logged_in else 'first'}) device '{session.mac_address}': eap-md5 challenge ok"
                )

                await session.login()

                TRACER.info(
                    msg=f"Authenticating ({'re' if is_logged_in else 'first'}) device '{session.mac_address}': success ({session.authentication_counter})"
                )

                await self._send_eap_success(
                    port=port,
                    dst_mac_address=session.mac_address,
                    eap_id=eap_id,  # TODO check eap id handling
                )

                # Start relogin task
                asyncio.get_event_loop().create_task(
                    self._handle_relogin_interval(session)
                )
            else:
                TRACER.info(
                    msg=f"Authenticating ({'re' if session.is_logged_in else 'first'}) device '{session.mac_address}': failure"
                )
                raise EAPAuthenticationError("Authentication failed.")
        else:
            raise EAPAuthenticationError("Wrong authentication procedure.")

    ######## One Time Password Challenge ########

    async def _handle_eap_request_otp(
        self,
        port: int,
        eap_id: int,
        session: AuthSession,
    ):
        if not isinstance(session.challenge, AuthOTPChallenge):
            raise EAPAuthenticationError("Wrong authentication procedure.")

        TRACER.info(
            msg=f"Authenticating ({'re' if session.is_logged_in else 'first'}) device '{session.mac_address}': eap-otp challenge"
        )

        id = session.get_id()

        # Generate challenges
        if session.challenge.otp_read_index < 0 or session.challenge.slot_pos is None:
            session.challenge.otp_read_index = self._otp_storing_factor - 1
            session.challenge.otp_write_index = self._otp_storing_factor - 1
            await session.challenge.prepare()

            self._otp_seed_register.set(
                id, bytearray(session.challenge.seed.encode("utf-8"))
            )

            # Reserve OTP slot
            if session.challenge.slot_pos is None:
                try:
                    session.challenge.slot_pos = self._otp_mapping.index(False)
                except ValueError:
                    raise EAPError("Missing OTP slots.")

                self._otp_mapping[session.challenge.slot_pos] = True

            # Start otp challenge fill task
            asyncio.get_event_loop().create_task(self._fill_otp_challenges(session))

        # Set status if already authenticated
        if session.challenge.status == AuthOTPStatus.AUTHENTICATED:
            session.challenge.status = AuthOTPStatus.REAUTHENTICATION_PENDING

        # Calculate OTP position
        start_pos = session.challenge.slot_pos * self._otp_per_auth * self._otp_storing_factor
        # Last sequence id of the current read index
        #    ([ ][ ][ ][ ]) ([ ][ ][ ][ ]) ([ ][ ][ ][ ])
        #  otp_read_index --^          ^-- otp_offset
        otp_offset = (session.challenge.otp_read_index + 1) * self._otp_per_auth - 1

        # Write challenge to data plane
        if not session.challenge.ready[session.challenge.otp_read_index]:
            self._write_otp_challenge(session)

        algo: str = ""
        if session.challenge.algo == AuthOTPAlgo.MD5:
            algo = "md5"
            self._otp_kdf_type_register.set(id, 1)
        elif session.challenge.algo == AuthOTPAlgo.SHA1:
            algo = "sha1"
            self._otp_kdf_type_register.set(id, 2)
        elif session.challenge.algo == AuthOTPAlgo.SHA2:
            algo = "sha2"
            self._otp_kdf_type_register.set(id, 3)
        elif session.challenge.algo == AuthOTPAlgo.SHA3:
            algo = "sha3"
            self._otp_kdf_type_register.set(id, 4)
        else:
            self._otp_kdf_type_register.set(id, 0)

        self._otp_position_register.set(
            id,
            start_pos + otp_offset,
        )
        self._otp_remaining_steps_register.set(
            id,
            self._otp_per_auth,
        )

        session.challenge.otp_read_index -= 1

        await self._send_eap_packet(
            port=port,
            dst_mac_address=session.mac_address,
            eap_packet=EAP_MD5(
                type=EAPType.OTP,
                id=eap_id,  # TODO check eap id handling
                value=(
                    "otp-"
                    + algo.ljust(4, " ")
                    + " "
                    + str(otp_offset + 1).rjust(4, " ")
                    + " "
                    + session.challenge.seed
                    + " "
                ).encode("utf-8"),
            ),
        )

    async def _fill_otp_challenges(self, session: AuthSession):
        @types.coroutine
        def _yield():
            """Yield processing back to asyncio loop"""
            yield

        if isinstance(session.challenge, AuthOTPChallenge):
            seed = session.challenge.seed
            while (
                session.is_logged_in or session.last_login == 0
            ) and seed == session.challenge.seed:
                if not self._write_otp_challenge(session):
                    break
                # We yield processing back to asyncio to allow for further processing
                await _yield()

    def _write_otp_challenge(self, session: AuthSession) -> bool:
        """Write OTP challenge to data plane"""
        if (
            isinstance(session.challenge, AuthOTPChallenge)
            and session.challenge.slot_pos is not None
        ):
            # Check write index for out of bound
            if not (session.challenge.otp_write_index >= 0):
                return False

            sequence_id_values = []
            first_values = []
            second_values = []

            start_pos = session.challenge.slot_pos * self._otp_per_auth * self._otp_storing_factor
            otp_offset = session.challenge.otp_write_index * self._otp_per_auth
            for index in range(self._otp_per_auth):
                position = start_pos + otp_offset + index

                next_sequence_id = otp_offset + index
                sequence_id_values.append(
                    (
                        position,
                        bytearray(bytes(str(next_sequence_id).rjust(4, " "), "utf-8")),
                    )
                )

                otp = session.challenge.challenges[otp_offset + index]
                first_values.append((position, bytearray(otp[:4])))
                second_values.append((position, bytearray(otp[4:])))

            self._otp_sequence_id_register.set_multiple(sequence_id_values)
            self._otp_first_register.set_multiple(first_values)
            self._otp_second_register.set_multiple(second_values)

            session.challenge.ready[session.challenge.otp_write_index] = True
            session.challenge.otp_write_index -= 1

            return True
        else:
            return False

    async def _handle_eap_response_otp(
        self,
        port: int,
        eap_id: int,
        eap_value: bytes,
        session: AuthSession,
    ):
        logging.info("EAP OTP response from '%s'.", session.mac_address)

        if isinstance(session.challenge, AuthOTPChallenge):
            if len(eap_value) >= 9 and all(a == 0 for a in eap_value[1:9]):
                logging.info(
                    "EAP-OTP authentication of '%s' succeeded.", session.mac_address
                )

                is_logged_in = session.is_logged_in
                TRACER.info(
                    f"Authenticating ({'re' if is_logged_in else 'first'}) device '{session.mac_address}': eap-otp challenge ok"
                )

                await session.login()

                TRACER.info(
                    f"Authenticating ({'re' if is_logged_in else 'first'}) device '{session.mac_address}': success ({session.authentication_counter})"
                )

                await self._send_eap_success(
                    port=port,
                    dst_mac_address=session.mac_address,
                    eap_id=eap_id,  # TODO check eap id handling
                )

                # Start relogin task
                asyncio.get_event_loop().create_task(
                    self._handle_relogin_interval(session)
                )
            else:
                TRACER.info(
                    f"Authenticating ({'re' if session.is_logged_in else 'first'}) device '{session.mac_address}': failure ({session.authentication_counter})"
                )
                raise EAPAuthenticationError("Authentication failed.")
        else:
            raise EAPAuthenticationError("Wrong authentication procedure.")
