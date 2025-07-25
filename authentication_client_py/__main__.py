"""Control Plane Main"""

from __future__ import annotations
import json
import logging
import argparse
import socket
from authentication_client_py.scapy_ext import *
from macaddress import EUI48
from scapy.packet import Padding
from scapy.layers.l2 import Ether
from scapy.layers.eap import EAPOL, EAP, EAP_MD5
import hashlib
import os
import time


sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

hashchains: dict[str, list[bytes]] = {}

src_mac_address: EUI48 = EUI48(os.urandom(6))
dst_mac_address: EUI48 = EUI48(os.urandom(6))
name: str = "admin"
password: str = "admin"


def exec_help(_args):
    global parser
    parser.print_help()


def send_start_request():
    logging.info("Start autentication")

    packet = Ether(
        dst=bytes(dst_mac_address),
        src=bytes(src_mac_address),
        type=EtherType.EAPoL,
    ) / EAPOL(
        type=EAPoLType.START,
    )

    sock.send(bytes(packet))


def send_identity_response(ether_packet: Ether, eap_id: int):
    packet = (
        Ether(
            dst=bytes(dst_mac_address),
            src=bytes(src_mac_address),
            type=EtherType.EAPoL,
        )
        / EAPOL(
            type=EAPoLType.EAP_PACKET,
        )
        / EAP(
            code=EAPCode.RESPONSE,
            id=eap_id,
            type=EAPType.IDENTITY,
            identity=name,
        )
    )

    sock.send(bytes(packet))


def send_md5_response(ether_packet: Ether, eap_id: int, eap_value: bytes):
    answer = hashlib.md5((name + password).encode("utf-8") + eap_value).digest()

    packet = (
        Ether(
            dst=bytes(dst_mac_address),
            src=bytes(src_mac_address),
            type=EtherType.EAPoL,
        )
        / EAPOL(
            type=EAPoLType.EAP_PACKET,
        )
        / EAP_MD5(
            code=EAPCode.RESPONSE,
            id=eap_id,
            type=EAPType.MD5,
            value=answer,
        )
    )

    sock.send(bytes(packet))


def hash_step(algo = None, value: bytes = bytes()) -> bytes:
    if algo == "otp-md5":
        value = hashlib.md5(value).digest()
        return bytes([_a ^ _b for _a, _b in zip(value[0:8], value[8:16])])
    elif algo == "otp-sha1":
        value = hashlib.sha1(value).digest()
        return bytes([_a ^ _b ^ _c for _a, _b, _c in zip(value[0:8], value[8:16], value[16:20] + bytes([ 0x00, 0x00, 0x00, 0x00 ]))])
    else:
        return bytes([ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])

def get_otp_answer(algo: str, sequence_id: int, seed: str) -> bytes:
    global hashchains, password

    hashchain = hashchains.get(seed)
    if hashchain is None:
        hashchain = hashchains[seed] = []
    
    if sequence_id <= 0:
        return hash_step()
    
    if sequence_id <= len(hashchain) :
        return hashchain[sequence_id-1]

    if len(hashchain) == 0:
        hashchain.append(hash_step(algo, (password + seed).encode('utf-8')))
    
    start_index = len(hashchain)
    end_index = max(start_index + 200, sequence_id)
    for i in range(start_index, end_index):
        hashchain.append(hash_step(algo, hashchain[-1]))
    
    return hashchain[sequence_id-1]

def send_otp_response(ether_packet: Ether, eap_id: int, eap_value: bytes):
    parts: list[str] = list(filter(None, eap_value.decode("ascii").split(" ")))
    algo = parts[0]
    sequence_id = int(parts[1])
    seed = parts[2]

    answer = get_otp_answer(algo, sequence_id, seed)

    packet = (
        Ether(
            dst=bytes(dst_mac_address),
            src=bytes(src_mac_address),
            type=EtherType.EAPoL,
        )
        / EAPOL(
            type=EAPoLType.EAP_PACKET,
        )
        / EAP_MD5(
            code=EAPCode.RESPONSE,
            id=eap_id,
            type=EAPType.OTP,
            value=answer + (str(sequence_id).rjust(4, ' ') + " " + seed + " ").encode("utf-8"),
        )
    )

    sock.send(bytes(packet))


def exec_run(args):
    global parser, src_mac_address, dst_mac_address, name, password

    interface: str
    if args.interface is not None:
        interface = args.interface
    else:
        parser.error("missing network interface")

    if args.src is not None:
        src_mac_address = args.src

    if args.dst is not None:
        dst_mac_address = args.dst

    if args.name is not None:
        name = args.name

    if args.password is not None:
        password = args.password

    sock.bind((interface, 0))

    send_start_request()

    while True:
        packet_raw = sock.recvfrom(4096)
        ether_packet = Ether(packet_raw[0])
        if ether_packet.haslayer(EAPOL):
            eapol_packet: EAPOL = ether_packet[EAPOL]

            if eapol_packet.type == EAPoLType.EAP_PACKET:  # EAP-Packet
                eap_packet: EAP = eapol_packet[EAP]

                if eap_packet.code == EAPCode.REQUEST:
                    if eap_packet.type == EAPType.IDENTITY:
                        send_identity_response(ether_packet, eap_packet.id)
                    elif eap_packet.type == EAPType.MD5:
                        logging.info("Send MD5 challenge")
                        send_md5_response(ether_packet, eap_packet.id, bytes(eapol_packet[EAP_MD5].value))
                    elif eap_packet.type == EAPType.OTP:
                        logging.info("Send OTP challenge")
                        send_otp_response(ether_packet, eap_packet.id, bytes(eapol_packet[Padding].load)[1:])
                elif eap_packet.code == EAPCode.SUCCESS:
                    logging.info("Authentication succeeded.")
                    if args.disable_reauth:
                        break
                elif eap_packet.code == EAPCode.FAILURE:
                    logging.error("Authentication failed.")
                    time.sleep(5)
                    send_start_request()
        elif ether_packet.type == EtherType.ROUTER_HELLO:
            send_start_request()


if __name__ == "__main__":
    # Initialize logger
    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
    logging.info("Starting authentication script")

    # Initialize parser
    parser = argparse.ArgumentParser(usage="<command> <args>", add_help=True)
    subparsers = parser.add_subparsers(
        title="Authentication", dest="Auth", help="Authentication Script"
    )

    # Help command
    parser_help = subparsers.add_parser("help", help="Print help")
    parser_help.set_defaults(func=exec_help)

    # Run command
    parser_run = subparsers.add_parser("run", help="Run control plane")
    parser_run.add_argument("--interface", type=str, help="Network Interface")
    parser_run.add_argument("--src", type=EUI48, help="Source mac address")
    parser_run.add_argument("--dst", type=EUI48, help="Destination mac address")
    parser_run.add_argument("--name", type=str, help="User name")
    parser_run.add_argument("--password", type=str, help="User password")
    parser_run.add_argument(
        "--disable-reauth",
        action="store_true",
        help="Disable automatic reauthentication",
    )
    parser_run.set_defaults(func=exec_run)

    # Run parser
    result = parser.parse_args()
    if hasattr(result, "func"):
        result.func(result)
