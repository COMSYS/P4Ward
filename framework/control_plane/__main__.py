"""Control Plane Main"""

from pydantic import ValidationError
import yaml
import json
import logging
import argparse

from framework.control_plane.config.protocol import ProtocolConfig
import framework.control_plane.tracing
from framework.control_plane.config.switch import SwitchConfig
from framework.control_plane.config.preload import PreloadConfig
from framework.control_plane.switch import Switch


def exec_help(_args):
    global parser
    parser.print_help()


def exec_config_save(args):
    if not isinstance(args.config, str):
        args.config = "config.yaml"

    switch_config = SwitchConfig()

    try:
        config_file = open(file=args.config, mode="w", encoding="UTF-8")
        config_file.write(
            yaml.safe_dump(switch_config.model_dump(exclude_none=True), indent=4)
        )
        config_file.close()
    except OSError as error:
        print(f"Failed to save config file.\n{error}")
    except Exception as error:
        print(f"Failed to dump config file.\n{error}")

    if isinstance(args.preload, str):
        preload_config = PreloadConfig()

        try:
            config_file = open(file=args.preload, mode="w", encoding="UTF-8")
            config_file.write(
                yaml.safe_dump(preload_config.model_dump(exclude_none=True), indent=4)
            )
            config_file.close()
        except OSError as error:
            print(f"Failed to save preloads config file.\n{error}")
        except Exception as error:
            print(f"Failed to dump preloads config file.\n{error}")


def exec_config_schema(_args):
    print(json.dumps(SwitchConfig.model_json_schema(), indent=4))

def exec_config_preload_schema(_args):
    print(json.dumps(PreloadConfig.model_json_schema(), indent=4))


def exec_run(args):
    preload_config: PreloadConfig
    if isinstance(args.preload, str):
        try:
            file = open(file=args.preload, mode="r", encoding="UTF-8")
            preload_config = PreloadConfig.model_validate(yaml.safe_load(file))
            file.close()
        except OSError as error:
            print(f"Failed to load preload config file.\n{error}")
            exit(-1)
        except Exception as error:
            print(f"Failed to parse preload config file.\n{error}")
            exit(-1)
    else:
        preload_config = PreloadConfig()

    switch_config: SwitchConfig
    if isinstance(args.config, str):
        try:
            file = open(file=args.config, mode="r", encoding="UTF-8")
            switch_config = SwitchConfig.model_validate(yaml.safe_load(file))
            file.close()
        except OSError as error:
            print(f"Failed to load config file.\n{error}")
            exit(-1)
        except Exception as error:
            print(f"Failed to parse config file.\n{error}")
            exit(-1)
    else:
        switch_config = SwitchConfig()

    protocol_config: ProtocolConfig
    if isinstance(args.protocol, str):
        try:
            file = open(file=args.protocol, mode="r", encoding="UTF-8")
            protocol_config = ProtocolConfig.model_validate(yaml.safe_load(file))
            file.close()
        except OSError as error:
            print(f"Failed to load protocol config file.\n{error}")
            exit(-1)
        except Exception as error:
            print(f"Failed to parse protocol config file.\n{error}")
            exit(-1)
    else:
        protocol_config = ProtocolConfig()

    if args.gen_configure:
        configure = ""

        configure += f'print(f"Configure Tofino Switch")\n'
        configure += f"\n"

        # Set CPU port
        configure += f"#### Set Copy to CPU port ####\n"
        configure += f'print("-> Set copy to CPU port")\n'
        configure += f"tm.set_cpuport(192)\n"
        configure += f"\n"

        # Reset multicast
        configure += f"#### Reset multicast ####\n"
        configure += f'print("-> Reset multicast groups")\n'
        configure += f"\n"
        configure += f"for i in range(mc.mgrp_get_count()):\n"
        configure += f"    mc.mgrp_destroy(mc.mgrp_get_first())\n"
        configure += f"for i in range(mc.node_get_count()):\n"
        configure += f"    mc.node_destroy(mc.node_get_first())\n"
        configure += f"\n"

        # Set multicast
        configure += f"#### Set multicast ####\n"
        configure += f'print("-> Set multicast groups")\n'
        configure += f"\n"
        configure += f"# Workaround broken devports_to_mcbitmap function\n"
        configure += f"def devports_to_mcbitmap_fixed(devport_list):\n"
        configure += f'    """\n'
        configure += (
            f"    Convert a list of devports into a Tofino-specific MC bitmap\n"
        )
        configure += f'    """\n'
        configure += f"    bit_map = [0] * int((288 + 7) / 8)\n"
        configure += f"    for dp in devport_list:\n"
        configure += f"        mc_port = devport_to_mcport(dp)\n"
        configure += f"        bit_map[int(mc_port / 8)] |= int(1 << (mc_port % 8))\n"
        configure += f"    return bytes_to_string(bit_map)\n"
        configure += f"\n"
        configure += f"# Workaround broken lags_to_mcbitmap function\n"
        configure += f"def lags_to_mcbitmap_fixed(lag_list):\n"
        configure += f'    """\n'
        configure += f"    Convert a list of LAG indices to a MC bitmap\n"
        configure += f'    """\n'
        configure += f"    bit_map = [0] * int((256 + 7) / 8)\n"
        configure += f"    for lag in lag_list:\n"
        configure += f"        bit_map[int(lag / 8)] |= int(1 << (lag % 8))\n"
        configure += f"    return bytes_to_string(bit_map)\n"
        configure += f"\n"

        index = 0
        ports: set[int] = set()
        for network in switch_config.networks.networks:
            index += 1
            if network.name is None:
                configure += f'print(" Multicast Group {index}")\n'
            else:
                configure += f'print(" Multicast Group {index} ({network.name})")\n'
            configure += f"mgrp = mc.mgrp_create({index})\n"
            configure += f'mgrp_node_1 = mc.node_create(1, devports_to_mcbitmap_fixed([{", ".join(str(a) for a in network.ports)}]), lags_to_mcbitmap_fixed([]))\n'
            configure += (
                f"mc.associate_node(mgrp, mgrp_node_1, xid=0, xid_valid=False)\n"
            )
            configure += f"\n"

            ports.update(network.ports)

        configure += f'print(" Multicast Layer 2 pruning")\n'
        for port in ports:
            configure += f"mc.update_port_prune_table({port}, devports_to_mcbitmap_fixed([{port}]))\n"
        configure += f"\n"

        # Complete operations
        configure += "mc.complete_operations()\n"

        try:
            configure_file = open(file="configure.g.py", mode="w", encoding="UTF-8")
            configure_file.write(configure)
            configure_file.close()
        except OSError as error:
            print(f"Failed to save configure file.\n{error}")

        return

    switch = Switch(switch_config, preload_config, protocol_config)
    switch.run()


def main():
    # Initialize logger
    logging.basicConfig(filename="switch.log", filemode="w", level=logging.DEBUG)
    logging.info("Starting switch")

    framework.control_plane.tracing.TRACER.info("Start Tracing")

    # Initialize parser
    global parser
    parser = argparse.ArgumentParser(usage="<command> <args>", add_help=True)
    subparsers = parser.add_subparsers(
        title="Control Plane", dest="CP", help="ACL Framework CP"
    )

    # Help command
    parser_help = subparsers.add_parser("help", help="Print help")
    parser_help.set_defaults(func=exec_help)

    # Config commands
    config_parser = subparsers.add_parser("config", help="Config management tools")
    config_subparsers = config_parser.add_subparsers(
        title="Config management tools", dest="config", help="Config management tools"
    )

    # Config save command
    parser_config_save = config_subparsers.add_parser("save", help="Save config to file")
    parser_config_save.add_argument("--config", help="Config file path")
    parser_config_save.add_argument("--preload", help="Preload config file path")
    parser_config_save.set_defaults(func=exec_config_save)

    # Config schema command
    parser_config_schema = config_subparsers.add_parser("schema", help="Print config schema")
    parser_config_schema.set_defaults(func=exec_config_schema)

    # Config preload schema command
    parser_config_preload_schema = config_subparsers.add_parser("preload-schema", help="Print preload config schema")
    parser_config_preload_schema.set_defaults(func=exec_config_preload_schema)

    # Run command
    parser_run = subparsers.add_parser("run", help="Run control plane")
    parser_run.add_argument(
        "--gen-configure", action="store_true", help="Generate configure script"
    )
    parser_run.add_argument("--config", help="Config file path")
    parser_run.add_argument("--preload", help="Preload config file path")
    parser_run.add_argument("--protocol", help="Protocol config file path")
    parser_run.set_defaults(func=exec_run)

    # Run parser
    result = parser.parse_args()
    if hasattr(result, "func"):
        result.func(result)


if __name__ == "__main__":
    main()
