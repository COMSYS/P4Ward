"""AA Server Main"""

import yaml
import logging
import argparse

from authentication_server.config.server import ServerConfig
from authentication_server.server import Server


def exec_help(_args):
    global parser
    parser.print_help()


def exec_config_save(args):
    if not isinstance(args.config, str):
        args.config = "authentication-config.yaml"

    switch_config = ServerConfig()

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


def exec_run(args) -> None:
    server_config: ServerConfig
    if isinstance(args.config, str):
        try:
            file = open(file=args.config, mode="r", encoding="UTF-8")
            server_config = ServerConfig.model_validate(yaml.safe_load(file))
            file.close()
        except OSError as error:
            print(f"Failed to load config file.\n{error}")
            exit(-1)
        except Exception as error:
            print(f"Failed to parse config file.\n{error}")
            exit(-1)
    else:
        server_config = ServerConfig()

    switch = Server(server_config)
    switch.run()


if __name__ == "__main__":
    # Initialize logger
    logging.basicConfig(level=logging.DEBUG)
    logging.info("Starting server")

    # Initialize parser
    parser = argparse.ArgumentParser(usage="<command> <args>", add_help=True)
    subparsers = parser.add_subparsers(
        title="AA server", dest="AA", help="Authentication and authorization server"
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
    parser_enable = config_subparsers.add_parser("save", help="Save config to file")
    parser_enable.add_argument("--defaults", action="store_true", help="Load defaults")
    parser_enable.set_defaults(func=exec_config_save)

    # Run command
    parser_run = subparsers.add_parser("run", help="Run control plane")
    parser_run.add_argument("--config", help="Config file path")
    parser_run.set_defaults(func=exec_run)

    # Run parser
    result = parser.parse_args()
    if hasattr(result, "func"):
        result.func(result)
