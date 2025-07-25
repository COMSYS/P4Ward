# P4Ward prototype implementation

## Description 

This repository contains the code of our P4Ward prototype.

This project aims to tackle the problems of network security in industrial networks by implementing a framework capable of introducing security measures, such as device authentication and access control while keeping the requirements of Industrial Control Systems (ICS) in mind and maintaining compatibility with legacy hardware. Our implementation targets the Intel Tofino hardware and is implemented using the P4 language on the data plane and Python on the control plane. To deploy security systems, we employ and adapt the MUD standard (IETF RFC 8520).

If you use any portion of our work, please cite our paper:

```bibtex
@inproceedings{2025_fink_p4ward,
    author = {Fink, Ina Berenice and Koehler, William and Serror, Martin and Wehrle, Klaus},
    title = {{P4Ward: Fine-Grained Behavioral Policy Enforcement for Industrial Networks}},
    booktitle = {Proceedings of the 50th IEEE Conference on Local Computer Networks (LCN '25), Oct 14-16, 2025, Sydney, Australia},
    year = {2025},
    publisher = {IEEE},
}
```

## Repository Overview

This repository contains different parts of the system, mainly the framework, the authentication server, and the authentication client.

- `mud-files`: Test MUD files that partly comprise extensions to support OPC UA and Modbus
- `framework`: Router Framework
    - `control_plane`: Control Plane 
    - `data_plane`: Data Plane
- `authentication_server`: Authentication Server
- `proto`: Google Protobuf definition for the communication between the router and the authentication server
- `authentication_client`: Authentication Client (written in C)
- `authentication_client_py`: Authentication Client (written in Python)

# Dependencies

- make
- python (v3.8) and pip3 (look at `DEPENDENCIES.md`)
- gRPC Tooling
- clang

# Build

Build the data plane using `make build`

**📓 Note**: If needed the location of the compilation, activation, and configuration scripts are defined using variables at the top the the `Makefile` and can easily be changed there.

# Run

**❗ Important**: Before running the framework, 1. several dependencies have to be downloaded (using pip3) and 2. protobuf files have to be compiled:
1. Look at `DEPENDENCIES.md` for a complete list of the dependencies. 
2. The script `./proto/gen.sh` uses the gRPC Tools to generate the necessary Python code based on the protobuf files `proto/*.proto`.

Before starting the control plane we have to create and update the control plane's configuration file. For this we use the command: `./py_framework save --config config.yaml`.

For more details about the format of the configuration file, you are welcome to read the code in `framework/control_plane/config/configs` or use the command `./py_framework schema`.

After customizing the configuration file the data plane can be activated using the command: `make activate` which takes the `config.yaml` and uses it to activate and configure the data plane (Copy-to-CPU port and multicasting)

If you don't want to scramble around with the configuration file you can also use the following sample configuration file:
```yaml
data-plane:
  push: 0.0.0.0:50052
  pull: ens1
networks:
  networks:
    - name: network 1
      mac: 00:00:00:00:a0:01
      ipv4-interface: 10.0.0.100/24
      ports: [ 140, 141 ]
mud:
  use-remote: False
  origin: "mud_profiles"
auth:
  use-remote: False
```

Now that the data plane has been deployed, the control plane can now be started. The helper script `py_framework` is used to execute the control plane more easily: `./py_framework run --config config.yaml`.

# Play around

When the control plane is running a simple CLI interface enables the management of every part of the router. For help on how to use the CLI interface, run the command: `help`.

**📓 Note**: All changes made when the framework is running are not saved and disappear after the framework is restarted.