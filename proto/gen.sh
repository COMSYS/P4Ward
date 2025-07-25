#!/usr/bin/env bash

#--pyi_out=$(pwd)../control_plane/controllers/auth/proto/
python3.8 -m grpc_tools.protoc -I=./ \
    --python_out=. \
    --grpc_python_out=. \
    ./proto/authentication_access.proto