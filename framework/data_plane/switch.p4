#ifndef __SWITCH__
#define __SWITCH__

#include "ingress.p4"
#include "egress.p4"

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;

#endif