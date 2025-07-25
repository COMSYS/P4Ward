"""Little helper class that enables CSV tracing"""

import logging

TRACER: logging.Logger = logging.getLogger("tracer")
handler = logging.FileHandler("switch-tracing.log", mode="w")
handler.stream.write(f'{"Time (ms)".ljust(10)}: Message\n')
handler.setFormatter(logging.Formatter('%(relativeCreated)-10d: %(message)s'))
TRACER.addHandler(handler)