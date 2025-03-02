#!/usr/bin/env python3
# Run the right version of monero.bt depending on linux headers
# https://github.com/cryptnono/cryptnono/pull/38

import platform
from os import execl
from pathlib import Path

# Check for the presence of a linux header only present on older kernels e.g.
# /usr/src/kernels/5.10.225-213.878.amzn2.x86_64/arch/x86/include/asm/fpu/internal.h
# Note it's not enough to check for the presence of a newer header (api.h)
machine = platform.machine()
if machine == "x86_64":
    fpu_internal = list(Path("/").glob("usr/src/*/arch/x86/include/asm/fpu/internal.h"))
else:
    raise NotImplementedError(f"Architecture {machine} not supported")
if len(fpu_internal):
    v = "v1"
else:
    v = "v2"

script = f"/scripts/monero-{v}.bt"
print(f"Running {script}")
execl(script, script)
