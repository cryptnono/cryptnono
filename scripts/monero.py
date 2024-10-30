#!/usr/bin/env python3
# Run the right version of monero.bt depending on linux headers
# https://github.com/cryptnono/cryptnono/pull/38

from pathlib import Path
from os import execl

# Check for the presence of a linux header only present on newer kernels e.g.
# /usr/src/linux-generic-6.1.30-0-virt/arch/x86/include/asm/fpu/api.h
fpu_api = list(Path("/").glob("usr/src/*/arch/*/include/asm/fpu/api.h"))
if len(fpu_api):
    v = "v2"
else:
    v = "v1"

script = f"/scripts/monero-{v}.bt"
print(f"Running {script}")
execl(script, script)
