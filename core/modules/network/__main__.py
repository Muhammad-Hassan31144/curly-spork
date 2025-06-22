#!/usr/bin/env python3
"""
shikra/core/modules/network/__main__.py
Entry point for running network module as a module

This allows: python -m core.modules.network
"""

import sys
from . import main

if __name__ == "__main__":
    sys.exit(main())