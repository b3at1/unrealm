"""
unrealm – Realm C2 framework detector and response agent.

Run as a module:
    python -m unrealm [OPTIONS]
"""
from unrealm.cli import main

if __name__ == "__main__":
    import sys
    sys.exit(main())
