"""`python -m triage_lens` で実行するためのエントリポイント。"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
