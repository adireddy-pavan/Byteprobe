"""ByteProbe entry point."""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from gui.app import ByteProbeApp


def main():
    app = ByteProbeApp()
    app.run()


if __name__ == '__main__':
    main()
