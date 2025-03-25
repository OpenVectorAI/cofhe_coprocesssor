from __future__ import absolute_import

import asyncio

from openvector_cofhe_coprocessor_backend.cli import parse_args
from openvector_cofhe_coprocessor_backend.app import App

def main():
    args = parse_args()
    app = App(args)
    asyncio.run(app.run())

if __name__ == "__main__":
    main()