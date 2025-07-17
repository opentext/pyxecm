"""Start the Customizer to process a payload."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import os
import sys

from .customizer import Customizer
from .payload import load_payload

logger = logging.getLogger("customizer")


def main() -> int:
    """Start the Customizer."""

    logging.basicConfig(
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%d-%b-%Y %H:%M:%S",
        level=logging.INFO,
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )

    if len(sys.argv) < 2:
        logger.error("No input file specified")
        sys.exit(1)

    payload_filename = sys.argv[1]

    if not os.path.isfile(payload_filename):
        logger.error("Input file does not exist")
        sys.exit(1)

    payload = load_payload(payload_filename)
    customizer_settings = payload.get("customizerSettings", {})

    # Overwrite the customizer settings with the payload specific ones:
    customizer_settings.update({"cust_payload": payload_filename})

    my_customizer = Customizer(logger=logger, settings=customizer_settings)

    try:
        my_customizer.customization_run()
    except KeyboardInterrupt:
        logger.warning("KeyboardInterrupt - exiting")
