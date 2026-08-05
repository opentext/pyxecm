"""pyxecm - A python library to interact with Opentext REST APIs."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

from .avts import AVTS
from .coreshare import CoreShare
from .otac import OTAC
from .otawp import OTAWP
from .otca import OTCA
from .otcs import OTCS
from .otds import OTDS
from .otiv import OTIV
from .otkd import OTKD
from .otmm import OTMM
from .otpd import OTPD

__all__ = ["AVTS", "OTAC", "OTAWP", "OTCA", "OTCS", "OTDS", "OTIV", "OTKD", "OTMM", "OTPD", "CoreShare"]
