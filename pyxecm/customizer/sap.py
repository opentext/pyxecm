"""
SAP RFC Module to implement Remote Function calls to SAP S/4HANA
For documentation of PyRFC see here: https://github.com/SAP/PyRFC
and here: https://sap.github.io/PyRFC/pyrfc.html 

RFC typically uses port 3300 to communication with the SAP server.
Make sure this port is not blocked by your firewall.

Connection Parameter:
* ashost (hostname or IP address of the application server - this should NOT be a full URL!)
* sysnr (the backend's system number, e.g. 00)
* client (the client or "Mandant" to which to logon, e.g. 100)
* user (e.g. "nwheeler")
* passwd (password of the user)
* lang (logon language as two-character ISO-Code, e.g. EN)
* trace (on of 0(off), 1(brief), 2(verbose), 3(detailed), 4(full))
* use_tls (activates SSL/TLS encryption. Set to 0 or 1. By default TLS is turned on (1))
* tls_client_pse (Specifies the PSE file containing the necessary certificates for TLS communication.
                  A PSE file is a SAP proprietary certificate store, similar to a p12 file,
                  containing the private key and the certificate chain to be used in the TLS
                  handshake with the server, beginning with the server's public certificate and
                  ending with the root CA certifcate. It should also contain the client certificate
                  used for login at the server, if your client program does not use basic
                  user & password authentication)

Class: SAP
Methods:

__init__ : class initializer
call: Calls and RFC based on its name and passes parameters.

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging

logger = logging.getLogger("pyxecm.customizer.sap")

try:
    import pyrfc

    _has_pyrfc = True

except ModuleNotFoundError as module_exception:
    logger.error("pyrfc not installed, SAP integration impacted")
    _has_pyrfc = False

except ImportError as import_exception:
    logger.error("pyrfc could not be loaded, SAP integration impacted")
    _has_pyrfc = False


class SAP(object):
    """Used to implement Remote Function Calls (RFC) to SAP S/4HANA"""

    _connection_parameters = {}

    def __init__(
        self,
        username: str,
        password: str,
        system_id: str,
        ashost: str = "",
        mshost: str = "",
        msport: str = "3601",
        group: str = "PUBLIC",
        destination: str = "",
        client: str = "100",
        system_number: str = "00",
        lang: str = "EN",
        trace: str = "3",
    ):
        """Initialize the SAP object."""

        logger.info("Initializing SAP object...")
        logger.info("Using PyRFC version -> %s", pyrfc.__version__)

        # Set up connection parameters
        self._connection_parameters = {
            "user": username,
            "passwd": password,
            "client": client,
            "trace": trace,
            "lang": lang,
        }

        # see https://sap.github.io/PyRFC/pyrfc.html#connection
        if ashost:
            logger.info("Logon with application server logon: requiring ashost, sysnr")
            self._connection_parameters["ashost"] = ashost
            self._connection_parameters["sysnr"] = system_number
            self._connection_parameters["sysid"] = system_id
        elif mshost:
            logger.info(
                "Logon with load balancing: requiring mshost, msserv, sysid, group"
            )
            self._connection_parameters["mshost"] = mshost
            self._connection_parameters["sysid"] = system_id
            self._connection_parameters["msserv"] = msport
            self._connection_parameters["group"] = group

        if destination:
            self._connection_parameters["dest"] = destination

        # end method definition

    def call(self, rfc_name: str, options: dict, rfc_parameters: dict) -> dict | None:
        """Do an RFC Call. See http://sap.github.io/PyRFC/pyrfc.html#pyrfc.Connection.call

        Args:
            rfc_name (str): this is the name of the RFC (typical in capital letters), e.g. SM02_ADD_MESSAGE
            options (dictionary, optional): the call options for the RFC call. Defaults to {}.
            * not_requested: Allows to deactivate certain parameters in the function module interface.
              This is particularly useful for BAPIs which have many large tables, the Python client is not interested in.
              Deactivate those, to reduce network traffic and memory consumption in your application considerably.
              This functionality can be used for input and output parameters. If the parameter is an input,
              no data for that parameter will be sent to the backend. If it’s an output, the backend will be
              informed not to return data for that parameter.
            * timeout: Cancel RFC connection if ongoing RFC call not completed within timeout seconds.
              Timeout can be also set as client connection configuration option, in which case is valid for all RFC calls.
            rfc_parameters (dict, optional): the actual RFC parameters thatare specific for
                                                   the type of the call. Defaults to {}.
        Returns:
            dict: Result of the RFC call or None if the call fails or timeouts.
        """

        # Create the connection object and call the RFC function
        params = self._connection_parameters
        logger.debug("Connection Parameters -> %s", params)

        try:
            with pyrfc.Connection(**params) as conn:
                result = conn.call(rfc_name, options=options, **rfc_parameters)
                return result
        except pyrfc.RFCError as exception:
            logger.error("Failed to call RFC -> %s; error -> %s", rfc_name, exception)
            return None

        # end method definition
