"""Assoc Module to implement functions to read / write from so called "Assoc" data structures in Content Server.

Right now this module is used to tweak settings in XML-based transport packages that include
Assoc structures inside some of the XML elements.
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import html
import re


class Assoc:
    """Class Assoc is used to handle Extended ECM Assoc data structures."""

    @classmethod
    def is_unicode_escaped(cls, assoc_string: str) -> bool:
        """Determine if a string is unicode escaped.

        Args:
            assoc_string (str): string with the Assoc data

        Returns:
            bool: True if string is in Unicode, False otherwise

        """

        pattern = r"\\u[0-9a-fA-F]{4}"
        matches = re.findall(pattern, assoc_string)

        return len(matches) > 0

    # end method definition

    @classmethod
    def escape_unicode(cls, assoc_string: str) -> str:
        """Escape / Encode a given string in Unicode.

        Args:
            assoc_string (str):
                The source string to escape.

        Returns:
            str:
                The escaped string.

        """

        encoded_string = assoc_string.encode("unicode_escape")  # .decode()

        return encoded_string

    # end method definition

    @classmethod
    def unescape_unicode(cls, assoc_string: str) -> str:
        """Unescape / Decode a given string.

        Args:
            assoc_string (str):
                The source string to unescape.

        Returns:
            str:
                The unescaped string.

        """
        try:
            decoded_string = bytes(assoc_string, "utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            return assoc_string

        return decoded_string

    # end method definition

    @classmethod
    def is_html_escaped(cls, assoc_string: str) -> bool:
        """Check if an Assoc String is HTML escaped.

        Args:
            assoc_string (str):
                The string to test for HTML escaping.

        Returns:
            bool:
                True = string is HTML escaped, False if now

        """

        decoded_string = html.unescape(assoc_string)

        return assoc_string != decoded_string

    # end method definition

    @classmethod
    def unescape_html(cls, assoc_string: str) -> str:
        """HTML unescape a a string.

        Args:
            assoc_string (str): the string to unescape.

        Returns:
            str: unescaped string

        """

        decoded_string = html.unescape(assoc_string)
        return decoded_string

    # end method definition

    @classmethod
    def string_to_dict(cls, assoc_string: str) -> dict:
        """Convert an Assoc string to a Python dict.

        Each comma-separated element of the Assoc will become a dict element.

        Args:
            assoc_string (str):
                The source Assoc string to convert.

        Returns:
            dict: Python dict with the Assoc elements

        """

        if cls.is_html_escaped(assoc_string):
            assoc_string = cls.unescape_html(assoc_string)
        if cls.is_unicode_escaped(assoc_string):
            assoc_string = cls.unescape_unicode(assoc_string)

        # Split the string using regex pattern
        pieces = re.split(r",(?=(?:[^']*'[^']*')*[^']*$)", assoc_string)

        # Trim any leading/trailing spaces from each piece
        pieces = [piece.strip() for piece in pieces]

        # Split the last pieces from the assoc close tag
        last_piece = pieces[-1].split(">")[0]

        # Remove the first two and last pieces from the list
        # the first two are mostly "1" and "?"
        pieces = pieces[2:-1]

        # Insert the last pieces separately
        pieces.append(last_piece)

        assoc_dict: dict = {}

        for piece in pieces:
            name = piece.split("=")[0]
            if name[0] == "'":
                name = name[1:]
            if name[-1] == "'":
                name = name[:-1]
            value = piece.split("=")[1]
            if value[0] == "'":
                value = value[1:]
            if value[-1] == "'":
                value = value[:-1]
            assoc_dict[name] = value

        return assoc_dict

    # end method definition

    @classmethod
    def dict_to_string(cls, assoc_dict: dict) -> str:
        """Convert a Python dict to an Assoc string.

        Args:
            assoc_dict (dict):
                The source dictionary to convert.

        Returns:
            str:
                The resulting Assoc string.

        """

        assoc_string: str = "A&lt;1,?,"

        for item in assoc_dict.items():
            assoc_string += "\u0027" + item[0] + "\u0027"
            assoc_string += "="
            # Extended ECM's XML is a bit special in cases.
            # If the value is empty set (curly braces) it does
            # not put it in quotes. As Extended ECM is also very
            # picky about XML syntax we better produce it exactly like that.
            if item[1] == "{}":
                assoc_string += item[1] + ","
            else:
                assoc_string += "\u0027" + item[1] + "\u0027,"

        if assoc_dict.items():
            assoc_string = assoc_string[:-1]
        assoc_string += "&gt;"
        return assoc_string

    # end method definition

    @classmethod
    def extract_substring(
        cls,
        input_string: str,
        start_sequence: str,
        stop_sequence: str,
    ) -> str | None:
        """Extract a substring that is delimited by a start and stop sequence.

        Args:
            input_string (str):
                Input string to search the delimited substring in.
            start_sequence (str):
                Start esequence of characters.
            stop_sequence (str):
                Stop sequence of characters

        Returns:
            str | None:
                The deliminated substring or None if not found.

        """

        start_index = input_string.find(start_sequence)
        if start_index == -1:
            return None

        end_index = input_string.find(stop_sequence, start_index)
        if end_index == -1:
            return None

        end_index += len(stop_sequence)
        return input_string[start_index:end_index]

    # end method definition

    @classmethod
    def extract_assoc_string(cls, input_string: str, is_escaped: bool = False) -> str:
        """Extract an Assoc from a string.

        The assoc is deliminated by A< ... >.

        Args:
            input_string (str):
                Input string that includes the Assoc as a substring.
            is_escaped (bool, optional):
                Whether or not the input string includes the
                assoc escaped or not.

        Returns:
            str:
                The assoc string.

        """

        if is_escaped:
            assoc_string = cls.extract_substring(input_string, "A&lt;", "&gt;")
        else:
            assoc_string = cls.extract_substring(input_string, "A<", ">")
        return assoc_string

    # end method definition
