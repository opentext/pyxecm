"""XML helper module."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import fnmatch
import glob
import logging
import os
import re
import zipfile
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

import xmltodict

# we need lxml instead of standard xml.etree to have xpath capabilities!
from lxml import etree
from lxml.etree import Element

from pyxecm.helper import Assoc

default_logger = logging.getLogger("pyxecm.helper.xml")


class XML:
    """Handle XML processing, e.g. to parse and update Extended ECM transport packages."""

    logger: logging.Logger = default_logger

    @classmethod
    def remove_xml_namespace(cls, tag: str) -> str:
        """Remove namespace from XML tag.

        Args:
            tag (str):
                The XML tag with namespace.

        Returns:
            str:
                The tag without namespace.

        """

        # In Python's ElementTree, the tag namespace
        # is put into curly braces like "{namespace}element"
        # that's why this method splits after the closing curly brace
        # and takes the last item (-1):

        return tag.split("}", 1)[-1]

    # end method definition

    @classmethod
    def xml_to_dict(cls, xml_string: str, encode: bool = False, include_attributes: bool = False) -> dict:
        """Parse XML string and return a dictionary without namespaces.

        Args:
            xml_string (str):
                The XML string to process.
            encode (bool, optional):
                True if the XML string should be encoded to UTF-8 bytes. Defaults to False.
            include_attributes (bool, optional):
                True if XML attributes should be included in the dictionary. Defaults to False.

        Returns:
            dict:
                The XML structure converted to a dictionary.

        """

        def xml_element_to_dict(element: Element) -> dict:
            """Convert XML element to dictionary.

            Args:
                element (Element):
                    The XML element.

            Returns:
                dict:
                    Dictionary representing the XML element

            """

            tag = cls.remove_xml_namespace(element.tag)
            children = list(element)
            node_dict = {}

            if element.attrib and include_attributes:
                node_dict.update({"@{}".format(k): v for k, v in element.attrib.items()})

            if children:
                child_dict = {}
                for child in children:
                    child_tag = cls.remove_xml_namespace(child.tag)
                    child_value = xml_element_to_dict(child)

                    # child_dict is {child_tag: ...}, we want the value inside
                    value = child_value[child_tag]

                    # Handle multiple occurrences of the same tag:
                    if child_tag in child_dict:
                        # If the tag already exists, ensure it becomes a list
                        if not isinstance(child_dict[child_tag], list):
                            child_dict[child_tag] = [child_dict[child_tag]]
                        child_dict[child_tag].append(value)
                    else:
                        child_dict[child_tag] = value

                # Merge children into node_dict
                node_dict.update(child_dict)

            # Add text if present and meaningful
            text = element.text.strip() if element.text and element.text.strip() else None
            if text:
                if node_dict:
                    node_dict["#text"] = text
                else:
                    return {tag: text}

            return {tag: node_dict if node_dict else text}

        if encode:
            xml_string = xml_string.encode("utf-8")
        root = etree.fromstring(xml_string)

        return xml_element_to_dict(root)

    # end method definition

    @classmethod
    def load_xml_file(
        cls,
        file_path: str,
        xpath: str,
        dir_name: str | None = None,
        logger: logging.Logger = default_logger,
    ) -> list | None:
        """Load an XML file into a Python list of dictionaries.

        Args:
            file_path (str):
                The path to XML file.
            xpath (str):
                XPath to select sub-elements.
            dir_name (str | None, optional):
                Directory name to include in each dictionary, if provided.
            logger (logging.Logger):
                The logging object used for all log messages.

        Returns:
            dict | None:
                A list of dictionaries representing the parsed XML elements,
                or None if an error occurs during file reading or parsing.

        """

        if not os.path.exists(file_path):
            logger.error("XML File -> %s does not exist!", file_path)
            return None

        try:
            tree = etree.parse(file_path)
            if not tree:
                logger.warning("Empty or invalid XML tree for file -> %s", file_path)
                return None

            # Extract elements using the XPath:
            elements = tree.xpath(xpath)
            if not elements:
                logger.warning(
                    "No elements matched XPath -> %s in file -> '%s'",
                    xpath,
                    file_path,
                )
                return None

            # Convert the selected elements to dictionaries
            results = []
            tag = xpath.split("/")[-1]
            for element in elements:
                element_dict = xmltodict.parse(etree.tostring(element))
                if tag in element_dict:
                    element_dict = element_dict[tag]
                if dir_name:
                    element_dict["directory"] = dir_name
                results.append(element_dict)

        except OSError:
            logger.error("IO Error with file -> %s", file_path)
            return None
        except etree.XMLSyntaxError:
            logger.error("XML Syntax Error in file -> %s", file_path)
            return None
        except etree.DocumentInvalid:
            logger.error("Invalid XML document -> %s", file_path)
            return None

        return results

    # end method definition

    @classmethod
    def load_xml_files_from_directory(
        cls,
        path_to_root: str,
        filenames: list | None,
        xpath: str | None = None,
        logger: logging.Logger = default_logger,
    ) -> list | None:
        """Load all XML files from a directory that matches defined file names.

        Then using the XPath to identify a set of elements and convert them
        into a Python list of dictionaries.

        Args:
            path_to_root (str):
                Path to the root element of the
                directory structure
            filenames (list):
                A list of filenames. This can also be patterns like
                "*/en/docovw.xml". If empty all filenames ending
                with ".xml" is used.
            xpath (str, optional):
                The XPath to the elements we want to select.
            logger (logging.Logger):
                The logging object used for all log messages.

        Returns:
            list:
                List of dictionaries.

        """

        if not filenames:
            filenames = ["*.xml"]

        try:
            # Check if the provided path is a directory or a zip file that can be extracted
            # into a directory:
            if not os.path.isdir(path_to_root) and not path_to_root.endswith(".zip"):
                logger.error(
                    "The provided path -> '%s' is not a valid directory or Zip file.",
                    path_to_root,
                )
                return None

            # If we have a zip file we extract it - but only if it has not been extracted before:
            if path_to_root.endswith(".zip"):
                zip_file_folder = os.path.splitext(path_to_root)[0]
                if not os.path.exists(zip_file_folder):
                    logger.info(
                        "Unzipping -> '%s' into folder -> '%s'...",
                        path_to_root,
                        zip_file_folder,
                    )
                    try:
                        with zipfile.ZipFile(path_to_root, "r") as zfile:
                            zfile.extractall(zip_file_folder)
                    except zipfile.BadZipFile:
                        logger.error(
                            "Failed to extract zip file -> '%s'",
                            path_to_root,
                        )
                        return None
                    except OSError:
                        logger.error(
                            "OS error occurred while trying to extract -> '%s'",
                            path_to_root,
                        )
                        return None
                else:
                    logger.info(
                        "Zip file is already extracted (path -> '%s' exists). Reusing extracted data...",
                        zip_file_folder,
                    )
                path_to_root = zip_file_folder

            results = []

            # Walk through the directory
            for root, _, files in os.walk(path_to_root):
                for file_data in files:
                    file_path = os.path.join(root, file_data)
                    file_size = os.path.getsize(file_path)
                    file_name = os.path.basename(file_path)
                    dir_name = os.path.dirname(file_path)

                    if any(fnmatch.fnmatch(file_path, pattern) for pattern in filenames) and file_name.endswith(".xml"):
                        logger.info(
                            "Load XML file -> '%s' of size -> %s",
                            file_path,
                            file_size,
                        )
                        elements = cls.load_xml_file(
                            file_path,
                            xpath=xpath,
                            dir_name=dir_name,
                        )
                        if elements:
                            results += elements

        except NotADirectoryError:
            logger.error(
                "The given path -> '%s' is not a directory!",
                path_to_root,
            )
            return None
        except FileNotFoundError:
            logger.error(
                "The given path -> '%s' does not exist!",
                path_to_root,
            )
            return None
        except PermissionError:
            logger.error(
                "No permission to access path -> '%s'!",
                path_to_root,
            )
            return None
        except OSError:
            logger.error("Low level OS error with file -> %s", path_to_root)
            return None

        return results

    # end method definition

    @classmethod
    def load_xml_files_from_directories(
        cls,
        directories: list[str],
        filenames: list[str] | None = None,
        xpath: str | None = None,
        logger: logging.Logger = default_logger,
    ) -> list[dict] | None:
        """Load XML files from multiple directories or zip files concurrently.

        Process them using XPath, and return a list of dictionaries containing the extracted elements.

        This method handles multiple directories or zip files, processes XML files inside them in parallel
        using threads, and extracts elements that match the specified XPath. It also supports pattern matching
        for filenames and handles errors such as missing files or permission issues.

        Args:
            directories (list[str]):
                A list of directories or zip files to process. Each item can be a path
                to a directory or a zip file that contains XML files.
            filenames (list[str] | None, optional):
                A list of filename patterns (e.g., ["*/en/docovw.xml"]) to match
                against the XML files. If None or empty, defaults to ["*.xml"].
            xpath (str | None, optional):
                An optional XPath string used to filter elements from the XML files.
            logger (logging.Logger):
                The logging object used for all log messages.

        Returns:
            list[dict] | None:
                A list of dictionaries containing the extracted XML elements. Returns None
                if any error occurs during processing.

        Raises:
            Exception: If any error occurs during processing, such as issues with directories, files, or zip extraction.

        """

        # Set default for filenames if not provided
        if not filenames:
            filenames = ["*.xml"]

        results_queue = Queue()

        def process_xml_file(file_path: str) -> None:
            """Process a single XML file.

            Args:
                file_path (str):
                    Path to the XML file.

            Results:
                Adds elements to the result_queue defined outside this sub-method.

            """

            try:
                file_size = os.path.getsize(file_path)
                file_name = os.path.basename(file_path)
                dir_name = os.path.dirname(file_path)

                if (
                    not filenames or any(fnmatch.fnmatch(file_path, pattern) for pattern in filenames)
                ) and file_name.endswith(".xml"):
                    logger.info(
                        "Load XML file -> '%s' of size -> %s",
                        file_path,
                        file_size,
                    )
                    elements = cls.load_xml_file(
                        file_path,
                        xpath=xpath,
                        dir_name=dir_name,
                    )
                    if elements:
                        results_queue.put(elements)
            except FileNotFoundError:
                logger.error("File not found -> '%s'!", file_path)
            except PermissionError:
                logger.error(
                    "Permission error with file -> '%s'!",
                    file_path,
                )
            except OSError:
                logger.error(
                    "OS error processing file -> '%s'!",
                    file_path,
                )
            except ValueError:
                logger.error(
                    "Value error processing file -> '%s'!",
                    file_path,
                )

        # end method process_xml_file

        def process_directory_or_zip(path_to_root: str) -> list | None:
            """Process all files in a directory or zip file.

            Args:
                path_to_root (str):
                    File path to the root directory or zip file.

            """

            try:
                # Handle zip files
                if path_to_root.endswith(".zip"):
                    zip_file_folder = os.path.splitext(path_to_root)[0]
                    if not os.path.exists(zip_file_folder):
                        logger.info(
                            "Unzipping -> '%s' into folder -> '%s'...",
                            path_to_root,
                            zip_file_folder,
                        )
                        try:
                            with zipfile.ZipFile(path_to_root, "r") as zfile:
                                zfile.extractall(zip_file_folder)
                        except zipfile.BadZipFile:
                            logger.error(
                                "Bad zip file -> '%s'!",
                                path_to_root,
                            )
                        except zipfile.LargeZipFile:
                            logger.error(
                                "Zip file is too large to process -> '%s'!",
                                path_to_root,
                            )
                        except PermissionError:
                            logger.error(
                                "Permission error extracting zip file -> '%s'!",
                                path_to_root,
                            )
                        except OSError:
                            logger.error(
                                "OS error occurred while extracting zip file -> '%s'!",
                                path_to_root,
                            )
                        return  # Don't proceed further if zip extraction fails

                    else:
                        logger.info(
                            "Zip file is already extracted (path -> '%s' exists). Reusing extracted data...",
                            zip_file_folder,
                        )
                    path_to_root = zip_file_folder
                # end if path_to_root.endswith(".zip")

                # Use inner threading to process files within the directory
                with ThreadPoolExecutor(
                    thread_name_prefix="ProcessXMLFile",
                ) as inner_executor:
                    for root, _, files in os.walk(path_to_root):
                        for file_data in files:
                            file_path = os.path.join(root, file_data)
                            inner_executor.submit(process_xml_file, file_path)

            except FileNotFoundError:
                logger.error(
                    "Directory or file not found -> '%s'!",
                    path_to_root,
                )
            except PermissionError:
                logger.error(
                    "Permission error with directory -> '%s'!",
                    path_to_root,
                )
            except OSError:
                logger.error(
                    "OS error processing path -> '%s'!",
                    path_to_root,
                )
            except ValueError:
                logger.error(
                    "Value error processing path -> '%s'!",
                    path_to_root,
                )

        # end method process_directory_or_zip

        try:
            # Resolve wildcards in the directories list
            expanded_directories: list[str] = []
            for directory in directories:
                if "*" in directory:
                    expanded_directory: list = glob.glob(directory)
                    logger.info(
                        "Expanding directory -> '%s' with wildcards...",
                        directory,
                    )
                    expanded_directories.extend(expanded_directory)
                else:
                    logger.info(
                        "Directory -> '%s' has no wildcards. Not expanding...",
                        directory,
                    )
                    expanded_directories.append(directory)

            # Use ThreadPoolExecutor for outer level: processing directories/zip files
            logger.info(
                "Starting %d threads for each directory or zip file...",
                len(expanded_directories),
            )
            with ThreadPoolExecutor(
                thread_name_prefix="ProcessDirOrZip",
            ) as outer_executor:
                futures = [
                    outer_executor.submit(process_directory_or_zip, directory) for directory in expanded_directories
                ]

                # Wait for all futures to complete
                for future in futures:
                    future.result()

            # Collect results from the queue
            logger.info("Collecting results from worker queue...")
            results = []
            while not results_queue.empty():
                results.extend(results_queue.get())
            logger.info("Done. Collected %d results.", len(results))

        except FileNotFoundError:
            logger.error(
                "Directory or file not found during execution!",
            )
            return None
        except PermissionError:
            logger.error("Permission error during execution!")
            return None
        except TimeoutError:
            logger.error(
                "Timeout occurred while waiting for threads!",
            )
            return None
        except BrokenPipeError:
            logger.error(
                "Broken pipe error occurred during thread communication!",
            )
            return None

        return results

    # end method definition

    @classmethod
    def get_xml_element(
        cls,
        xml_content: str,
        xpath: str,
    ) -> Element:
        """Retrieve an XML Element from a string using an XPath expression.

        Args:
            xml_content (str):
                XML file as a string
            xpath (str):
                XPath used to find the element.

        Returns:
            Element:
                The XML element.

        """

        # Parse XML content into an etree
        tree = etree.fromstring(xml_content)

        # Find the XML element specified by XPath
        element = tree.find(xpath)

        return element

    # end method definition

    @classmethod
    def modify_xml_element(
        cls,
        xml_content: str,
        xpath: str,
        new_value: str,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Update the text (= content) of an XML element.

        Args:
            xml_content (str):
                The content of an XML file.
            xpath (str):
                XML Path to identify the XML element.
            new_value (str):
                The new text (content).
            logger (logging.Logger):
                The logging object used for all log messages.

        """
        element = cls.get_xml_element(xml_content=xml_content, xpath=xpath)

        if element is not None:
            # Modify the XML element with the new value
            element.text = new_value
        else:
            logger.warning("XML Element -> %s not found.", xpath)

    # end method definition

    @classmethod
    def search_setting(
        cls,
        element_text: str,
        setting_key: str,
        is_simple: bool = True,
        is_escaped: bool = False,
    ) -> str | None:
        """Search a setting in an XML element and return its value.

        The simple case covers settings like this:
        &quot;syncCandidates&quot;:true,
        "syncCandidates":true,
        In this case the setting value is a scalar like true, false, a number or none
        the regular expression pattern searches for a setting name in "..." (quotes) followed
        by a colon (:). The value is taken from what follows the colon until the next comma (,)

        The more complex case is a string value that may itself have commas,
        so we cannot look for comma as a delimiter like in the simple case
        but we take the value for a string delimited by double quotes ("...")

        Args:
            element_text (str):
                The text to examine - typically content of an XML element.
            setting_key (str):
                The name of the setting key (before the colon).
            is_simple (bool, optional):
                True if the value is scalar (not having assocs with commas). Defaults to True.
            is_escaped (bool, optional):
                True if the quotes or escaped with &quot;. Defaults to False.

        Returns:
            str:
                The value of the setting or None if the setting is not found.

        """

        if is_simple:
            pattern = r"&quot;{}&quot;:[^,]*".format(setting_key) if is_escaped else r'"{}":[^,]*'.format(setting_key)
        elif is_escaped:
            pattern = r"&quot;{}&quot;:&quot;.*&quot;".format(setting_key)
        else:
            pattern = r'"{}":"([^"]*)"'.format(setting_key)

        match = re.search(pattern, element_text)
        if match:
            setting_line = match.group(0)
            setting_value = setting_line.split(":")[1]
            return setting_value
        else:
            return None

    # end method definition

    @classmethod
    def replace_setting(
        cls,
        element_text: str,
        setting_key: str,
        new_value: str,
        is_simple: bool = True,
        is_escaped: bool = False,
    ) -> str:
        """Replace the value of a defined setting with a new value.

        The simple case covers settings like this:
        &quot;syncCandidates&quot;:true,
        "syncCandidates":true,
        In this case the setting value is a scalar like true, false, a number or none
        the regular expression pattern searches for a setting name in "..." (quotes) followed
        by a colon (:). The value is taken from what follows the colon until the next comma (,)

        The more complex case is a string value that may itself have commas,
        so we cannot look for comma as a delimiter like in the simple case
        but we take the value for a string delimited by double quotes ("...")

        Args:
            element_text (str):
                The original text of the XML element (that is to be updated).
            setting_key (str):
                The name of the setting.
            new_value (str):
                The new value of the setting.
            is_simple (bool, optional):
                True = value is a scalar like true, false, a number or none. Defaults to True.
            is_escaped (bool, optional):
                True if the value is surrrounded with &quot;. Defaults to False.

        Returns:
            str:
                The updated element text.

        """

        if is_simple:
            pattern = r"&quot;{}&quot;:[^,]*".format(setting_key) if is_escaped else r'"{}":[^,]*'.format(setting_key)
        elif is_escaped:
            pattern = r"&quot;{}&quot;:&quot;.*&quot;".format(setting_key)
        else:
            pattern = r'"{}":"([^"]*)"'.format(setting_key)

        new_text = re.sub(pattern, new_value, element_text)

        return new_text

    # end method definition

    @classmethod
    def replace_in_xml_files(
        cls,
        directory: str,
        search_pattern: str,
        replace_string: str,
        xpath: str = "",
        setting: str = "",
        assoc_elem: str = "",
        logger: logging.Logger = default_logger,
    ) -> bool:
        """Replace all occurrences of the search pattern with the replace string.

        This is done in all XML files in the directory and its subdirectories.

        Args:
            directory (str):
                Directory to traverse for XML files
            search_pattern (str):
                The string to search in the XML file.
                This can be empty if xpath is used!
            replace_string (str):
                The replacement string.
            xpath (str, optional):
                An XPath can be given to narrow down the replacement to an XML element.
                For now the XPath needs to be constructed in a way the it returns
                one or none element.
            setting (str, optional):
                Narrow down the replacement to the line that includes the setting with this name.
                This parameter is optional.
            assoc_elem (str, optional):
                Lookup a specific assoc element. This parameter is optional.
            logger (logging.Logger):
                The logging object used for all log messages.

        Returns:
            bool:
                True if a replacement happened, False otherwise

        """

        # Define the regular expression pattern to search for
        # search pattern can be empty if an xpath is used. So
        # be careful here:
        if search_pattern:
            pattern = re.compile(search_pattern)

        found = False

        # Traverse the directory and its subdirectories
        for subdir, _, files in os.walk(directory):
            for filename in files:
                # Check if the file is an XML file
                if filename.endswith(".xml"):
                    # Read the contents of the file
                    file_path = os.path.join(subdir, filename)

                    # if xpath is given we do an intelligent replacement
                    if xpath:
                        xml_modified = False
                        logger.debug("Replacement with xpath...")
                        logger.debug(
                            "XML path -> %s, setting -> %s, assoc element -> %s",
                            xpath,
                            setting,
                            assoc_elem,
                        )
                        tree = etree.parse(file_path)
                        if not tree:
                            logger.error(
                                "Cannot parse XML tree -> %s. Skipping...",
                                file_path,
                            )
                            continue
                        root = tree.getroot()
                        # find the matching XML elements using the given XPath:
                        elements = root.xpath(xpath)
                        if not elements:
                            logger.debug(
                                "The XML file -> %s does not have any element with the given XML path -> %s. Skipping...",
                                file_path,
                                xpath,
                            )
                            continue
                        for element in elements:
                            # as XPath returns a list
                            logger.debug(
                                "Found XML element -> %s in file -> %s using xpath -> %s",
                                element.tag,
                                filename,
                                xpath,
                            )
                            # the simple case: replace the complete text of the XML element
                            if not setting and not assoc_elem:
                                logger.debug(
                                    "Replace complete text of XML element -> %s from -> %s to -> %s",
                                    xpath,
                                    element.text,
                                    replace_string,
                                )
                                element.text = replace_string
                                xml_modified = True
                            # In this case we want to set a complete value of a setting (basically replacing a whole line)
                            elif setting and not assoc_elem:
                                logger.debug(
                                    "Replace single setting -> %s in XML element -> %s with new value -> %s",
                                    setting,
                                    xpath,
                                    replace_string,
                                )
                                setting_value = cls.search_setting(
                                    element.text,
                                    setting,
                                    is_simple=True,
                                )
                                if setting_value:
                                    logger.debug(
                                        "Found existing setting value -> %s",
                                        setting_value,
                                    )
                                    # Check if the setting value needs to be surrounded by quotes.
                                    # Only simplistic values like booleans or numeric values don't need quotes
                                    if replace_string in ("true", "false", "none") or replace_string.isnumeric():
                                        replace_setting = '"' + setting + '":' + replace_string
                                    else:
                                        replace_setting = '"' + setting + '":"' + replace_string + '"'
                                    logger.debug(
                                        "Replacement setting -> %s",
                                        replace_setting,
                                    )
                                    element.text = cls.replace_setting(
                                        element_text=element.text,
                                        setting_key=setting,
                                        new_value=replace_setting,
                                        is_simple=True,
                                    )
                                    xml_modified = True
                                else:
                                    logger.warning(
                                        "Cannot find the value for setting -> %s. Skipping...",
                                        setting,
                                    )
                                    continue
                            # in this case the text is just one assoc (no setting substructure)
                            elif not setting and assoc_elem:
                                logger.debug(
                                    "Replace single Assoc value -> %s in XML element -> %s with -> %s",
                                    assoc_elem,
                                    xpath,
                                    replace_string,
                                )
                                assoc_string: str = Assoc.extract_assoc_string(
                                    input_string=element.text,
                                )
                                logger.debug("Assoc String -> %s", assoc_string)
                                assoc_dict = Assoc.string_to_dict(
                                    assoc_string=assoc_string,
                                )
                                logger.debug("Assoc Dict -> %s", str(assoc_dict))
                                assoc_dict[assoc_elem] = replace_string  # escaped_replace_string
                                assoc_string_new: str = Assoc.dict_to_string(
                                    assoc_dict=assoc_dict,
                                )
                                logger.debug(
                                    "Replace assoc with -> %s",
                                    assoc_string_new,
                                )
                                element.text = assoc_string_new
                                element.text = element.text.replace('"', "&quot;")
                                xml_modified = True
                            # In this case we have multiple settings with their own assocs
                            elif setting and assoc_elem:
                                logger.debug(
                                    "Replace single Assoc value -> %s in setting -> %s in XML element -> %s with -> %s",
                                    assoc_elem,
                                    setting,
                                    xpath,
                                    replace_string,
                                )
                                setting_value = cls.search_setting(
                                    element.text,
                                    setting,
                                    is_simple=False,
                                )
                                if setting_value:
                                    logger.debug(
                                        "Found setting value -> %s",
                                        setting_value,
                                    )
                                    assoc_string: str = Assoc.extract_assoc_string(
                                        input_string=setting_value,
                                    )
                                    logger.debug("Assoc String -> %s", assoc_string)
                                    assoc_dict = Assoc.string_to_dict(
                                        assoc_string=assoc_string,
                                    )
                                    logger.debug("Assoc Dict -> %s", str(assoc_dict))
                                    escaped_replace_string = replace_string.replace(
                                        "'",
                                        "\\\\\u0027",
                                    )
                                    logger.debug(
                                        "Escaped replacement string -> %s",
                                        escaped_replace_string,
                                    )
                                    assoc_dict[assoc_elem] = escaped_replace_string  # escaped_replace_string
                                    assoc_string_new: str = Assoc.dict_to_string(
                                        assoc_dict=assoc_dict,
                                    )
                                    assoc_string_new = assoc_string_new.replace(
                                        "'",
                                        "\\u0027",
                                    )
                                    replace_setting = '"' + setting + '":"' + assoc_string_new + '"'
                                    logger.debug(
                                        "Replacement setting -> %s",
                                        replace_setting,
                                    )
                                    # here we need to apply a "trick". It is required
                                    # as regexp cannot handle the special unicode escapes \u0027
                                    # we require. We first insert a placeholder "PLACEHOLDER"
                                    # and let regexp find the right place for it. Then further
                                    # down we use a simple search&replace to switch the PLACEHOLDER
                                    # to the real value (replace() does not have the issues with unicode escapes)
                                    element.text = cls.replace_setting(
                                        element_text=element.text,
                                        setting_key=setting,
                                        new_value="PLACEHOLDER",
                                        is_simple=False,
                                        is_escaped=False,
                                    )
                                    element.text = element.text.replace(
                                        "PLACEHOLDER",
                                        replace_setting,
                                    )
                                    element.text = element.text.replace('"', "&quot;")
                                    xml_modified = True
                                else:
                                    logger.warning(
                                        "Cannot find the value for setting -> %s. Skipping...",
                                        setting,
                                    )
                                    continue
                        if xml_modified:
                            logger.debug(
                                "XML tree has been modified. Write updated file -> %s...",
                                file_path,
                            )

                            new_contents = etree.tostring(
                                tree,
                                pretty_print=True,
                                xml_declaration=True,
                                encoding="UTF-8",
                            )
                            # we need to undo some of the stupid things tostring() did:
                            new_contents = new_contents.replace(
                                b"&amp;quot;",
                                b"&quot;",
                            )
                            new_contents = new_contents.replace(
                                b"&amp;apos;",
                                b"&apos;",
                            )
                            new_contents = new_contents.replace(b"&amp;gt;", b"&gt;")
                            new_contents = new_contents.replace(b"&amp;lt;", b"&lt;")

                            # Replace single quotes inside double quotes strings with "&apos;" (manual escaping)
                            # This is required as we next want to replace all double quotes with single quotes
                            pattern = b'"([^"]*)"'
                            new_contents = re.sub(
                                pattern,
                                lambda m: m.group(0).replace(b"'", b"&apos;"),
                                new_contents,
                            )

                            # Replace single quotes in XML text elements with "&apos;"
                            # and replace double quotes in XML text elements with "&quot;"
                            # This is required as we next want to replace all double quotes with single quotes
                            # to make the XML files as similar as possible with Extended ECM's format
                            pattern = b">([^<>]+?)<"
                            replacement = lambda match: match.group(0).replace(  # noqa: E731
                                b'"',
                                b"&quot;",
                            )
                            new_contents = re.sub(pattern, replacement, new_contents)
                            replacement = lambda match: match.group(0).replace(  # noqa: E731
                                b"'",
                                b"&apos;",
                            )
                            new_contents = re.sub(pattern, replacement, new_contents)

                            # Change double quotes to single quotes across the XML file - Extended ECM has it that way:
                            new_contents = new_contents.replace(b'"', b"'")

                            # Write the updated contents to the file.
                            # We DO NOT want to use tree.write() here
                            # as it would undo the manual XML tweaks we
                            # need for Extended ECM. We also need "wb"
                            # as we have bytes and not str as a data type
                            with open(file_path, "wb") as f:
                                f.write(new_contents)

                            found = True
                    # this is not using xpath - do a simple search and replace
                    else:
                        logger.debug("Replacement without xpath...")
                        with open(file_path, encoding="UTF-8") as f:
                            contents = f.read()
                        # Replace all occurrences of the search pattern with the replace string
                        new_contents = pattern.sub(replace_string, contents)

                        # Write the updated contents to the file if there were replacements
                        if contents != new_contents:
                            logger.debug(
                                "Found search string -> %s in XML file -> %s. Write updated file...",
                                search_pattern,
                                file_path,
                            )
                            # Write the updated contents to the file
                            with open(file_path, "w", encoding="UTF-8") as f:
                                f.write(new_contents)
                            found = True

        return found

    # end method definition

    @classmethod
    def extract_from_xml_files(
        cls,
        directory: str,
        xpath: str,
        logger: logging.Logger = default_logger,
    ) -> list | None:
        """Extract the XML subtrees using an XPath in all XML files in the directory and its subdirectories.

        Args:
            directory (str):
                The directory to traverse for XML files.
            xpath (str):
                Used to determine XML elements to extract.
            logger (logging.Logger):
                The logging object used for all log messages.

        Returns:
            list | None:
                Extracted data if it is found by the XPath, None otherwise.

        """

        extracted_data_list = []

        # Traverse the directory and its subdirectories
        for subdir, _, files in os.walk(directory):
            for filename in files:
                # Check if the file is an XML file
                if filename.endswith(".xml"):
                    # Read the contents of the file
                    file_path = os.path.join(subdir, filename)

                    logger.debug("Extraction with xpath -> %s...", xpath)
                    tree = etree.parse(file_path)
                    if not tree:
                        logger.error(
                            "Cannot parse XML file -> '%s'. Skipping...",
                            file_path,
                        )
                        continue
                    root = tree.getroot()
                    # find the matching XML elements using the given XPath:
                    elements = root.xpath(xpath)
                    if not elements:
                        logger.debug(
                            "The XML file -> %s does not have any element with the given XML path -> %s. Skipping...",
                            file_path,
                            xpath,
                        )
                        continue
                    for element in elements:
                        # as XPath returns a list
                        logger.debug(
                            "Found XML element -> %s in file -> %s using xpath -> %s. Add it to result list.",
                            element.tag,
                            filename,
                            xpath,
                        )
                        extracted_content = etree.tostring(element)

                        try:
                            dict_content = xmltodict.parse(extracted_content)
                        except xmltodict.expat.ExpatError:
                            logger.error(
                                "Invalid XML syntax in file -> %s. Please check the XML file for errors.",
                                filename,
                            )
                            continue

                        extracted_data_list.append(dict_content)

        return extracted_data_list

    # end method definition
