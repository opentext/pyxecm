"""
Data Module to implement functions to leverage Pandas to
manipulte data structures read for bulk generation of Extended ECM items.

This code implements a class called data which is referring
to Pandas DataFrame.

Class: Payload
Methods:

__init__ : class initializer
__len__: Lenght of the embedded DataFrame object.
__str__: Print the DataFrame of the class
get_data_frame: Get the Pandas DataFrame object
set_data_frame: Set the Pandas DataFrame object
append: Append additional data to the data frame.

load_json_data: Load JSON data into DataFrame
save_json_data: Save JSON data from DataFrame to file
load_excel_data: Load Excel file into DataFrame
load_csv_data: Load CSV data into DataFrame
load_directory: Load directory structure into Pandas Data Frame

partitionate: Partition a data frame into equally sized partions
deduplicate: Remove dupclicate rows that have all fields in unique_fields in common
sort: Sort the data frame based on one or multiple fields.
flatten: Flatten a sub-dictionary by copying selected fields to the
         parent dictionary.
explode_and_flatten: Explode a substructure in the Data Frame
drop_columns: Drop selected columns from the Data Frame
keep_columns: Keep only selected columns from the Data Frame. Drop the rest.
cleanse: Cleanse data with regular expressions and upper/lower case conversion.
filter: Filter the DataFrame based on conditions

fill_forward: Fill the missing cells appropriately by carrying forward
              the values from the previous rows where necessary.
fill_na_in_column: Replace NA values in a column with a defined new default value              
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import json
import os
import re
import threading

import pandas as pd

logger = logging.getLogger("pyxecm.helper.data")


class Data:
    """Used to automate data loading for the customizer."""

    _df: pd.DataFrame
    _lock = threading.Lock()

    def __init__(self, init_data: pd.DataFrame | list = None):
        """Initialize the Data object.

        Args:
            init_data (pd.DataFrame | list, optional): Data to initialize the data frame. Can either be
                                                       another data frame (that gets copied) or a list of dictionaries.
                                                       Defaults to None.
        """

        if init_data is not None:
            # if a data frame is passed to the constructor we
            # copy its content to the new Data object

            if isinstance(init_data, pd.DataFrame):
                self._df: pd.DataFrame = init_data.copy()
            elif isinstance(init_data, Data):
                if init_data.get_data_frame() is not None:
                    self._df: pd.DataFrame = init_data.get_data_frame().copy()
            elif isinstance(init_data, list):
                self._df: pd.DataFrame = pd.DataFrame(init_data)
            elif isinstance(init_data, dict):
                # it is important to wrap the dict in a list to avoid that more than 1 row is created
                self._df: pd.DataFrame = pd.DataFrame([init_data])
            else:
                logger.error("Illegal initialization data for 'Data' class!")
                self._df = None
        else:
            self._df = None

    # end method definition

    def __len__(self) -> int:
        """Lenght of the embedded DataFrame object.
           This is basically a convenience method.

        Returns:
            int: Lenght of the DataFrame
        """

        if self._df is not None:
            return len(self._df)
        return 0

    # end method definition

    def __str__(self) -> str:
        """Print the DataFrame of the class.

        Returns:
            str: String representation.
        """

        # if data frame is initialized we return
        # the string representation of pd.DataFrame
        if self._df is not None:
            return str(self._df)

        return str(self)

    # end method definition

    def __getitem__(self, column: str) -> pd.Series:
        """Return the column corresponding to the key from the DataFrame

        Args:
            column (str): name of the Data Frame column

        Returns:
            pd.Series: column of the Data Frame with the given name
        """

        return self._df[column]

    # end method definition

    def lock(self):
        """Return the threading lock object.

        Returns:
            _type_: threading lock object
        """
        return self._lock

    # end method definition

    def get_data_frame(self) -> pd.DataFrame:
        """Get the Pandas DataFrame object

        Returns:
            pd.DataFrame: Pandas DataFrame object
        """

        return self._df

    # end method definition

    def set_data_frame(self, df: pd.DataFrame):
        """Set the Pandas DataFrame object

        Args:
            df (pd.DataFrame): Pandas DataFrame object
        """

        self._df = df

    # end method definition

    def print_info(
        self,
        show_size: bool = True,
        show_info: bool = False,
        show_columns: bool = False,
        show_first: bool = False,
        show_last: bool = False,
        show_sample: bool = False,
        show_statistics: bool = False,
        row_num: int = 10,
    ):
        """Log information about the data frame

        Args:
            show_size (bool, optional): Show size of data frame. Defaults to True.
            show_info (bool, optional): Show information for data frame. Defaults to False.
            show_columns (bool, optional): Show columns of data frame. Defaults to False.
            show_first (bool, optional): Show first 10 items. Defaults to False.
            show_last (bool, optional): Show last 10 items. Defaults to False.
            show_sample (bool, optional): Show 10 sample items. Defaults to False.
            show_statistics (bool, optional): Show data frame statistics. Defaults to False.
        """

        if self._df is None:
            logger.warning("Data Frame is not initialized!")
            return

        if show_size:
            logger.info(
                "Data Frame has %s row(s) and %s column(s)",
                self._df.shape[0],
                self._df.shape[1],
            )

        if show_info:
            # df.info() can not easily be embedded into a string
            self._df.info()

        if show_columns:
            logger.info("Columns:\n%s", self._df.columns)
            logger.info(
                "Columns with number of null values:\n%s", self._df.isnull().sum()
            )
            logger.info(
                "Columns with number of non-null values:\n%s", self._df.notnull().sum()
            )
            logger.info("Columns with number of NaN values:\n%s", self._df.isna().sum())
            logger.info(
                "Columns with number of non-NaN values:\n%s", self._df.notna().sum()
            )

        if show_first:
            # the default for head is n = 5:
            logger.info("First %s rows:\n%s", str(row_num), self._df.head(row_num))

        if show_last:
            # the default for tail is n = 5:
            logger.info("Last %s rows:\n%s", str(row_num), self._df.tail(row_num))

        if show_sample:
            # the default for sample is n = 1:
            logger.info("%s Sample rows:\n%s", str(row_num), self._df.sample(n=row_num))

        if show_statistics:
            logger.info(
                "Description of statistics for data frame:\n%s", self._df.describe()
            )
            logger.info(
                "Description of statistics for data frame (Transformed):\n%s",
                self._df.describe().T,
            )
            logger.info(
                "Description of statistics for data frame (objects):\n%s",
                self._df.describe(include="object"),
            )

    # end method definition

    def append(self, add_data: pd.DataFrame | list | dict) -> bool:
        """Append additional data to the data frame.

        Args:
            add_data (pd.DataFrame | list | dict): Additional data. Can be pd.DataFrame or list of dicts (or Data)

        Returns:
            bool: True = Success, False = Error
        """

        # Does the data frame has already content?
        # Then we need to concat / append. Otherwise
        # we just initialize self._df
        if self._df is not None:
            if isinstance(add_data, pd.DataFrame):
                self._df = pd.concat([self._df, add_data], ignore_index=True)
                return True
            elif isinstance(add_data, Data):
                df = add_data.get_data_frame()
                if df:
                    self._df = pd.concat([self._df, df], ignore_index=True)
                return True
            elif isinstance(add_data, list):
                if add_data:
                    df = Data(add_data)
                    self._df = pd.concat(
                        [self._df, df.get_data_frame()], ignore_index=True
                    )
                return True
            elif isinstance(add_data, dict):
                if add_data:
                    # it is important to wrap the dict in a list to avoid that more than 1 row is created
                    df = Data([add_data])
                    self._df = pd.concat(
                        [self._df, df.get_data_frame()], ignore_index=True
                    )
                return True
            else:
                logger.error("Illegal data type -> '%s'", type(add_data))
                return False
        else:  # self._df is None (initial state)
            if isinstance(add_data, pd.DataFrame):
                self._df = add_data
                return True
            elif isinstance(add_data, Data):
                self._df = add_data.get_data_frame()
                return True
            elif isinstance(add_data, list):
                self._df = pd.DataFrame(add_data)
                return True
            elif isinstance(add_data, dict):
                # it is important to wrap the dict in a list to avoid that more than 1 row is created
                self._df = pd.DataFrame([add_data])
                return True
            else:
                logger.error("Illegal data type -> '%s'", type(add_data))
                return False

    # end method definition

    def load_json_data(self, json_path: str, convert_dates: bool = False) -> bool:
        """Load JSON data into DataFrame

        Args:
            json_path (str): Path to the JSON file.
            convert_dates (bool, optional): whether or not dates should be converted
        Returns:
            bool: False in case an error occured, True otherwise.
        """

        if json_path is not None and os.path.exists(json_path):
            # Load data from JSON file
            try:
                df = pd.read_json(path_or_buf=json_path, convert_dates=convert_dates)
                if self._df is None:
                    self._df = df
                else:
                    self._df = pd.concat([self._df, df])
                logger.info(
                    "After loading -> '%s' the Data Frame has %s row(s) and %s column(s)",
                    json_path,
                    self._df.shape[0],
                    self._df.shape[1],
                )
            except FileNotFoundError:
                logger.error(
                    "JSON file -> %s not found. Please check the file path.", json_path
                )
                return False
            except PermissionError:
                logger.error(
                    "Permission denied to access the JSON file -> %s.", json_path
                )
                return False
            except IOError as e:
                logger.error("An I/O error occurred -> %s", str(e))
                return False
            except json.JSONDecodeError as e:
                logger.error("Error: Unable to decode JSON -> %s", str(e))
                return False
            except ValueError as e:
                logger.error("Invalid JSON input -> %s", str(e))
                return False
            except AttributeError as e:
                logger.error("Unexpected JSON data structure -> %s", str(e))
                return False
            except TypeError as e:
                logger.error("Unexpected JSON data type -> %s", str(e))
                return False
            except KeyError as e:
                logger.error("Missing key in JSON data -> %s", str(e))
                return False

        else:
            logger.error(
                "Missing JSON file - you have not specified a valid path -> %s.",
                json_path,
            )
            return False
        return True

    # end method definition

    def save_json_data(
        self, json_path: str, orient: str = "records", preserve_index: bool = False
    ) -> bool:
        """Save JSON data from DataFrame to file

        Args:
            json_path (str): Path to the JSON file.
            orient (str, optional): Structure of the JSON
            preserve_index (bool, optional)
        Returns:
            bool: False in case an error occured, True otherwise.
        """

        if json_path is not None and os.path.exists(os.path.dirname(json_path)):
            # Load data from JSON file
            try:
                if self._df is not None:
                    # index parameter is only allowed if orient has one of the following values:
                    if (
                        orient == "columns"
                        or orient == "index"
                        or orient == "table"
                        or orient == "split"
                    ):
                        self._df.to_json(
                            path_or_buf=json_path,
                            index=preserve_index,
                            orient=orient,
                            indent=2,
                        )
                    else:
                        self._df.to_json(path_or_buf=json_path, orient=orient, indent=2)
                else:
                    logger.warning("Data Frame is empty. Cannot write it to JSON")
                    return False
            except FileNotFoundError:
                logger.error(
                    "File -> '%s' not found. Please check the file path.", json_path
                )
                return False
            except PermissionError:
                logger.error("Permission denied to access the file -> '%s'.", json_path)
                return False
            except IOError as e:
                logger.error("An I/O error occurred -> %s", str(e))
                return False
            except ValueError as e:
                logger.error("Value Error -> %s", str(e))
                return False

        else:
            logger.error(
                "Missing JSON file -> '%s' you have not specified a valid path!",
                json_path,
            )
            return False
        return True

    # end method definition

    def load_excel_data(
        self,
        xlsx_path: str,
        sheet_names: str | list | None = 0,
        usecols: str | list | None = None,
        skip_rows: int | None = None,
        header: int | None = 0,
        names: list | None = None,
        na_values: list | None = None,
    ) -> bool:
        """Load Excel (xlsx) data into DataFrame. Supports xls, xlsx, xlsm, xlsb, odf, ods and odt file extensions
           read from a local filesystem or URL. Supports an option to read a single sheet or a list of sheets.

        Args:
            xlsx_path (str): Path to the Excel file.
            sheet_names (list | str | int, optional): Name or Index of the sheet in the Excel workbook to load.
                                                      If 'None' then all sheets will be loaded.
                                                      If 0 then first sheet in workbook will be loaded (this is the Default)
                                                      If string then this is interpreted as the name of the sheet to load.
                                                      If a list is passed, this can be a list of index values (int) or
                                                      a list of strings with the sheet names to load.
            usecols (list | str, optional): List of columns to load, specified by general column names in Excel,
                                            e.g. usecols='B:D', usecols=['A', 'C', 'F']
            skip_rows (int, optional): List of rows to skip on top of the sheet (e.g. to not read headlines)
            header (int | None, optional): Excel Row (0-indexed) to use for the column labels of the parsed DataFrame.
                                           If file contains no header row, then you should explicitly pass header=None.
                                           Default is 0.
            names (list): List of column names to use. Default is None
            na_values (list, optional): List of values in the Excel that should become the Pandas NA value.
        Returns:
            bool: False in case an error occured, True otherwise.
        """

        if xlsx_path is not None and os.path.exists(xlsx_path):
            # Load data from Excel file
            try:
                df = pd.read_excel(
                    io=xlsx_path,
                    sheet_name=sheet_names,
                    usecols=usecols,
                    skiprows=skip_rows,
                    header=header,
                    names=names,
                    na_values=na_values,
                )
                # if multiple sheets from an Excel workbook are loaded,
                # then read_excel() returns a dictionary. The keys are
                # the names of the sheets and the values are the Data Frames.
                # we handle this case as follows:
                if isinstance(df, dict):
                    logger.info("Loading multiple Excel sheets from the workbook!")
                    multi_sheet_df = pd.DataFrame()
                    for sheet in df.keys():
                        multi_sheet_df = pd.concat(
                            [multi_sheet_df, df[sheet]], ignore_index=True
                        )
                    df = multi_sheet_df
                if self._df is None:
                    self._df = df
                else:
                    self._df = pd.concat([self._df, df], ignore_index=True)
            except FileNotFoundError:
                logger.error(
                    "Excel file -> '%s' not found. Please check the file path.",
                    xlsx_path,
                )
                return False
            except PermissionError:
                logger.error(
                    "Permission denied to access the Excel file -> '%s'.", xlsx_path
                )
                return False
            except IOError as e:
                logger.error(
                    "An I/O error occurred -> %s while reading the Excel file -> %s",
                    str(e),
                    xlsx_path,
                )
                return False
            except ValueError as e:
                logger.error(
                    "Invalid Excel input -> %s in Excel file -> %s", str(e), xlsx_path
                )
                return False
            except AttributeError as e:
                logger.error("Unexpected data structure -> %s", str(e))
                return False
            except TypeError as e:
                logger.error("Unexpected data type -> %s", str(e))
                return False
            except KeyError as e:
                logger.error("Missing key in Excel data -> %s", str(e))
                return False

        else:
            logger.error(
                "Missing Excel file -> '%s' you have not specified a valid path!",
                xlsx_path,
            )
            return False
        return True

    # end method definition

    def save_excel_data(
        self, excel_path: str, sheet_name: str = "Pandas Export", index: bool = False
    ) -> bool:
        """
        Save the DataFrame to an Excel file, with robust error handling and logging.

        Args:
            excel_path (str): The file path to save the Excel file.
            sheet_name (str): The sheet name where data will be saved. Default is 'Sheet1'.
            index: Whether to write the row names (index). Default is False.
        """
        try:
            # Check if the directory exists
            directory = os.path.dirname(excel_path)
            if directory and not os.path.exists(directory):
                raise FileNotFoundError(
                    "The directory -> '%s' does not exist." % directory
                )

            # Attempt to save the DataFrame to Excel
            self._df.to_excel(excel_path, sheet_name=sheet_name, index=index)
            logger.info("Data saved successfully to -> %s", excel_path)

        except FileNotFoundError as e:
            logger.error("Error: %s", e)
            return False
        except PermissionError:
            logger.error(
                "Error: Permission denied. You do not have permission to write to '%s'.",
                excel_path,
            )
            return False
        except ValueError as ve:
            logger.error("Error: Invalid data for Excel format -> %s", ve)
            return False
        except OSError as oe:
            logger.error("Error: OS error occurred while saving file -> %s", oe)
            return False
        except Exception as e:
            # Catch-all for any other unexpected errors
            logger.error("An unexpected error occurred -> %s", e)
            return False

        return True

    # end method definition

    def load_csv_data(
        self, csv_path: str, delimiter: str = ",", encoding: str = "utf-8"
    ) -> bool:
        """Load CSV (Comma separated values) data into DataFrame

        Args:
            csv_path (str): Path to the CSV file.
            delimiter (str, optional, length = 1): chracter to delimit values. Default ="," (comma)
            encoding (str, optional): encoding of the file. Default = "utf-8".
        Returns:
            bool: False in case an error occured, True otherwise.
        """

        if csv_path is not None and os.path.exists(csv_path):
            # Load data from CSV file
            try:
                df = pd.read_csv(
                    filepath_or_buffer=csv_path, delimiter=delimiter, encoding=encoding
                )
                if self._df is None:
                    self._df = df
                else:
                    self._df = pd.concat([self._df, df])
            except FileNotFoundError:
                logger.error(
                    "CSV file -> '%s' not found. Please check the file path.", csv_path
                )
                return False
            except PermissionError:
                logger.error(
                    "Permission denied to access the CSV file -> %s.", csv_path
                )
                return False
            except IOError as e:
                logger.error("An I/O error occurred -> %s", str(e))
                return False
            except ValueError as e:
                logger.error("Invalid CSV input -> %s", str(e))
                return False
            except AttributeError as e:
                logger.error("Unexpected data structure -> %s", str(e))
                return False
            except TypeError as e:
                logger.error("Unexpected data type -> %s", str(e))
                return False
            except KeyError as e:
                logger.error("Missing key in CSV data -> %s", str(e))
                return False

        else:
            logger.error(
                "Missing CSV file -> '%s' you have not specified a valid path!",
                csv_path,
            )
            return False
        return True

    # end method definition

    def load_xml_data(
        self, xml_path: str, xpath: str | None = None, xslt_path: str | None = None
    ) -> bool:
        """Load XML data into DataFrame

        Args:
            xml_path (str): Path to the XML file.
            xpath (str, optional): XPath to the elements we want to select
            xslt_path (str, optional): XSLT transformation file
        Returns:
            bool: False in cause an error occured, True otherwise.
        """

        try:
            df = pd.read_xml(path_or_buffer=xml_path, xpath=xpath, stylesheet=xslt_path)
            # Process the loaded data as needed
            if self._df is None:
                self._df = df
            else:
                self._df = pd.concat([self._df, df])
            logger.info("XML file loaded successfully!")
            return True
        except FileNotFoundError:
            print("File not found.")
            return False
        except PermissionError:
            logger.error("Permission denied to access the file -> %s.", xml_path)
            return False
        except IOError as e:
            logger.error("An I/O error occurred -> %s", str(e))
            return False
        except ValueError as e:
            logger.error("Invalid CSV input -> %s", str(e))
            return False
        except AttributeError as e:
            logger.error("Unexpected data structure -> %s", str(e))
            return False
        except TypeError as e:
            logger.error("Unexpected data type -> %s", str(e))
            return False
        except KeyError as e:
            logger.error("Missing key in CSV data -> %s", str(e))
            return False

    # end method definition

    def load_directory(self, path_to_root: str) -> bool:
        """Load directory structure into Pandas Data Frame

        Args:
            path_to_root (str): Path to the root element of the
                                directory structure

        Returns:
            bool: True = Success, False = Failure
        """

        try:
            # Check if the provided path is a directory
            if not os.path.isdir(path_to_root):
                logger.error(
                    "The provided path -> '%s' is not a valid directory.", path_to_root
                )
                return False

            # Initialize a list to hold file information
            data = []

            # Walk through the directory
            for root, _, files in os.walk(path_to_root):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_size = os.path.getsize(file_path)
                    relative_path = os.path.relpath(file_path, path_to_root)
                    path_parts = relative_path.split(os.sep)

                    # Create a dictionary with the path parts and file details
                    entry = {
                        "level {}".format(i): part
                        for i, part in enumerate(path_parts[:-1], start=1)
                    }
                    entry.update({"filename": path_parts[-1], "size": file_size})
                    data.append(entry)

            # Create DataFrame from list of dictionaries
            self._df = pd.DataFrame(data)

            # Determine the maximum number of levels
            max_levels = max((len(entry) - 2 for entry in data), default=0)

            # Ensure all entries have the same number of levels
            for entry in data:
                for i in range(1, max_levels + 1):
                    entry.setdefault("level {}".format(i), "")

            # Convert to DataFrame again to make sure all columns are consistent
            self._df = pd.DataFrame(data)

        except NotADirectoryError as nde:
            print(f"Error: {nde}")
        except FileNotFoundError as fnfe:
            print(f"Error: {fnfe}")
        except PermissionError as pe:
            print(f"Error: {pe}")

        return True

    # end method definition

    def load_xml_directory(self, path_to_root: str, xpath: str | None = None) -> bool:
        """Load directory structure into Pandas Data Frame

        Args:
            path_to_root (str): Path to the root element of the
                                directory structure
            xpath (str, optional): XPath to the elements we want to select

        Returns:
            bool: True = Success, False = Failure
        """

        try:
            # Check if the provided path is a directory
            if not os.path.isdir(path_to_root):
                logger.error(
                    "The provided path -> '%s' is not a valid directory.", path_to_root
                )
                return False

            # Walk through the directory
            for root, _, files in os.walk(path_to_root):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_size = os.path.getsize(file_path)
                    file_name = os.path.basename(file_path)

                    if file_name == "docovw.xml":
                        logger.info(
                            "Load XML file -> '%s' of size -> %s", file_path, file_size
                        )
                        success = self.load_xml_data(file_path, xpath=xpath)
                        if success:
                            logger.info(
                                "Successfully loaded XML file -> '%s'", file_path
                            )

        except NotADirectoryError as nde:
            logger.error("Error -> %s", str(nde))
        except FileNotFoundError as fnfe:
            logger.error("Error -> %s", str(fnfe))
        except PermissionError as pe:
            logger.error("Error -> %s", str(pe))

        return True

    # end method definition

    def partitionate(self, number: int) -> list:
        """Partition a data frame into equally sized
           partions

        Args:
            number (int): Number of partitions

        Returns:
            list: List of partitions
        """

        # Calculate the approximate size of each partition
        size = len(self._df)

        if size >= number:
            partition_size = size // number
            remainder = size % number
        else:
            partition_size = size
            number = 1
            remainder = 0

        logger.info(
            "Data set has -> %s elements. We split it into -> %s partitions with -> %s rows and remainder -> %s...",
            str(size),
            str(number),
            str(partition_size),
            str(remainder),
        )

        # Initialize a list to store partitions
        partitions = []
        start_index = 0

        # Slice the DataFrame into equally sized partitions
        for i in range(number):
            # start_index = i * partition_size
            # end_index = (i + 1) * partition_size if i < number - 1 else None
            # partition = self._df.iloc[start_index:end_index]
            # partitions.append(partition)
            # Calculate the end index for this partition
            end_index = start_index + partition_size + (1 if i < remainder else 0)
            partition = self._df.iloc[start_index:end_index]
            partitions.append(partition)
            start_index = end_index

        return partitions

    # end method definition

    def partitionate_by_column(self, column_name: str) -> list | None:
        """Partition a data frame based on equal values in a specified column.

        Args:
            column_name (str): The column name to partition by

        Returns:
            list | None: List of partitions or None in case of an error (e.g. column name does not exist).
        """

        if column_name not in self._df.columns:
            logger.error(
                "Column -> '%s' does not exist in the Data Frame. Data Frame has these columns -> %s",
                column_name,
                str(self._df.columns),
            )
            return None

        # Separate rows with NaN or None values in the specified column
        nan_partitions = self._df[self._df[column_name].isna()]
        non_nan_df = self._df.dropna(subset=[column_name])

        # Group by the specified column and create a list of DataFrames for each group
        grouped = non_nan_df.groupby(column_name)
        partitions = [group for _, group in grouped]

        # Add each row with NaN or None values as its own partition
        for i in range(len(nan_partitions)):
            partitions.append(nan_partitions.iloc[[i]])

        logger.info(
            "Data Frame has been partitioned into -> %s partitions based on the values in column '%s'...",
            str(len(partitions)),
            column_name,
        )

        return partitions

    # end method definition

    def deduplicate(self, unique_fields: list, inplace: bool = True) -> pd.DataFrame:
        """Remove dupclicate rows that have all fields in
           unique_fields in common.

        Args:
            unique_fields (list): Defines the fields for which we want a unique
                                  combination.
            inplace (bool, optional): True if the deduplication happens in-place.
                                      Defaults to True.
        Returns:
            pd.DataFrame | None: If inplace is False than a new deduplicatd DataFrame
                                 is returned. Otherwise the object is modified in place
                                 and self._df is returned.
        """

        if inplace:
            self._df.drop_duplicates(subset=unique_fields, inplace=True)
            self._df.reset_index(drop=True, inplace=True)
            return self._df
        else:
            df = self._df.drop_duplicates(subset=unique_fields, inplace=False)
            df = df.reset_index(drop=True, inplace=False)
            return df

    # end method definition

    def sort(self, sort_fields: list, inplace: bool = True) -> pd.DataFrame:
        """Sort the data frame based on one or multiple fields -
           either in place or return it as a new data frame (e.g. not modifying self._df)

        Args:
            sort_fields (list): Columns / fields to be used for sorting
            inplace (bool, optional): If the sorting should be inplace, i.e. modifying self._df.
                                      Defaults to True.
        Returns:
            pd.DataFrame: New DataFrame (if inplace = False) or self._df (if inplace = True)
        """

        if self._df is None:
            return None

        if not all(sort_field in self._df.columns for sort_field in sort_fields):
            logger.warning(
                "Not all of the given sort fields -> %s do exist in the Data Frame.",
                str(sort_fields),
            )
            # Reduce the sort fields to those that really exist in the DataFrame:
            sort_fields = [
                sort_field
                for sort_field in sort_fields
                if sort_field in self._df.columns
            ]
            logger.warning(
                "Only these given sort fields -> %s do exist as columns in the Data Frame.",
                str(sort_fields),
            )

        if inplace:
            self._df.sort_values(by=sort_fields, inplace=True)
            self._df.reset_index(drop=True, inplace=True)
            return self._df
        else:
            df = self._df.sort_values(by=sort_fields, inplace=False)
            df = df.reset_index(drop=True, inplace=False)
            return df

    # end method definition

    def flatten(
        self,
        parent_field: str,
        flatten_fields: list,
    ):
        """Flatten a sub-dictionary by copying selected fields to the
           parent dictionary. This is e.g. useful for then de-duplicate
           a data set.

        Args:
            parent_field (str): name of the field in the parent dictionary
            flatten_fields (list): fields in the sub-dictionary to copy
                                   into the parent dictionary.
        """

        for flatten_field in flatten_fields:
            flat_field = parent_field + "_" + flatten_field
            # The following expression generates a new column in the
            # data frame with the name of 'flat_field'.
            # In the lambada function x is a dictionary that includes the subvalues
            # and it returns the value of the given flatten field
            # (if it exists, otherwise None). So x is self._df[parent_field], i.e.
            # what the lambda function gets 'applied' on.
            self._df[flat_field] = self._df[parent_field].apply(
                lambda x, sub_field=flatten_field: (
                    x.get(sub_field, None) if isinstance(x, dict) else None
                )
            )

    # end method definition

    def explode_and_flatten(
        self,
        explode_field: str | list,
        flatten_fields: list | None = None,
        make_unique: bool = False,
        reset_index: bool = False,
        split_string_to_list: bool = False,
        separator: str = ";,",
    ) -> pd.DataFrame:
        """Explode a substructure in the Data Frame

        Args:
            explode_field (str | list): Field(s) to explode which each has/have a list structure.
                                        Exploding multiple columns at once is possible. This delivers
                                        a very different result compared to exploding one column after
                                        the other!
            flatten_fields (list): Fields in the exploded substructure to include
                                   in the main dictionaries for easier processing.
            make_unique (bool, optional): if True deduplicate the exploded data frame.
            reset_index (bool, False): True = index is reset, False = Index is not reset
            split_string_to_list (bool, optional): if True flatten the exploded data frame.
            separator (str, optional): characters used to split the string values in the given column into a list
        Returns:
            pd.DataFrame: Pointer to the Pandas DataFrame
        """

        def update_column(row):
            try:
                if sub in row:
                    return row[sub]
            except (IndexError, KeyError, ValueError):
                return ""

        # Define a function to split a string into a list
        def string_to_list(string: str | None) -> list:
            # Do nothing if the string is already a list
            if isinstance(string, list):
                return_list = string
            elif not string or pd.isna(string):
                return_list = []
            else:
                # Use regular expression to split by comma, semicolon, or comma followed by space
                return_list = re.split(rf"[{separator}]\s*", str(string))

            return return_list

        if isinstance(explode_field, list):
            logger.info("Explode multiple columns -> %s", str(explode_field))
        elif isinstance(explode_field, str):
            logger.info("Explode single column -> '%s'", explode_field)
        else:
            logger.error(
                "Illegal explode field(s) data type provided -> %s", type(explode_field)
            )
            return self._df

        try:
            # remove the sub dictionary that sometimes is introduced by
            # XML loading. We just want the main part.
            if "." in explode_field:
                main = explode_field.split(".")[0]
                sub = explode_field.split(".")[1]
                self._df[main] = self._df[main].apply(update_column)
                explode_field = main

            # Now that we have the right explode column
            # we need to convert it to a list if it is inside a string (with delimiters)
            if split_string_to_list:
                logger.info(
                    "Split the string values of column -> '%s' into a list using separator -> '%s'",
                    explode_field,
                    separator,
                )
                # Apply the function to convert the string values in the column (give by the name in explode_field) to lists
                # The string_to_list() sub-method above also considers the separator parameter.
                self._df[explode_field] = self._df[explode_field].apply(string_to_list)

            # Explode the field that has list values
            self._df = self._df.explode(column=explode_field)
        except KeyError:
            logger.error("Column -> '%s' not found in Data Frame!", str(explode_field))
        except ValueError:
            logger.error(
                "Unable to explode the specified column -> '%s'!", str(explode_field)
            )

        if flatten_fields:
            self.flatten(parent_field=explode_field, flatten_fields=flatten_fields)

            if make_unique:
                self._df.drop_duplicates(subset=flatten_fields, inplace=True)

        if reset_index:
            self._df.reset_index(inplace=True)

        return self._df

    # end method definition

    def drop_columns(self, column_names: list, inplace: bool = True) -> pd.DataFrame:
        """Drop selected columns from the Data Frame

        Args:
            column_names (list): list of column names to drop.
            inplace (bool, optional): If the dropping should be inplace, i.e. modifying self._df.
                                      Defaults to True.
        Returns:
            pd.DataFrame: New DataFrame (if inplace = False) or self._df (if inplace = True)
        """

        if not all(column_name in self._df.columns for column_name in column_names):
            # Reduce the column names to those that really exist in the DataFrame:
            column_names = [
                column_name
                for column_name in column_names
                if column_name in self._df.columns
            ]
            logger.warning(
                "Reduce to these columns -> %s that do exist in the Data Frame.",
                str(column_names),
            )

        if inplace:
            self._df.drop(column_names, axis=1, inplace=True)
            return self._df
        else:
            df = self._df.drop(column_names, axis=1, inplace=False)
            return df

    # end method definition

    def keep_columns(self, column_names: list, inplace: bool = True) -> pd.DataFrame:
        """Keep only selected columns from the Data Frame. Drop the rest.

        Args:
            column_names (list): list of column names to keep.
            inplace (bool, optional): If the keeping should be inplace, i.e. modifying self._df.
                                      Defaults to True.
        Returns:
            pd.DataFrame: New DataFrame (if inplace = False) or self._df (if inplace = True)
        """

        if not all(column_name in self._df.columns for column_name in column_names):
            # Reduce the column names to those that really exist in the DataFrame:
            column_names = [
                column_name
                for column_name in column_names
                if column_name in self._df.columns
            ]
            logger.warning(
                "Reduce to these columns -> %s that do exist in the Data Frame.",
                column_names,
            )

        if inplace:
            # keep only those columns which are in column_names:
            if column_names != []:
                self._df = self._df[column_names]
            return self._df
        else:
            # keep only those columns which are in column_names:
            if column_names != []:
                df = self._df[column_names]
                return df
            return None

    # end method definition

    def cleanse(self, cleansings: dict):
        """Cleanse data with regular expressions and upper/lower case conversion.

        Args:
            cleansings (dict): Dictionary with keys that equal the column names.
                               The dictionary values are dictionaries itself with
                               these fields:
                               * replacements (dict): name of a column in the data frame
                               * upper (bool): change the value to uppercase
                               * lower (bool): change the value to lowercase
                            Example:
                                cleansings = {
                                    "airportName": {
                                        "upper": true
                                        "replacements" : {
                                            "-": " ",  # replace hypen with space
                                            ",\s*": " ",  # remove commas followed by on or more spaces with a single space
                                            "\s+$": "", # remove trailing spaces at the end of the name
                                            "^\s+": "", # remove spaces at the beginning of the name
                                        }
                                        "length": 10
                                    }
                                    "airportId": {
                                        "upper": true
                                        "replacements" : {
                                            "K(.{3})": "\1", # if the airport has 4 charters and starts with a 'K' we remove the 'K'
                                            "\/": "", # remove forward slashes - this helps to have consistency with N/A, NA, n/a, na
                                        }
                                    }
                                }
        """

        # Iterate over each column in regex_dict
        for column, cleansing in cleansings.items():
            # "colum" is the name of the field we want to cleanse.
            # "cleansing" is a dict with
            if "." in column:
                # Handle columns with subfields
                main_field, sub_field = column.split(".")
                if not main_field in self._df.columns:
                    continue
                # we use the additional parameters for lambda (beside x)
                # to avoid linter warning W0640
                self._df[main_field] = self._df[main_field].apply(
                    lambda x, sub_field=sub_field, cleansing=cleansing: self._cleanse_subfield(
                        data=x,
                        sub_field=sub_field,
                        replacements=cleansing.get("replacements", {}),
                        upper=cleansing.get("upper", False),
                        lower=cleansing.get("lower", False),
                        length=cleansing.get("length", 0),
                    )
                )
            else:
                if not column in self._df.columns:
                    continue

                logger.debug("\nBEFORE:\n%s\n", self._df[column])

                if cleansing.get("upper", False) and self._df[column].dtype == "object":
                    self._df[column] = self._df[column].str.upper()
                if cleansing.get("lower", False) and self._df[column].dtype == "object":
                    self._df[column] = self._df[column].str.lower()

                # Handle regular columns. regexp_pattern is on the left side
                # of the colon, and replacement the string on the right side of
                # the colon:
                for regex_pattern, replacement in cleansing.get(
                    "replacements", {}
                ).items():
                    if not regex_pattern:
                        logger.error("Empty search / regexp pattern!")
                        continue
                    # \b is a word boundary anchor in regular expressions.
                    # It matches a position where one side is a word character
                    # (like a letter or digit) and the other side is a non-word character
                    # (like whitespace or punctuation). It's used to match whole words.
                    # We want to have this to e.g. not replace "INT" with "INTERNATIONAL"
                    # if the word is already "INTERNATIONAL". It is important
                    # that the \b ... \b enclosure is ONLY used if regex_pattern is NOT
                    # a regular expression but just a normal string.
                    # Check if the pattern does NOT contain any regex special characters
                    # (excluding dot and ampersand) and ONLY then use \b ... \b
                    # Special regexp characters include: ^ $ * + ? ( ) [ ] { } | \
                    if not re.search(r"[\\^$*+?()|[\]{}]", regex_pattern):
                        # Wrap with word boundaries for whole-word matching
                        regex_pattern = rf"\b{regex_pattern}\b"
                    self._df[column] = self._df[column].str.replace(
                        pat=regex_pattern, repl=replacement, regex=True
                    )

                if (
                    cleansing.get("length", 0) > 0
                    and self._df[column].dtype == "object"
                ):
                    self._df[column] = self._df[column].str.slice(
                        0, cleansing["length"]
                    )

                logger.debug("\nAFTER:\n%s\n", self._df[column])

    # end method definition

    def _cleanse_subfield(
        self,
        data: list | dict,
        sub_field: str,
        replacements: dict,
        upper: bool,
        lower: bool,
        length: int = 0,
    ) -> list | dict:
        """Helper function to cleanse subfield data

        Args:
            data (list | dict): sub data - either a list of dictionaries or a dictionary
            sub_field (str): defines which field in the sub data should be updated
            regex_replacements (dict): Dictionary of regular expressions
            upper (bool): if True transform value in subfield to upper-case
            lower (bool): if True, transform value in subfield to lower-case
            length (int, optional): maximum length of the strings
        Returns:
            list | dict: Updated data
        """

        if isinstance(data, list):
            # If data is a list, apply cleansing to each dictionary in the list
            for i, item in enumerate(data):
                if (
                    item is not None
                    and sub_field in item
                    and not pd.isnull(item[sub_field])
                ):
                    if upper:
                        item[sub_field] = item[sub_field].upper()
                    elif lower:
                        item[sub_field] = item[sub_field].lower()
                    for regex_pattern, replacement in replacements.items():
                        if replacement:
                            regex_pattern = rf"\b{regex_pattern}\b"
                        item[sub_field] = re.sub(
                            regex_pattern, replacement, item[sub_field]
                        )
                    if length > 0:
                        item[sub_field] = item[sub_field][:length]
                data[i] = item
        elif isinstance(data, dict):
            # If data is a dictionary, apply cleansing directly to the subfield
            if sub_field in data and not pd.isnull(data[sub_field]):
                if upper:
                    data[sub_field] = data[sub_field].upper()
                elif lower:
                    data[sub_field] = data[sub_field].lower()
                for regex_pattern, replacement in replacements.items():
                    if replacement:
                        regex_pattern = rf"\b{regex_pattern}\b"
                    data[sub_field] = re.sub(
                        regex_pattern, replacement, data[sub_field]
                    )
                if length > 0:
                    data[sub_field] = data[sub_field][:length]
        return data

    # end method definition

    def filter(self, conditions: list, inplace: bool = True) -> pd.DataFrame:
        """Filter the DataFrame based on (multiple) conditions.

        Args:
            conditions (list): Conditions are a list of dictionaries with 3 items:
                               * field (str): name of a column in the data frame
                               * value (str or list): expected value (filter criterium).
                                                      If it is a list then one of
                                                      the list elements must match the field value (OR)
                               * regex (bool): this flag controls if the value is interpreted as a
                                               regular expression. If there is no regex item in the
                                               dictionary then the default is False (= values is NOT regex).
                               If there are multiple conditions in the list each has to evaluate to True (AND)
            inplace (bool, optional): Defines if the self._df is modified (inplace) or just
                                      a new DataFrame is returned. Defaults to True.
        Returns:
            pd.DataFrame: new data frame or pointer to self._df (depending on the value of 'inplace')
        """

        if self._df is None:
            logger.error("DataFrame is not initialized.")
            return None

        if self._df.empty:
            logger.error("DataFrame is empty.")
            return None

        # first filtered_df is the full DataFreame.
        # then it is subsequentially reduced by each condition
        # at the end it is just those rows that match all conditions.
        filtered_df = self._df

        # We traverse a list of conditions. Each condition must evaluate to true
        # otherwise the current workspace or document (i.e. the data set for these objects)
        # will be skipped. The variable filtered_df is
        for condition in conditions:
            field = condition.get("field", None)
            if not field:
                logger.error("Missing value for filter condition 'field' in payload!")
                continue
            if field not in self._df.columns:
                logger.warning(
                    "Filter condition field -> '%s' does not exist as column in data frame! Data frame has these columns -> %s",
                    field,
                    str(self._df.columns),
                )
                continue  # Skip filtering for columns not present in DataFrame
            value = condition.get("value", None)
            if not value:
                logger.error(
                    "Missing filter value of for filter condition field -> '%s'!", field
                )
                continue
            regex = condition.get("regex", False)

            logger.info(
                "Data Frame has %s row(s) and %s column(s) before filter -> %s has been applied.",
                filtered_df.shape[0],
                filtered_df.shape[1],
                str(condition),
            )

            filtered_dfs = []

            # if a single string is passed as value we put
            # it into an 1-item list to simplify the following code:
            if not isinstance(value, list):
                value = [value]

            # multiple values are treated like a logical "or" condition
            for value_item in value:
                if regex:
                    filtered_dfs.append(
                        filtered_df[
                            ~filtered_df[field].isna()
                            & filtered_df[field].str.contains(value_item, regex=True)
                        ]
                    )
                else:
                    result_df = filtered_df[
                        ~filtered_df[field].isna() & filtered_df[field].eq(value_item)
                    ]
                    if not result_df.empty:
                        filtered_dfs.append(result_df)
            # end for values

            if not filtered_dfs:
                logger.warning(
                    "Filter with field -> '%s' and value -> '%s' delivered an empty Data Frame",
                    field,
                    str(value),
                )
                filtered_df.drop(filtered_df.index, inplace=True)
            else:
                # Concatenate the filtered DataFrames for each value in the list
                filtered_df = pd.concat(filtered_dfs, ignore_index=True)

            logger.info(
                "Data Frame has %s row(s) and %s column(s) after filter -> %s has been applied.",
                filtered_df.shape[0],
                filtered_df.shape[1],
                str(condition),
            )
        # end for condition

        if inplace:
            self._df = filtered_df

        return filtered_df

    # end method definition

    def fill_na_in_column(self, column_name: str, default_value: str | int):
        """Replace NA values in a column with a defined new default value

        Args:
            column_name (str): name of the column in the DataFrame
            default_value (str | int): value to replace NA with
        """

        if column_name in self._df.columns:
            self._df[column_name] = self._df[column_name].fillna(value=default_value)
        else:
            logger.error(
                "Cannot replace NA values as column -> '%s' does not exist in the Data Frame! Data Frame has these columns -> %s",
                column_name,
                str(self._df.columns),
            )

    # end method definition

    def fill_forward(self, inplace: bool) -> pd.DataFrame:
        """Fill the missing cells appropriately by carrying forward
           the values from the previous rows where necessary.
           This has applications if a hierarchy is represented by
           nested cells e.g. in an Excel sheet.

        Args:
            inplace (bool): Should the modification happen inplace or not.

        Returns:
            pd.DataFrame: Resulting dataframe
        """

        # To convert an Excel representation of a folder structure with nested
        # columns into a format appropriate for Pandas,
        # where all cells should be filled
        df_filled = self._df.ffill(inplace=inplace)

        return df_filled

    # end method definition

    def lookup_value(
        self, lookup_column: str, lookup_value: str, separator: str = "|"
    ) -> pd.Series | None:
        """Lookup a row that includes a lookup value in the value of a given column.

        Args:
            lookup_column (str): name of the column to search in
            lookup_value (str): value to search for
            separator (str): string list delimiter / separator

        Returns:
            pd.Series | None: data frame row that matches or None if no match was found.
        """

        # Use the `apply` function to filter rows where the lookup value matches a whole item in the comma-separated list
        def match_lookup_value(string_list: str) -> bool:
            """Spilt delimiter-separated list into a python list

            Args:
                string_list (str): delimiter-separated string list like "a, b, c" or "a | b | c"

            Returns:
                bool: True if lookup_value is equal to one of the delimiter-separated terms
            """
            # Ensure that the string is a string
            string_list = str(string_list)

            return lookup_value in [
                item.strip() for item in string_list.split(separator)
            ]

        df = self._df

        if self._df is None:
            return None

        if lookup_column not in self._df.columns:
            logger.error(
                "Column -> '%s' does not exist in the Data Frame! Data Frame has these columns -> %s",
                lookup_column,
                str(self._df.columns),
            )
            return None

        # Fill NaN or None values in the lookup column with empty strings
        df[lookup_column] = df[lookup_column].fillna("")

        # Use the `apply` function to filter rows where the lookup value is in the Synonyms list
        matched_row = df[df[lookup_column].apply(match_lookup_value)]

        # Return the first matched row, if any
        if not matched_row.empty:
            return matched_row.iloc[0]

        return None

    # end method definition

    def add_column(
        self,
        source_column: str,
        reg_exp: str,
        new_column: str,
        prefix="",
        suffix="",
        length: int | None = None,
        group_chars: int | None = None,
        group_separator: str = ".",
        group_remove_leading_zero: bool = True,
    ) -> bool:
        """Add additional column to the data frame.

        Args:
            source_column (str): name of the source column
            reg_exp (str): regular expression to apply on the content of the source column
            new_column (str): name of the column to add
            prefix (str, optional): Prefix to add in front of the value. Defaults to "".
            suffix (str, optional): Suffix to add at the end of the value. Defaults to "".
            length (int | None, optional): Length to reduce to. Defaults to None (= unlimited).
            group_chars (int | None, optional): group the resulting string in characters of group_chars. Defaults to None.
                                                Usable e.g. for thousand seperator "."
            group_separator (str, optional): Separator string for the grouping. Defaults to ".".
            group_remove_leading_zero (bool, optional): Remove leading zeros from the groups. Defaults to True.

        Returns:
            bool: True = Success, False = Failure
        """

        if self._df is None:
            return False

        # Use str.extract to apply the regular expression to the source column
        # and then assign this modified colum to the variable extracted:
        extracted = self._df[source_column].str.extract(pat=reg_exp, expand=False)

        # Limit the result to the specified length
        if length is not None:
            extracted = extracted.str[:length]

        if group_chars is not None:

            def process_grouping(x):
                if pd.isna(x):
                    return x
                # Split into groups
                groups = [x[i : i + group_chars] for i in range(0, len(x), group_chars)]
                if group_remove_leading_zero:
                    # Remove leading zeros from each group
                    groups = [group.lstrip("0") or "0" for group in groups]
                # Join groups with separator
                return group_separator.join(groups)

            extracted = extracted.apply(process_grouping)

        # Add prefix and suffix
        if prefix or suffix:
            extracted = prefix + extracted.astype(str) + suffix

        self._df[new_column] = extracted

        return True

    # end method definition

    def convert_to_lists(self, columns: list, delimiter: str = ","):
        """Method to intelligently convert strings to lists, with a configurable delimiter,
           ignoring delimiters inside quotes

        Args:
            columns (list): name of the columns whose values should be converted to lists.
                            It is expected that
            delimiter (str, optional): Character that delimits list items. Defaults to ",".

        Returns:
            None. self._df is modified in place.
        """

        # Regex to split by the delimiter, ignoring those inside quotes or double quotes
        def split_string_ignoring_quotes(s, delimiter):
            # Escaping the delimiter in case it's a special regex character
            delimiter = re.escape(delimiter)
            # Match quoted strings and unquoted delimiters separately
            pattern = rf'(?:"[^"]*"|\'[^\']*\'|[^{delimiter}]+)'
            return re.findall(pattern, s)

        for col in columns:
            self._df[col] = self._df[col].apply(
                lambda x: (
                    split_string_ignoring_quotes(x, delimiter)
                    if isinstance(x, str) and delimiter in x
                    else x
                )
            )

    # end method definition

    def add_column_list(self, source_columns: list, new_column: str):
        """Add a column with list objects. The list items are taken from a list of
           source columns (row by row).

        Args:
            source_columns (list): column names the list values are taken from
            new_column (str): name of the new column
        Returns:
            None. self._df is modified in place.
        """

        def create_list(row):
            return [row[col] for col in source_columns]

        self._df[new_column] = self._df.apply(create_list, axis=1)

    # end method definition

    def add_column_table(
        self, source_columns: list, new_column: str, delimiter: str = ","
    ):
        """Add a column with tabular objects (list of dictionaris). The
           source columns should include lists. The resulting dictionary
           keys are the column names for the source columns.

           Example:
           X[1] = 1, 2, 3
           Y[1] = A, B, C
           X[2] = 4, 5, 6
           Y[2] = D, E, F

           Table[1] = [
                {
                    "X": "1"
                    "Y": "A"
                },
                {
                    "X": "2"
                    "Y": "B"
                }
                {
                    "X": "3"
                    "Y": "C"
                }
           ]
           Table[2] = [
                {
                    "X": "4"
                    "Y": "D"
                },
                {
                    "X": "5"
                    "Y": "E"
                }
                {
                    "X": "6"
                    "Y": "F"
                }
           ]

        Args:
            source_columns (list): column names the list values are taken from
            new_column (str): name of the new column
            delimiter (str, optional): Character that delimits list items. Defaults to ",".

        Returns:
            None. self._df is modified in place.
        """

        # Call the convert_to_lists method to ensure the columns are converted
        self.convert_to_lists(columns=source_columns, delimiter=delimiter)

        # Sub-method to pad lists to the same length
        def pad_list(lst: list, max_len: int):
            return lst + [None] * (max_len - len(lst))

        def create_table(row) -> list:
            max_len = max(
                len(row[col]) if isinstance(row[col], list) else 1
                for col in source_columns
            )

            # Pad lists to the maximum length, leave scalars as they are
            for col in source_columns:
                if isinstance(row[col], list):
                    row[col] = pad_list(row[col], max_len)
                else:
                    if not pd.isna(row[col]):
                        row[col] = [
                            row[col]
                        ] * max_len  # Repeat scalar to match the max length
                    else:
                        row[col] = [None] * max_len
            # Create a list of dictionaries for each row
            table = []
            for i in range(max_len):
                table.append({col: row[col][i] for col in source_columns})
            return table

        # Apply the function to create a new column with a table
        self._df[new_column] = self._df.apply(create_table, axis=1)

    # end method definition
