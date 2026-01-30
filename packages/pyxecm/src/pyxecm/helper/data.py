"""Data Module leveraging Pandas to manipulte data sets read for bulk generation of Content Server items.

See: https://pandas.pydata.org

This code implements a class called "Data" which is a wrapper
to Pandas data frame.
"""

from __future__ import annotations  # to allow using `Data` within class definitions

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import json
import logging
import os
import re
import threading
from io import StringIO

import pandas as pd
import requests

default_logger = logging.getLogger("pyxecm.helper.data")


class Data:
    """Used to handle big data sets that have a tabular structure."""

    # Only class variables or class-wide constants should be defined here:

    logger: logging.Logger = default_logger

    @classmethod
    def read_sql(
        cls,
        sql: str,
        con: any,
        columns: list[str] | None = None,
        dtypes: dict[str, type | str] | None = None,
        index_columns: str | list[str] | None = None,
        **kwargs: dict,
    ) -> Data:
        """Load a Data object directly from a SQL table/query.

        Args:
            sql (str):
                SQL query string or SQLAlchemy Table.
            con (any):
                Database connection or engine.
            columns (list[str] | None):
                List of columns to load. Defaults to all.
            dtypes (dict[str, type | str] | None):
                Column dtype dictionary (NumPy/Pandas types or strings).
            index_columns (str | list[str] | None, optional):
                The name of the column that should become the index
                of the data frame. Defaults to None.
                Also a list of column names can be provided to create
                a multi-index.
            **kwargs (dict):
                Extra kwargs passed to pd.read_sql.

        """
        df = pd.read_sql(sql, con=con, columns=columns, **kwargs)
        return cls(init_data=df, dtypes=dtypes, index_columns=index_columns)

    def __init__(
        self,
        init_data: pd.DataFrame | list = None,
        columns: list[str] | None = None,
        dtypes: dict[str, type] | None = None,
        index_columns: str | list[str] | None = None,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the Data object.

        Args:
            init_data (pd.DataFrame | list, optional):
                Data to initialize the data frame. Can either be
                another data frame (that gets copied) or a list of dictionaries.
                Defaults to None.
            columns (list[str] | None, optional):
                The list of column names to use if init_data is None.
                Defaults to None.
            dtypes (dict[str, type] | None, optional):
                A dictionary defining the data types for specific columns.
                The keys are the column names and the values are the desired data types.
                Defaults to None. In this case pandas will infer the data types automatically.
            index_columns (str | list[str] | None, optional):
                The name of the column that should become the index
                of the data frame. Defaults to None.
                Also a list of column names can be provided to create
                a multi-index.
            logger (logging.Logger, optional):
                Pass a special logging object. This is optional. If not provided,
                the default logger is used.

        """

        if logger != default_logger:
            self.logger = logger.getChild("data")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        self._lock: threading.Lock = threading.Lock()

        self._schema = dtypes

        if init_data is None:
            self._df = pd.DataFrame(columns=columns)
        elif isinstance(init_data, pd.DataFrame):
            self._df = init_data.copy()
        elif isinstance(init_data, Data):
            self._df = init_data.get_data_frame().copy()
        elif isinstance(init_data, list):
            self._df = pd.DataFrame(init_data)
        elif isinstance(init_data, dict):
            self._df = pd.DataFrame([init_data])
        else:
            error_message = "Illegal initialization data for 'Data' class!"
            raise TypeError(error_message)

        # Apply dtypes if given
        self._schema = dtypes
        if self._schema:
            for col, dtype in self._schema.items():
                if col in self._df.columns:
                    self._df[col] = self._df[col].astype(dtype)

        # set index if specified
        if index_columns:
            # convert single string to list for uniformity
            if isinstance(index_columns, str):
                self._index_columns = [index_columns]
            else:
                self._index_columns = index_columns

            # check that all index columns exist in the DataFrame
            missing_cols = [col for col in self._index_columns if col not in self._df.columns]
            if missing_cols:
                msg = f"Cannot set index. Missing columns in DataFrame: {missing_cols}"
                raise ValueError(msg)

            # set the index
            self._df.set_index(self._index_columns, inplace=True, drop=False)
        else:
            self._index_columns = None

    # end method definition

    def __len__(self) -> int:
        """Return lenght of the embedded Pandas data frame object.

        This is basically a convenience method.

        Returns:
            int:
                Lenght of the data frame.

        """

        if self._df is not None:
            return len(self._df)
        return 0

    # end method definition

    def __str__(self) -> str:
        """Print the Pandas data frame object.

        Returns:
            str:
                String representation.

        """

        # if data frame is initialized we return
        # the string representation of pd.DataFrame
        if self._df is not None:
            return str(self._df)

        return str(self)

    # end method definition

    def __getitem__(self, column: str) -> pd.Series:
        """Return the column corresponding to the key from the data frame.

        Args:
            column (str):
                The name of the data frame column. This can also be used
                to filter by a mask, e.g. data['column_name'] == 'value'

        Returns:
            pd.Series:
                The column of the data frame with the given name.

        """

        if self._df is None or self._df.empty:
            msg = "Data frame is empty or not initialized!"
            raise KeyError(msg)

        return self._df[column]

    # end method definition

    def __getattr__(self, attr: str) -> any:
        """Delegate attribute access to the internal pandas DataFrame.

        This method is only called if the attribute is not found
        on the Data instance itself. It allows the Data class to
        behave like a pandas DataFrame for most attributes.

        Args:
            attr (str): The attribute name being accessed.

        Returns:
            Any: The corresponding attribute from the internal DataFrame.

        Raises:
            AttributeError: If the attribute is not present on the DataFrame.

        """

        if self._df is None:
            error_message = "'Data' object has no attribute -> '{}' (internal DataFrame is None)".format(attr)
            raise AttributeError(error_message)

        try:
            return getattr(self._df, attr)
        except AttributeError:
            self.logger.error("'Data' object has no attribute -> '%s'", attr)
            raise

    # end method definition

    def lock(self) -> threading.Lock:
        """Return the threading lock object.

        Returns:
            threading.Lock: The threading lock object.

        """

        return self._lock

    # end method definition

    def get_data_frame(self) -> pd.DataFrame:
        """Get the Pandas data frame object.

        Returns:
            pd.DataFrame: The Pandas data frame object.

        """

        return self._df

    # end method definition

    def set_data_frame(self, df: pd.DataFrame) -> None:
        """Set the Pandas data frame object.

        Args:
            df (pd.DataFrame): The new Pandas data frame object.

        """

        self._df = df

    # end method definition

    def get_columns(self) -> list | None:
        """Get the list of column names of the data frame.

        Returns:
            list | None:
                The list of column names in the data frame.

        """

        if self._df is None:
            return None

        return self._df.columns

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
    ) -> None:
        """Log information about the data frame.

        Args:
            show_size (bool, optional):
                Show size of data frame. Defaults to True.
            show_info (bool, optional):
                Show information for data frame. Defaults to False.
            show_columns (bool, optional):
                Show columns of data frame. Defaults to False.
            show_first (bool, optional):
                Show first N items. Defaults to False. N is defined
                by the row_num parameter.
            show_last (bool, optional):
                Show last N items. Defaults to False. N is defined
                by the row_num parameter.
            show_sample (bool, optional):
                Show N sample items. Defaults to False. N is defined
                by the row_num parameter.
            show_statistics (bool, optional):
                Show data frame statistics. Defaults to False.
            row_num (int, optional):
                Used as the number of rows printed using show_first,
                show_last, show_sample. Default is 10.

        """

        if self._df is None:
            self.logger.warning("Data frame is not initialized!")
            return

        if show_size:
            self.logger.info(
                "Data frame has %s row(s) and %s column(s)",
                self._df.shape[0],
                self._df.shape[1],
            )

        if show_info:
            # df.info() can not easily be embedded into a string
            self._df.info()

        if show_columns:
            self.logger.info("Columns:\n%s", self._df.columns)
            self.logger.info(
                "Columns with number of NaN values:\n%s",
                self._df.isna().sum(),
            )
            self.logger.info(
                "Columns with number of non-NaN values:\n%s",
                self._df.notna().sum(),
            )

        if show_first:
            # the default for head is n = 5:
            self.logger.info("First %s rows:\n%s", str(row_num), self._df.head(row_num))

        if show_last:
            # the default for tail is n = 5:
            self.logger.info("Last %s rows:\n%s", str(row_num), self._df.tail(row_num))

        if show_sample:
            # the default for sample is n = 1:
            self.logger.info(
                "%s Sample rows:\n%s",
                str(row_num),
                self._df.sample(n=row_num),
            )

        if show_statistics:
            self.logger.info(
                "Description of statistics for data frame:\n%s",
                self._df.describe(),
            )
            self.logger.info(
                "Description of statistics for data frame (transformed):\n%s",
                self._df.describe().T,
            )
            self.logger.info(
                "Description of statistics for data frame (objects):\n%s",
                self._df.describe(include="object"),
            )

    # end method definition

    def append(self, add_data: pd.DataFrame | list | dict | Data) -> bool:
        """Append additional data to the data frame.

        Behavior:
        - If self._schema is None:
            -> pandas-native dynamic behavior (no dtype guarantees)
        - If self._schema is not None:
            -> strict schema mode (dtype preserved + enforced)

        Args:
            add_data (pd.DataFrame | list | dict | Data):
                Additional data. Can be pd.DataFrame or list of dicts (or Data).

        Returns:
            bool:
                True = Success, False = Error

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
                if df is not None and not df.empty:
                    self._df = pd.concat([self._df, df], ignore_index=True)
                return True
            elif isinstance(add_data, list):
                if add_data:
                    df = Data(add_data, logger=self.logger)
                    self._df = pd.concat(
                        [self._df, df.get_data_frame()],
                        ignore_index=True,
                    )
                return True
            elif isinstance(add_data, dict):
                if add_data:
                    # it is important to wrap the dict in a list to avoid that more than 1 row is created
                    df = Data([add_data], logger=self.logger)
                    self._df = pd.concat(
                        [self._df, df.get_data_frame()],
                        ignore_index=True,
                    )
                return True
            else:
                self.logger.error("Illegal data type -> '%s'", type(add_data))
                return False
        elif isinstance(add_data, pd.DataFrame):
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
            self.logger.error("Illegal data type -> '%s'", type(add_data))
            return False

    # end method definition

    def append_with_schema(self, add_data: pd.DataFrame | list | dict | Data) -> bool:
        """Append data to the Data object, enforcing schema and preserving index.

        Args:
            add_data: pd.DataFrame, list of dicts, dict, or another Data object.

        Returns:
            True if append succeeded, False if an error occurred.

        """
        try:
            # 1️⃣ Normalize input to DataFrame
            if isinstance(add_data, Data):
                new_df = add_data.get_data_frame()
            elif isinstance(add_data, pd.DataFrame):
                new_df = add_data
            elif isinstance(add_data, list):
                if not add_data:
                    return True
                new_df = pd.DataFrame(add_data)
            elif isinstance(add_data, dict):
                new_df = pd.DataFrame([add_data])
            else:
                self.logger.error("Illegal data type -> '%s'", type(add_data))
                return False

            # 2️⃣ Align columns to schema and enforce dtypes
            if self._schema is not None:
                new_df = new_df.reindex(columns=self._schema.keys()).astype(self._schema)

            # 3️⃣ Set index on the new data
            if self._index_columns is not None:
                new_df.set_index(self._index_columns, inplace=True, drop=False)

            # 4️⃣ Initialize or append
            if self._df is None or self._df.empty:
                self._df = new_df
            else:
                self._df = pd.concat([self._df, new_df], ignore_index=False)

        except Exception as e:
            self.logger.error("Append with schema failed; error -> %s", e)
            return False
        else:
            return True

    # end method definition

    def merge(
        self,
        merge_data: pd.DataFrame,
        on: str | list[str] | None = None,
        how: str = "inner",
        left_on: str | list[str] | None = None,
        right_on: str | list[str] | None = None,
        left_index: bool = False,
        right_index: bool = False,
        suffixes: tuple[str, str] = ("_x", "_y"),
        indicator: bool = False,
        validate: str | None = None,
    ) -> pd.DataFrame | None:
        """Merge the current DataFrame (_df) with another DataFrame.

        Args:
            merge_data (pd.DataFrame | Data):
                The DataFrame to merge with.
            on (str | list[str]):
                Column(s) to merge on. Defaults to None.
            how (str, optional):
                Type of merge ('inner', 'outer', 'left', 'right', 'cross'). Defaults to 'inner'.
            left_on (str | list[str] | None, optional):
                Column(s) from self._df to merge on. Defaults to None.
            right_on (str | list[str] | None, optional):
                Column(s) from other DataFrame to merge on. Defaults to None.
            left_index (str | list[str], optional):
                 Whether to merge on the index of self._df. Defaults to False.
            right_index (bool, optional):
                Whether to merge on the index of other. Defaults to False.
            suffixes (tuple[str, str]):
                Suffixes for overlapping column names. Defaults to ('_x', '_y').
            indicator (bool, optional):
                If True, adds a column showing the merge source. Defaults to False.
            validate ():
                If provided, checks merge integrity
                ('one_to_one', 'one_to_many', 'many_to_one', 'many_to_many'). Defaults to None.

        Returns:
            The merged DataFrame or None in case of an error.

        Exceptions:
            ValueError: If `other` is not a DataFrame.
            KeyError: If required columns for merging are missing.
            ValueError: If `validate` check fails.

        """

        if self._df is None or self._df.empty:
            self._df = merge_data

        if isinstance(merge_data, Data):
            merge_data = merge_data.get_data_frame()  # Extract DataFrame from Data instance

        try:
            return self._df.merge(
                merge_data,
                how=how,
                on=on,
                left_on=left_on,
                right_on=right_on,
                left_index=left_index,
                right_index=right_index,
                suffixes=suffixes,
                indicator=indicator,
                validate=validate,
            )
        except KeyError:
            self.logger.error("Column(s) not found for merging!")
        except ValueError:
            self.logger.error("Invalid merge operation!")

        return None

    # end method definition

    def strip(self, columns: list | None = None, inplace: bool = True) -> pd.DataFrame:
        """Strip leading and trailing spaces from specified columns in a data frame.

        Args:
            columns (list | None):
                The list of column names to strip. If None, it strips
                leading and trailing spaces from _all_ string columns.
            inplace (bool, optional):
                If True, the data modification is done in place, i.e.
                modifying the existing data frame of the object.
                If False, the data frame is copied and the copy is modified
                and returned.

        Returns:
            pd.DataFrame:
                The modified data frame with stripped columns.

        """

        df = self._df.copy() if not inplace else self._df

        if columns is None:
            # Strip spaces from all string columns
            df = df.apply(lambda x: x.str.strip() if x.dtype == "object" else x)
        else:
            # Strip spaces from specified columns
            for col in columns:
                if col in df.columns and df[col].dtype == "object":  # Check if the column exists and is of string type
                    df[col] = df[col].str.strip()

        if inplace:
            self._df = df

        return df

    # end method definition

    def load_json_data(
        self,
        json_path: str,
        convert_dates: bool = False,
        index_column: str | None = None,
        compression: str | None = None,
    ) -> bool:
        """Load JSON data into a Pandas data frame.

        Args:
            json_path (str):
                The path to the JSON file.
            convert_dates (bool, optional):
                Defines whether or not dates should be converted.
                The default is False = dates are NOT converted.
            index_column (str | None, optional):
                The Name of the column (i.e. JSON data field) that should
                become the index in the loaded data frame.
            compression (str | None):
                Remove a compression:
                * gzip (.gz)
                * bz2 (.bz2)
                * zip (.zip)
                * xz (.xz)
                The value for compression should not include the dot.
                Default is None = no compression.

        Returns:
            bool: False in case an error occured, True otherwise.

        """

        if not json_path:
            self.logger.error(
                "You have not specified a JSON path!",
            )
            return False

        # If compression is enabled the file path should have
        # the matching file name extension:
        if compression:
            compression = compression.lstrip(".")  # remove a dot prefix if present
            suffix = "." + compression if compression != "gzip" else "gz"
            if not json_path.endswith(suffix):
                json_path += suffix

        if not os.path.exists(json_path):
            self.logger.error(
                "Missing JSON file - you have not specified a valid path -> '%s'.",
                json_path,
            )
            return False

        # Load data from JSON file
        try:
            df = pd.read_json(
                path_or_buf=json_path,
                convert_dates=convert_dates,
                compression=compression,
            )

            if index_column and index_column not in df.columns:
                self.logger.error(
                    "Specified index column -> '%s' not found in the JSON data.",
                    index_column,
                )
                return False

            if index_column:
                df = df.set_index(keys=index_column)
            if self._df is None:
                self._df = df
            else:
                self._df = pd.concat([self._df, df], ignore_index=True)
            self.logger.info(
                "After loading JSON file -> '%s', the data frame has %s row(s) and %s column(s)",
                json_path,
                self._df.shape[0],
                self._df.shape[1],
            )
        except FileNotFoundError:
            self.logger.error(
                "JSON file -> '%s' not found. Please check the file path.",
                json_path,
            )
            return False
        except PermissionError:
            self.logger.error(
                "Missing permission to access the JSON file -> '%s'.",
                json_path,
            )
            return False
        except OSError:
            self.logger.error("An I/O error occurred!")
            return False
        except json.JSONDecodeError:
            self.logger.error(
                "Unable to decode JSON file -> '%s'",
                json_path,
            )
            return False
        except ValueError:
            self.logger.error("Invalid JSON input -> %s", json_path)
            return False
        except AttributeError:
            self.logger.error("Unexpected JSON data structure in file -> %s", json_path)
            return False
        except TypeError:
            self.logger.error("Unexpected JSON data type in file -> %s", json_path)
            return False
        except KeyError:
            self.logger.error("Missing key in JSON data in file -> %s", json_path)
            return False

        return True

    # end method definition

    def save_json_data(
        self,
        json_path: str,
        orient: str = "records",
        preserve_index: bool = False,
        index_column: str = "index",
        compression: str | None = None,
    ) -> bool:
        """Save JSON data from data frame to file.

        Args:
            json_path (str): The path to where the JSON file should be safed.
            orient (str, optional):
                The structure of the JSON. Possible values:
                * "records" (this is the default)
                * "columns"
                * "index"
                * "table"
                * "split"
            preserve_index (bool, optional):
                Defines if the index column of the data frame should be exported as well.
                The default is False (index is not exported).
            index_column (str, optional):
                The Name of the column (i.e. JSON data field) that should
                become the index in the loaded data frame. The default is "index".
            compression (str | None):
                Apply a compression:
                * gzip (.gz)
                * bz2 (.bz2)
                * zip (.zip)
                * xz (.xz)

        Returns:
            bool:
                False in case an error occured, True otherwise.

        """

        if not json_path:
            self.logger.error(
                "You have not specified a JSON path!",
            )
            return False

        # If compression is enabled the file path should have
        # the matching file name extension:
        if compression:
            suffix = "." + compression if compression != "gzip" else ".gz"
            if not json_path.endswith(suffix):
                json_path += suffix

        # Save data to JSON file
        try:
            if self._df is not None:
                if not os.path.exists(os.path.dirname(json_path)):
                    os.makedirs(os.path.dirname(json_path), exist_ok=True)

                # index parameter is only allowed if orient has one of the following values:
                if orient in ("columns", "index", "table", "split"):
                    self._df.to_json(
                        path_or_buf=json_path,
                        index=preserve_index,
                        orient=orient,
                        indent=2,
                        compression=compression,
                        date_format="iso",
                    )
                # In this case we cannot use the index parameter as this would give this error:
                # Value Error -> 'index=True' is only valid when 'orient' is 'split', 'table', 'index', or 'columns'
                # So we create a new column that preserves the original row IDs from the index. The nasme

                elif preserve_index:
                    df_with_index = self._df.reset_index(
                        names=index_column,
                        inplace=False,
                    )
                    df_with_index.to_json(
                        path_or_buf=json_path,
                        orient=orient,
                        indent=2,
                        compression=compression,
                        date_format="iso",
                    )
                else:
                    self._df.to_json(
                        path_or_buf=json_path,
                        orient=orient,
                        indent=2,
                        compression=compression,
                        date_format="iso",
                    )
            else:
                self.logger.warning(
                    "Data frame is empty. Cannot write it to JSON file -> '%s'.",
                    json_path,
                )
                return False
        except FileNotFoundError:
            self.logger.error(
                "File -> '%s' not found. Please check the file path.",
                json_path,
            )
            return False
        except PermissionError:
            self.logger.error(
                "Permission denied to access the file -> '%s'.",
                json_path,
            )
            return False
        except OSError:
            self.logger.error("An I/O error occurred accessing file -> %s", json_path)
            return False
        except ValueError:
            self.logger.error("Value error!")
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
        """Load Excel (xlsx) data into Pandas data frame.

        Supports xls, xlsx, xlsm, xlsb, odf, ods and odt file extensions
        read from a local filesystem or URL. Supports an option to read a
        single sheet or a list of sheets.

        Args:
            xlsx_path (str):
                The path to the Excel file to load.
            sheet_names (list | str | int, optional):
                Name or Index of the sheet in the Excel workbook to load.
                If 'None' then all sheets will be loaded.
                If 0 then first sheet in workbook will be loaded (this is the Default).
                If string then this is interpreted as the name of the sheet to load.
                If a list is passed, this can be a list of index values (int) or
                a list of strings with the sheet names to load.
            usecols (list | str, optional):
                A list of columns to load, specified by general column names in Excel,
                e.g. usecols='B:D', usecols=['A', 'C', 'F']
            skip_rows (int, optional):
                List of rows to skip on top of the sheet (e.g. to not read headlines)
            header (int | None, optional):
                Excel Row (0-indexed) to use for the column labels of the parsed data frame.
                If file contains no header row, then you should explicitly pass header=None.
                Default is 0.
            names (list, optional):
                A list of column names to use. Default is None.
            na_values (list, optional):
                A list of values in the Excel that should become the Pandas NA value.

        Returns:
            bool:
                False in case an error occured, True otherwise.

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
                # If multiple sheets from an Excel workbook are loaded,
                # then read_excel() returns a dictionary. The keys are
                # the names of the sheets and the values are the data frames.
                # As this class can only handle one data frame per object,
                # We handle this case by concatenating the different sheets.
                # If you don't want this make sure your Excel workbook has only
                # one sheet or use the "sheet_name" parameter to select the one(s)
                # you want to load.
                if isinstance(df, dict):
                    self.logger.info("Loading multiple Excel sheets from the workbook!")
                    multi_sheet_df = pd.DataFrame()
                    for sheet in df:
                        multi_sheet_df = pd.concat(
                            [multi_sheet_df, df[sheet]],
                            ignore_index=True,
                        )
                    df = multi_sheet_df
                if self._df is None:
                    self._df = df
                else:
                    self._df = pd.concat([self._df, df], ignore_index=True)
            except FileNotFoundError:
                self.logger.error(
                    "Excel file -> '%s' not found. Please check the file path.",
                    xlsx_path,
                )
                return False
            except PermissionError:
                self.logger.error(
                    "Missing permission to access the Excel file -> '%s'.",
                    xlsx_path,
                )
                return False
            except OSError:
                self.logger.error(
                    "An I/O error occurred while reading the Excel file -> '%s'",
                    xlsx_path,
                )
                return False
            except ValueError:
                self.logger.error(
                    "Invalid Excel input in file -> '%s'",
                    xlsx_path,
                )
                return False
            except AttributeError:
                self.logger.error("Unexpected data structure in file -> %s", xlsx_path)
                return False
            except TypeError:
                self.logger.error("Unexpected data type in file -> %s", xlsx_path)
                return False
            except KeyError:
                self.logger.error("Missing key in Excel data in file -> %s", xlsx_path)
                return False

        else:
            self.logger.error(
                "Missing Excel file -> '%s'. You have not specified a valid path!",
                xlsx_path,
            )
            return False

        return True

    # end method definition

    def save_excel_data(
        self,
        excel_path: str,
        sheet_name: str = "Pandas Export",
        index: bool = False,
        columns: list | None = None,
    ) -> bool:
        """Save the data frame to an Excel file, with robust error handling and logging.

        Args:
            excel_path (str):
                The file path to save the Excel file.
            sheet_name (str):
                The sheet name where data will be saved. Default is 'Sheet1'.
            index (bool, optional):
                Whether to write the row names (index). Default is False.
            columns (list | None, optional):
                A list of column names to write into the excel file.

        Returns:
            bool:
                True = success, False = error.

        """

        try:
            # Check if the directory exists
            directory = os.path.dirname(excel_path)
            if directory and not os.path.exists(directory):
                os.makedirs(directory)

            # Validate columns if provided
            if columns:
                existing_columns = [col for col in columns if col in self._df.columns]
                missing_columns = set(columns) - set(existing_columns)
                if missing_columns:
                    self.logger.warning(
                        "The following columns do not exist in the data frame and cannot be saved to Excel -> %s",
                        ", ".join(missing_columns),
                    )
                columns = existing_columns

            # Attempt to save the data frame to Excel:
            if self._df is None:
                self.logger.error(
                    "Cannot write Excel file -> '%s' from empty / non-initialized data frame!", excel_path
                )
            self._df.to_excel(
                excel_path,
                sheet_name=sheet_name,
                index=index,
                columns=columns or None,  # Pass None if no columns provided
            )
            self.logger.info(
                "Data frame saved successfully to Excel file -> '%s'.",
                excel_path,
            )

        except FileNotFoundError as fnf_error:
            self.logger.error("Cannot write data frame to Excel file -> '%s'; error -> %s", excel_path, str(fnf_error))
            return False
        except PermissionError as pe:
            self.logger.error("Cannot write data frame to Excel file -> '%s'; error -> %s", excel_path, str(pe))
            return False
        except ValueError as ve:
            self.logger.error("Cannot write data frame to Excel file -> '%s'; error -> %s", excel_path, str(ve))
            return False
        except OSError as ose:
            self.logger.error("Cannot write data frame to Excel file -> '%s'; error -> %s", excel_path, str(ose))
            return False

        return True

    # end method definition

    def load_csv_data(
        self,
        csv_path: str,
        delimiter: str = ",",
        names: list | None = None,
        header: int | None = 0,
        usecols: list | None = None,
        encoding: str = "utf-8",
    ) -> bool:
        """Load CSV (Comma separated values) data into data frame.

        Args:
            csv_path (str):
                The path to the CSV file.
            delimiter (str, optional, length = 1):
                The character used to delimit values. Default is "," (comma).
            names (list | None, optional):
                The list of column names. This is useful if file does not have a header line
                but just the data.
            header (int | None, optional):
                The index of the header line. Default is 0 (first line). None indicates
                that the file does not have a header line
            usecols (list | None, optional):
                There are three possible list values types:
                1. int:
                    These values are treated as column indices for columns to keep
                    (first column has index 0).
                2. str:
                    The names of the columns to keep. For this to work the file needs
                    either a header line (i.e. 'header != None') or the 'names'
                    parameter must be specified.
                3. bool:
                    The length of the list must match the number of columns. Only
                    columns that have a value of True are kept.
            encoding (str, optional):
                The encoding of the file. Default = "utf-8".

        Returns:
            bool:
                False in case an error occured, True otherwise.

        """

        if csv_path.startswith("http"):
            # Download file from remote location specified by the packageUrl
            # this must be a public place without authentication:
            self.logger.debug("Download CSV file from URL -> '%s'.", csv_path)

            try:
                response = requests.get(url=csv_path, timeout=1200)
                response.raise_for_status()
            except requests.exceptions.HTTPError:
                self.logger.error("HTTP error with -> %s", csv_path)
                return False
            except requests.exceptions.ConnectionError:
                self.logger.error("Connection error with -> %s", csv_path)
                return False
            except requests.exceptions.Timeout:
                self.logger.error("Timeout error with -> %s", csv_path)
                return False
            except requests.exceptions.RequestException:
                self.logger.error("Request error with -> %s", csv_path)
                return False

            self.logger.debug(
                "Successfully downloaded CSV file -> %s; status code -> %s",
                csv_path,
                response.status_code,
            )

            # Convert bytes to a string using utf-8 and create a file-like object
            csv_file = StringIO(response.content.decode(encoding))

        elif os.path.exists(csv_path):
            self.logger.debug("Using local CSV file -> '%s'.", csv_path)
            csv_file = csv_path

        else:
            self.logger.error(
                "Missing CSV file -> '%s' you have not specified a valid path!",
                csv_path,
            )
            return False

        # Load data from CSV file or buffer
        try:
            df = pd.read_csv(
                filepath_or_buffer=csv_file,
                delimiter=delimiter,
                names=names,
                header=header,
                usecols=usecols,
                encoding=encoding,
                skipinitialspace=True,
            )
            if self._df is None:
                self._df = df
            else:
                self._df = pd.concat([self._df, df], ignore_index=True)
        except FileNotFoundError:
            self.logger.error(
                "CSV file -> '%s' not found. Please check the file path.",
                csv_path,
            )
            return False
        except PermissionError:
            self.logger.error(
                "Permission denied to access the CSV file -> '%s'.",
                csv_path,
            )
            return False
        except OSError:
            self.logger.error("An I/O error occurred!")
            return False
        except ValueError:
            self.logger.error("Invalid CSV input in file -> %s", csv_path)
            return False
        except AttributeError:
            self.logger.error("Unexpected data structure in file -> %s", csv_path)
            return False
        except TypeError:
            self.logger.error("Unexpected data type in file -> %s", csv_path)
            return False
        except KeyError:
            self.logger.error("Missing key in CSV data -> %s", csv_path)
            return False

        return True

    # end method definition

    def load_xml_data(
        self,
        xml_path: str,
        xpath: str | None = None,
        xslt_path: str | None = None,
        encoding: str = "utf-8",
    ) -> bool:
        """Load XML data into a Pandas data frame.

        Args:
            xml_path (str):
                The path to the XML file to load.
            xpath (str, optional):
                An XPath to the elements we want to select.
            xslt_path (str, optional):
                An XSLT transformation file to convert the XML data.
            encoding (str, optional):
                The encoding of the file. Default is UTF-8.

        Returns:
            bool:
                False in case an error occured, True otherwise.

        """

        if xml_path.startswith("http"):
            # Download file from remote location specified by the packageUrl
            # this must be a public place without authentication:
            self.logger.debug("Download XML file from URL -> '%s'.", xml_path)

            try:
                response = requests.get(url=xml_path, timeout=1200)
                response.raise_for_status()
            except requests.exceptions.HTTPError:
                self.logger.error("HTTP error with -> %s", xml_path)
                return False
            except requests.exceptions.ConnectionError:
                self.logger.error("Connection error with -> %s", xml_path)
                return False
            except requests.exceptions.Timeout:
                self.logger.error("Timeout error with -> %s", xml_path)
                return False
            except requests.exceptions.RequestException:
                self.logger.error("Request error with -> %s", xml_path)
                return False

            self.logger.debug(
                "Successfully downloaded XML file -> '%s'; status code -> %s",
                xml_path,
                response.status_code,
            )
            # Convert bytes to a string using utf-8 and create a file-like object
            xml_file = StringIO(response.content.decode(encoding))

        elif os.path.exists(xml_path):
            self.logger.debug("Using local XML file -> '%s'.", xml_path)
            xml_file = xml_path

        else:
            self.logger.error(
                "Missing XML file -> '%s'. You have not specified a valid path or URL!",
                xml_path,
            )
            return False

        # Load data from XML file or buffer
        try:
            df = pd.read_xml(
                path_or_buffer=xml_file,
                xpath=xpath,
                stylesheet=xslt_path,
                encoding=encoding,
            )
            # Process the loaded data as needed
            if self._df is None:
                self._df = df
            else:
                self._df = pd.concat([self._df, df], ignore_index=True)
            self.logger.info("XML file -> '%s' loaded successfully!", xml_path)
        except FileNotFoundError:
            self.logger.error("XML file -> '%s' not found.", xml_path)
            return False
        except PermissionError:
            self.logger.error(
                "Missing permission to access the XML file -> '%s'.",
                xml_path,
            )
            return False
        except OSError:
            self.logger.error("An I/O error occurred loading from -> %s", xml_path)
            return False
        except ValueError:
            self.logger.error("Invalid XML data in file -> %s", xml_path)
            return False
        except AttributeError:
            self.logger.error("Unexpected data structure in XML file -> %s", xml_path)
            return False
        except TypeError:
            self.logger.error("Unexpected data type in XML file -> %s", xml_path)
            return False
        except KeyError:
            self.logger.error("Missing key in XML file -> %s", xml_path)
            return False

        return True

    # end method definition

    def load_directory(self, path_to_root: str) -> bool:
        """Load directory structure into Pandas data frame.

        Args:
            path_to_root (str):
                Path to the root element of the directory structure.

        Returns:
            bool: True = Success, False = Failure

        """

        try:
            # Check if the provided path is a directory
            if not os.path.isdir(path_to_root):
                self.logger.error(
                    "The provided path -> '%s' is not a valid directory.",
                    path_to_root,
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
                    entry = {"level {}".format(i): part for i, part in enumerate(path_parts[:-1], start=1)}

                    entry.update(
                        {
                            "filename": path_parts[-1],
                            "size": file_size,
                            "path": path_parts[1:-1],
                            "relative_path": relative_path,
                            "download_dir": root,
                        },
                    )
                    data.append(entry)

            # Create data frame from list of dictionaries:
            self._df = pd.DataFrame(data)

            # Determine the maximum number of levels
            max_levels = max((len(entry) - 2 for entry in data), default=0)

            # Ensure all entries have the same number of levels:
            for entry in data:
                for i in range(1, max_levels + 1):
                    entry.setdefault("level {}".format(i), "")

            # Convert to data frame again to make sure all columns are consistent:
            self._df = pd.DataFrame(data)

        except NotADirectoryError:
            self.logger.error(
                "Provided path -> '%s' is not a directory!",
                path_to_root,
            )
            return False
        except FileNotFoundError:
            self.logger.error(
                "Provided path -> '%s' does not exist in file system!",
                path_to_root,
            )
            return False
        except PermissionError:
            self.logger.error(
                "Permission error accessing path -> '%s'!",
                path_to_root,
            )
            return False

        return True

    # end method definition

    def load_xml_directory(
        self,
        path_to_root: str,
        xpath: str | None = None,
        xml_files: list | None = None,
    ) -> bool:
        """Load XML files from a directory structure into Pandas data frame.

        Args:
            path_to_root (str):
                Path to the root element of the directory structure.
            xpath (str, optional):
                XPath to the XML elements we want to select.
            xml_files (list | None, optional):
                Names of the XML files to load from the directory.

        Returns:
            bool:
                True = Success, False = Failure

        """

        # Establish a default if None is passed via the parameter:
        if not xml_files:
            xml_files = ["docovw.xml"]

        try:
            # Check if the provided path is a directory
            if not os.path.isdir(path_to_root):
                self.logger.error(
                    "The provided path -> '%s' is not a valid directory.",
                    path_to_root,
                )
                return False

            # Walk through the directory
            for root, _, files in os.walk(path_to_root):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_size = os.path.getsize(file_path)
                    file_name = os.path.basename(file_path)

                    if file_name in xml_files:
                        self.logger.info(
                            "Load XML file -> '%s' of size -> %s from -> '%s'...",
                            file_name,
                            file_size,
                            file_path,
                        )
                        success = self.load_xml_data(file_path, xpath=xpath)
                        if success:
                            self.logger.info(
                                "Successfully loaded XML file -> '%s'.",
                                file_path,
                            )

        except NotADirectoryError:
            self.logger.error(
                "Provided path -> '%s' is not a directory",
                path_to_root,
            )
            return False
        except FileNotFoundError:
            self.logger.error(
                "Provided path -> '%s' does not exist in file system!",
                path_to_root,
            )
            return False
        except PermissionError:
            self.logger.error(
                "Missing permission to access path -> '%s'",
                path_to_root,
            )
            return False

        return True

    # end method definition

    def load_web_links(
        self,
        url: str,
        common_data: dict | None = None,
        pattern: str = r"",
    ) -> list | None:
        """Get all linked file URLs on a given web page (url) that are following a given pattern.

        Construct a list of dictionaries based on this. This method is a helper method for load_web() below.

        Args:
            url (str):
                The web page URL.
            common_data (dict | None, optional):
                Fields that should be added to each dictionary item. Defaults to None.
            pattern (str, optional):
                Regular Expression. Defaults to r"".

        Returns:
            list | None:
                List of links on the web page that are complying with the given regular expression.

        """

        try:
            response = requests.get(url, timeout=300)
            response.raise_for_status()
        except requests.RequestException:
            self.logger.error("Failed to retrieve page at %s", url)
            return []

        # Find all file links (hyperlinks) on the page (no file extension assumed)
        # Example filename pattern: "al022023.public.005"
        file_links = re.findall(r'href="([^"]+)"', response.text)
        if not file_links:
            self.logger.warning("No file links found on the web page -> %s", url)
            return []

        result_list = []
        base_url = url if url.endswith("/") else url + "/"

        for link in file_links:
            data = common_data.copy() if common_data else {}

            # Construct the full URL
            full_url = base_url + link.lstrip("/")

            if pattern:
                # Filter by expected naming pattern for links
                match = re.search(pattern, link)
                if not match:
                    continue

                # Extract and assign groups if they exist
                # TODO(mdiefenb): these names are currently hard-coded
                # for the National Hurricane Center Dataset (NHC)
                if len(match.groups()) >= 1:
                    data["Code"] = match.group(1).upper()
                if len(match.groups()) >= 2:
                    data["Type"] = match.group(2)
                if len(match.groups()) >= 3:
                    data["Message ID"] = match.group(3)

            data["URL"] = full_url
            data["Filename"] = link

            result_list.append(data)

        return result_list

    # end method definition

    def load_web(
        self,
        values: list,
        value_name: str,
        url_templates: list,
        special_values: list | None = None,
        special_url_templates: dict | None = None,
        pattern: str = r"",
    ) -> bool:
        """Traverse years and bulletin types to collect all bulletin URLs.

        Args:
            values (list):
                List of values to travers over
            value_name (str):
                Dictionary key to construct an item in combination with a value from values
            url_templates (list):
                URLs to travers per value. The URLs should contain one {} that is
                replace by the current value.
            special_values (list | None, optional):
                List of vales (a subset of the other values list)
                that we want to handle in a special way. Defaults to None.
            special_url_templates (dict | None, optional):
                URLs for the special values. Defaults to None.
                The dictionary keys are the special values. The
                dictionary values are lists of special URLs with placeholders.
            pattern (str, optional):
                Regular expression to find the proper links on the page. Defaults to r"".

        Returns:
            bool:
                True for success, False in case of an error.

        """

        result_list = []

        # We have two nested for loops below. The out traverses over all placeholder values.
        # These could be the calendar years, e.g. [2003,...,2024]
        # The inner for loop traverses over the list of specified URLs. We can have multiple for
        # each value.

        # Do we have a list of placeholder values we want to iterate over?
        if values:
            # Traverse all values in the values list:
            for value in values:
                # Do we want a special treatment for this value (e.g. the current year)
                if value in special_values:
                    self.logger.debug("Processing special value -> '%s'...", value)
                    if value not in special_url_templates and str(value) not in special_url_templates:
                        self.logger.error(
                            "Cannot find key -> '%s' in special URL templates dictionary -> %s! Skipping...",
                            value,
                            str(special_url_templates),
                        )
                        continue
                    # If the dictionary uses string keys then we need to convert the value
                    # to a string as well to avoid key errors:
                    if str(value) in special_url_templates:
                        value = str(value)
                    special_url_template_list = special_url_templates[value]
                    for special_url_template in special_url_template_list:
                        # Now the value is inserted into the placeholder in the URL:
                        special_url = special_url_template.format(value)
                        common_data = {value_name: value} if value_name else None
                        result_list += self.load_web_links(
                            url=special_url,
                            common_data=common_data,
                            pattern=pattern,
                        )
                else:  # normal URLs
                    self.logger.info("Processing value -> '%s'...", value)
                    for url_template in url_templates:
                        # Now the value is inserted into the placeholder in the URL:
                        url = url_template.format(value)
                        common_data = {value_name: value} if value_name else None
                        result_list += self.load_web_links(
                            url=url,
                            common_data=common_data,
                            pattern=pattern,
                        )
        else:
            for url_template in url_templates:
                url = url_template.format(value)
                result_list += self.load_web_links(
                    url=url,
                    common_data=None,
                    pattern=pattern,
                )

        # Add the data list to the data frame:
        self.append(result_list)

        return True

    # end method definition

    def partitionate(self, number: int) -> list:
        """Partition a data frame into equally sized partitions.

        Args:
            number (int):
                The number of desired partitions.

        Returns:
            list:
                A list of created partitions.

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

        self.logger.info(
            "Data frame has -> %s elements. We split it into -> %s partitions with -> %s row%s and remainder -> %s...",
            str(size),
            str(number),
            str(partition_size),
            "s" if partition_size > 1 else "",
            str(remainder),
        )

        # Initialize a list to store partitions:
        partitions = []
        start_index = 0

        # Slice the data frame into equally sized partitions:
        for i in range(number):
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
            column_name (str):
                The column name to partition by.

        Returns:
            list | None:
                List of partitions or None in case of an error (e.g. column name does not exist).

        """

        if column_name not in self._df.columns:
            self.logger.error(
                "Cannot partitionate by column -> '%s'. Column does not exist in the data frame. Data frame has these columns -> %s",
                column_name,
                str(self._df.columns),
            )
            return None

        # Separate rows with NaN or None values in the specified column:
        nan_partitions = self._df[self._df[column_name].isna()]

        # Keep only rows where the specified column has valid (non-NaN) values:
        non_nan_df = self._df.dropna(subset=[column_name])

        # Group the non-NaN DataFrame by the specified column's values:
        grouped = non_nan_df.groupby(column_name)

        # Create a list of partitions (DataFrames) for each unique value in the column:
        partitions = [group for _, group in grouped]

        # Add each row with NaN/None as its own partition
        # iterrows() returns each row as a Series. To convert it back to a DataFrame:
        # 1. .to_frame() turns the Series into a DataFrame, but with the original column names as rows.
        # 2. .T (transpose) flips it back, turning the original row into a proper DataFrame row.
        # This ensures that even rows with NaN values are treated as DataFrame partitions.
        partitions.extend([row.to_frame().T for _, row in nan_partitions.iterrows()])

        self.logger.info(
            "Data frame has been partitioned into -> %s partitions based on the values in column -> '%s'...",
            str(len(partitions)),
            column_name,
        )

        return partitions

    # end method definition

    def deduplicate(self, unique_fields: list, inplace: bool = True) -> pd.DataFrame:
        """Remove dupclicate rows that have all fields in unique_fields in common.

        Args:
            unique_fields (list):
                Defines the fields for which we want a unique combination for.
            inplace (bool, optional):
                True if the deduplication happens in-place. Defaults to True.

        Returns:
            pd.DataFrame:
                If inplace is False than a new deduplicatd data frame is returned.
                Otherwise the object is modified in place and self._df is returned.

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

    def sort(self, sort_fields: list, inplace: bool = True) -> pd.DataFrame | None:
        """Sort the data frame based on one or multiple fields.

        Sorting can be either in place or return it as a new data frame
        (e.g. not modifying self._df).

        Args:
            sort_fields (list):
                The columns / fields to be used for sorting.
            inplace (bool, optional):
                If the sorting should be inplace, i.e. modifying self._df.
                Defaults to True.

        Returns:
            pd.DataFrame | None:
                New data frame (if inplace = False) or self._df (if inplace = True).
                None in case of an error.

        """

        if self._df is None:
            return None

        if not all(sort_field in self._df.columns for sort_field in sort_fields):
            self.logger.warning(
                "Not all of the given sort fields -> %s do exist in the data frame.",
                str(sort_fields),
            )
            # Reduce the sort fields to those that really exist in the data frame:
            sort_fields = [sort_field for sort_field in sort_fields if sort_field in self._df.columns]
            self.logger.warning(
                "Only these given sort fields -> %s do exist as columns in the data frame.",
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

    def flatten(self, parent_field: str, flatten_fields: list, concatenator: str = "_") -> None:
        """Flatten a sub-dictionary by copying selected fields to the parent dictionary.

        This is e.g. useful for then de-duplicate a data frame.
        To flatten a data frame makes sense in situation when a column used
        to have a list of dictionaries and got "exploded" (see explode_and_flatten()
        method below). In this case the column as dictionary values that then can
        be flattened.

        Args:
            parent_field (str):
                Name prefix of the new column in the data frame. The flattened field
                names are added with a leading underscore.
            flatten_fields (list):
                Fields in the dictionary of the source column that are copied
                as new columns into the data frame.
            concatenator (str, optional):
                Character or string used to concatenate the parent field with the flattened field
                to create a unique name.

        """

        # First do a sanity check if the data frame is not yet initialized.
        if self._df is None:
            self.logger.error(
                "The data frame is not initialized or empty. Cannot flatten field(s) -> '%s' in the data frame.",
                flatten_fields,
            )
            return

        if parent_field not in self._df.columns:
            self.logger.warning(
                "The parent field -> '%s' cannot be flattened as it doesn't exist as column in the data frame!",
                parent_field,
            )
            return

        for flatten_field in flatten_fields:
            flat_field = parent_field + concatenator + flatten_field
            # The following expression generates a new column in the
            # data frame with the name of 'flat_field'.
            # In the lambda function x is a dictionary that includes the subvalues
            # and it returns the value of the given flatten field
            # (if it exists, otherwise None). So x is self._df[parent_field], i.e.
            # what the lambda function gets 'applied' on.
            self._df[flat_field] = self._df[parent_field].apply(
                lambda x, sub_field=flatten_field: (x.get(sub_field, None) if isinstance(x, dict) else None),
            )

    # end method definition

    def explode_and_flatten(
        self,
        explode_fields: str | list,
        flatten_fields: list | None = None,
        make_unique: bool = False,
        reset_index: bool = False,
        split_string_to_list: bool = False,
        separator: str = ";,",
    ) -> pd.DataFrame | None:
        """Explode a substructure in the Pandas data frame.

        Args:
            explode_fields (str | list):
                Field(s) to explode. Each field to explode should have a list structure.
                Exploding multiple columns at once is possible. This delivers
                a very different result compared to exploding one column after the other!
            flatten_fields (list):
                Fields in the exploded substructure to include
                in the main dictionaries for easier processing.
            make_unique (bool, optional):
                If True, deduplicate the exploded data frame.
            reset_index (bool, False):
                If True, then the index is reset, False = Index is not reset.
            split_string_to_list (bool, optional):
                If True flatten the exploded data frame.
            separator (str, optional):
                Characters used to split the string values in the given column into a list.

        Returns:
            pd.DataFrame | None:
                Pointer to the Pandas data frame.

        """

        def update_column(row: pd.Series, sub: str) -> str:
            """Extract the value of a sub-column from a nested dictionary within a Pandas Series.

            Args:
                row (pd.Series):
                    A row from the data frame.
                sub (str):
                    The sub-column name to extract.

            Returns:
                str:
                    The value of the sub-column, or an empty string if not found.

            """

            if isinstance(row, dict) and sub in row:
                return row[sub]
            return ""

        # end def update_column()

        def string_to_list(value: str) -> list:
            """Convert a string to a list by splitting it using a specified separator.

            If the input is already a list, it is returned as-is. If the input is `None` or a missing value,
            an empty list is returned. Otherwise, the string is split into a list of substrings using
            the given separator. Leading and trailing spaces in the resulting substrings are removed.

            Args:
                value (str):
                    The input string to be converted into a list. Can also be a list, `None`,
                    or a missing value (e.g., NaN).

            Returns:
                list:
                    A list of substrings if the input is a string, or an empty list if the input
                    is `None` or a missing value. If the input is already a list, it is returned unchanged.

            """

            # Check if the value is already a list; if so, return it directly
            if isinstance(value, list):
                return value

            # If the value is None or a missing value (e.g., NaN), return an empty list
            if not value or pd.isna(value):
                return []

            # Use a regular expression to split the string by the separator
            # and remove leading/trailing spaces from each resulting substring
            return_list = re.split(rf"[{separator}]\s*", str(value))

            return return_list

        # end def string_to_list()

        #
        # Start of main method:
        #

        # First do a sanity check if the data frame is not yet initialized.
        if self._df is None:
            self.logger.error(
                "The data frame is not initialized or empty. Cannot explode data frame.",
            )
            return None

        # Next do a sanity check for the given explode_field. It should
        # either be a string (single column name) or a list (multiple column names):
        if isinstance(explode_fields, list):
            self.logger.info("Exploding list of columns -> %s", str(explode_fields))
        elif isinstance(explode_fields, str):
            self.logger.info("Exploding single column -> '%s'", explode_fields)
        else:
            self.logger.error(
                "Illegal explode field(s) data type -> %s. Explode field must either be a string or a list of strings.",
                type(explode_fields),
            )
            return self._df

        # Ensure explode_fields is a list for uniform processing:
        if isinstance(explode_fields, str):
            explode_fields = [explode_fields]

        # Process nested field names with '.'
        processed_fields = []
        for field in explode_fields:
            # The "." indicates that the column has dictionary values:
            if "." in field:
                main, sub = field.split(".", 1)
                if main not in self._df.columns:
                    self.logger.error(
                        "The column -> '%s' does not exist in the data frame! Cannot explode it. Data frame has these columns -> %s",
                        main,
                        str(self._df.columns.tolist()),
                    )
                    continue

                # Use update_column to extract the dictionary key specified by the sub value:
                self.logger.info(
                    "Extracting dictionary value for key -> '%s' from column -> '%s'.",
                    sub,
                    main,
                )
                self._df[main] = self._df[main].apply(update_column, args=(sub,))
                processed_fields.append(main)
            else:
                processed_fields.append(field)

        # Verify all processed fields exist in the data frame:
        missing_columns = [col for col in processed_fields if col not in self._df.columns]
        if missing_columns:
            self.logger.error(
                "The following columns are missing in the data frame and cannot be exploded -> %s. Data frame has these columns -> %s",
                missing_columns,
                str(self._df.columns.tolist()),
            )
            return self._df

        # Handle splitting strings into lists if required:
        if split_string_to_list:
            for field in processed_fields:
                self.logger.info(
                    "Splitting strings in column -> '%s' into lists using separator -> '%s'",
                    field,
                    separator,
                )
                # Apply the function to convert the string values in the column (give by the name in explode_field) to lists
                # The string_to_list() sub-method above also considers the separator parameter.
                self._df[field] = self._df[field].apply(string_to_list)

        # Explode all specified columns at once.
        # explode() can either take a string field or a list of fields.
        # # It is VERY important to do the explosion of multiple columns together -
        # otherwise we get combinatorial explosion. Explosion of multiple columns 1-by-1
        # is VERY different from doing the explosion together!
        self.logger.info("Validated column(s) to explode -> %s", processed_fields)
        try:
            self._df = self._df.explode(
                column=processed_fields,
                ignore_index=reset_index,
            )
        except ValueError:
            self.logger.error(
                "Error exploding columns -> %s",
                processed_fields,
            )
            return self._df

        if flatten_fields:
            # Ensure that flatten() is called for each exploded column
            for field in processed_fields:
                self.flatten(parent_field=field, flatten_fields=flatten_fields)

            # Deduplicate rows if required
            if make_unique:
                self._df.drop_duplicates(subset=flatten_fields, inplace=True)

        # Reset index explicitly if not handled during explode
        if reset_index:
            self._df.reset_index(drop=True, inplace=True)

        return self._df

    # end method definition

    def drop_columns(self, column_names: list, inplace: bool = True) -> pd.DataFrame:
        """Drop selected columns from the Pandas data frame.

        Args:
            column_names (list):
                The list of column names to drop.
            inplace (bool, optional):
                Whether or not the dropping should be inplace, i.e. modifying self._df.
                Defaults to True.

        Returns:
            pd.DataFrame:
                New data frame (if inplace = False) or self._df (if inplace = True)

        """

        if not all(column_name in self._df.columns for column_name in column_names):
            # Reduce the column names to those that really exist in the data frame:
            column_names = [column_name for column_name in column_names if column_name in self._df.columns]
            self.logger.info(
                "Drop columns -> %s from the data frame.",
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
        """Keep only selected columns in the data frame. Drop the rest.

        Args:
            column_names (list):
                A list of column names to keep.
            inplace (bool, optional):
                If the keeping should be inplace, i.e. modifying self._df.
                Defaults to True.

        Returns:
            pd.DataFrame:
                New data frame (if inplace = False) or self._df (if inplace = True).

        """

        if not all(column_name in self._df.columns for column_name in column_names):
            # Reduce the column names to those that really exist in the data frame:
            column_names = [column_name for column_name in column_names if column_name in self._df.columns]
            self.logger.info(
                "Reduce columns to keep to these columns -> %s that do exist in the data frame.",
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

    def rename_column(self, old_column_name: str, new_column_name: str) -> bool:
        """Rename a data frame column.

        Args:
            old_column_name (str):
                The old name of the column.
            new_column_name (str):
                The new name of the column.

        Returns:
            bool:
                True = Success, False = Error

        """

        if self._df is None:
            return False

        if old_column_name not in self._df.columns:
            self.logger.error(
                "Cannot rename column -> '%s'. It does not exist in the data frame! Data frame has these columns -> %s",
                old_column_name,
                str(self._df.columns),
            )
            return False

        if new_column_name in self._df.columns:
            self.logger.error(
                "Cannot rename column -> '%s' to -> '%s'. New name does already exist as column in the data frame! Data frame has these columns -> %s",
                old_column_name,
                new_column_name,
                str(self._df.columns),
            )
            return False

        self._df.rename(columns={old_column_name: new_column_name}, inplace=True)

        return True

    # end method definition

    def is_dict_column(self, column: pd.Series, threshold: float = 0.5) -> bool:
        """Safely checks if a column predominantly contains dictionary-like objects.

        Args:
            column (pd.Series):
                The pandas Series (column) to check.
            threshold (float, optional):
                0.0 < threshold <= 1.0. Float representation of the percentage.
                Default = 0.5 (50%).

        Returns:
            bool:
                True if the column contains mostly dictionary-like objects, False otherwise.

        """

        if not isinstance(column, pd.Series):
            self.logger.error(
                "Expected Pandas series, but got -> %s",
                str(type(column)),
            )
            return False
        if not 0.0 < threshold <= 1.0:
            self.logger.error(
                "Threshold must be between 0.0 and 1.0, but got -> %s",
                str(threshold),
            )
            return False

        # Drop null values (NaN or None) and check types of remaining values
        non_null_values = column.dropna()
        dict_count = non_null_values.apply(lambda x: isinstance(x, dict)).sum()

        # If more than threshold % of non-null values are dictionaries, return True.
        # Else return False.
        return dict_count / len(non_null_values) > threshold if len(non_null_values) > 0 else False

    # end method definition

    def is_list_column(self, column: pd.Series, threshold: float = 0.5) -> bool:
        """Safely checks if a column predominantly contains list-like objects.

        Args:
            column (pd.Series):
                The pandas Series (column) to check.
            threshold (float, optional):
                0.0 < threshold <= 1.0. Float representation of the percentage. Default = 0.5 (50%).

        Returns:
            bool:
                True if the column contains list-like objects, False otherwise.

        """

        if not isinstance(column, pd.Series):
            self.logger.error(
                "Expected pandas series, but got -> %s",
                str(type(column)),
            )
            return False
        if not 0.0 < threshold <= 1.0:
            self.logger.error(
                "Threshold must be between 0.0 and 1.0, but got -> %s",
                str(threshold),
            )
            return False

        # Drop null values (NaN or None) and check types of remaining values
        non_null_values = column.dropna()
        list_count = non_null_values.apply(lambda x: isinstance(x, list)).sum()

        # If more than threshold % of non-null values are lists, return True.
        # Else return False.
        return list_count / len(non_null_values) > threshold if len(non_null_values) > 0 else False

    # end method definition

    def is_string_column(self, column: pd.Series) -> bool:
        """Determine if a Pandas series predominantly contains string values, ignoring NaN values.

        Args:
            column (pd.Series):
                The Pandas Series to check.

        Returns:
            bool:
                True if all non-NaN values in the column are strings, False otherwise.

        """

        # Drop NaN values and check if remaining values are strings
        return column.dropna().map(lambda x: isinstance(x, str)).all()

    # end method definition

    def cleanse(self, cleansings: dict) -> None:
        """Cleanse data with regular expressions and upper/lower case conversions.

        Args:
            cleansings (dict):
                Dictionary with keys that equal the column names.
                The dictionary values are dictionaries themselves with
                these fields:
                * replacements (dict): name of a column in the data frame
                * upper (bool, optional, default = False): change the value to uppercase
                * lower (bool, optional, default = False): change the value to lowercase
                * capitalize (bool, optional, default = False) - first character upper case, rest lower-case
                * title (bool, optional, default = False) - first character of each word upper case
                * length (int, optional, default = 0): truncate to max length

        """

        # Iterate over each column in the cleansing dictionary
        for column, cleansing in cleansings.items():
            # Read the cleansing parameters:
            replacements = cleansing.get("replacements", {})
            upper = cleansing.get("upper", False)
            lower = cleansing.get("lower", False)
            capitalize = cleansing.get("capitalize", False)
            title = cleansing.get("title", False)
            length = cleansing.get("length", 0)

            # Handle dict columns - we expect the column name to seperate
            # main field from sub field using a dot syntax (e.g., "column.subfield")
            if "." in column:
                column, dict_key = column.split(".")
                if column not in self._df.columns:
                    self.logger.error(
                        "Cannot cleanse column -> '%s'. It does not exist in the data frame! Data frame has these columns -> %s",
                        column,
                        str(self._df.columns),
                    )
                    continue
                # Apply cleansing to dictionary values in the main column
                self.logger.debug(
                    "Cleansing for column -> '%s' has a subfield -> '%s' configured. Do cleansing for dictionary items with key -> '%s'...",
                    column,
                    dict_key,
                    dict_key,
                )
                self._df[column] = self._df[column].apply(
                    lambda x,
                    dict_key=dict_key,
                    replacements=replacements,
                    upper=upper,
                    lower=lower,
                    capitalize=capitalize,
                    title=title,
                    length=length: self._cleanse_subfield(
                        data=x,
                        dict_key=dict_key,
                        replacements=replacements,
                        upper=upper,
                        lower=lower,
                        capitalize=capitalize,
                        title=title,
                        length=length,
                    ),
                )
            # end if "." in column
            else:  # the else case handles strings and list columns
                if column not in self._df.columns:
                    self.logger.error(
                        "Cannot cleanse column -> '%s'. It does not exist in the data frame! Data frame has these columns -> %s",
                        column,
                        str(self._df.columns),
                    )
                    continue

                # Handle string columns:
                if self.is_string_column(self._df[column]):
                    # Apply cleansing operations on string column
                    self.logger.debug(
                        "Column -> '%s' has string values. Do cleansing for string values...",
                        column,
                    )
                    self._df[column] = self._df[column].apply(
                        lambda x,
                        replacements=replacements,
                        upper=upper,
                        lower=lower,
                        capitalize=capitalize,
                        title=title,
                        length=length: (
                            self._apply_string_cleansing(
                                value=x,
                                replacements=replacements,
                                upper=upper,
                                lower=lower,
                                capitalize=capitalize,
                                title=title,
                                length=length,
                            )
                            if isinstance(x, str)
                            else x
                        ),
                    )

                # Handle list columns:
                elif self.is_list_column(self._df[column]):
                    # Handle list-like columns for this we iterate over each list item
                    # and apply the cleansing by calling _apply_string_cleansing() for item:
                    self.logger.debug(
                        "Column -> '%s' has list values. Do cleansing for each list item...",
                        column,
                    )
                    self._df[column] = self._df[column].apply(
                        lambda x,
                        replacements=replacements,
                        upper=upper,
                        lower=lower,
                        capitalize=capitalize,
                        title=title,
                        length=length: (
                            [
                                (
                                    self._apply_string_cleansing(
                                        value=item,
                                        replacements=replacements,
                                        upper=upper,
                                        lower=lower,
                                        capitalize=capitalize,
                                        title=title,
                                        length=length,
                                    )
                                    if isinstance(
                                        item,
                                        str,
                                    )  # we just change string list items
                                    else item
                                )
                                for item in x
                            ]
                            if isinstance(x, list)
                            else x
                        ),
                    )

                else:
                    self.logger.error(
                        "Column -> '%s' is not a string, list, or dict-like column. Skipping cleansing...",
                        column,
                    )
            # end else handling strings and lists
        # for column, cleansing in cleansings.items()

    # end method definition

    def _cleanse_dictionary(
        self,
        data: dict,
        dict_key: str,
        replacements: dict[str, str],
        upper: bool,
        lower: bool,
        capitalize: bool = False,
        title: bool = False,
        length: int = 0,
    ) -> dict:
        """Cleanse dictionary data within a single column value that has a given key.

        Args:
            data (dict):
                The column dictionary value.
            dict_key (str):
                The dictionary key whose value should be cleansed in the row to cleanse.
            replacements (dict):
                Dictionary of regex replacements to apply to the subfield value.
            upper (bool):
                If True, convert value in subfield to upper-case.
            lower (bool):
                If True, convert value in subfield to lower-case.
            capitalize (bool, optional):
                If True, capitalize the first letter of the subfield value.
            title (bool, optional):
                If True, title-case the subfield value.
            length (int, optional):
                The maximum length for the subfield value.

        Returns:
            dict:
                The updated data with the cleansing applied to the dictionary item with the given key.

        """

        if pd.isna(data):
            return data

        if dict_key not in data:
            self.logger.warning(
                "The dictionary key -> '%s' (field) is not in the data frame row! Cleansing skipped!",
                dict_key,
            )
            return data

        # 1. Read the value to be cleansed from the data dict:
        value = data[dict_key]

        # 2. Apply string operations based on the type of the value (str, list, or dict)

        if isinstance(value, str):
            # If the value is a string, apply the string operations directly
            value: str = self._apply_string_cleansing(
                value=value,
                replacements=replacements,
                upper=upper,
                lower=lower,
                capitalize=capitalize,
                title=title,
                length=length,
            )
        elif isinstance(value, list):
            # If the value is a list, apply string operations to each element
            value: list = [
                (
                    self._apply_string_cleansing(
                        value=item,
                        replacements=replacements,
                        upper=upper,
                        lower=lower,
                        capitalize=capitalize,
                        title=title,
                        length=length,
                    )
                    if isinstance(item, str)
                    else item
                )
                for item in value
            ]
        elif isinstance(value, dict):
            # If the value is a dictionary, apply string operations to each value
            value: dict = {
                k: (
                    self._apply_string_cleansing(
                        value=v,
                        replacements=replacements,
                        upper=upper,
                        lower=lower,
                        capitalize=capitalize,
                        title=title,
                        length=length,
                    )
                    if isinstance(v, str)
                    else v
                )
                for k, v in value.items()
            }

        # 3. Write back the cleansed value to the data dict:
        data[dict_key] = value

        return data

    # end method definition

    def _cleanse_subfield(
        self,
        data: dict | list,
        dict_key: str,
        replacements: dict[str, str],
        upper: bool,
        lower: bool,
        capitalize: bool = False,
        title: bool = False,
        length: int = 0,
    ) -> dict | list:
        """Cleanse subfield data within a single column value.

        This is NOT a pd.Series but either a dictionary or a list of dictionaries.

        Args:
            data (dict | list):
                The column value. Can be a dictionary or a list of dictionaries
            dict_key (str):
                The dictionary key whose value should be cleansed in the data to cleanse.
            replacements (dict):
                Dictionary of regex replacements to apply to the subfield value.
            upper (bool):
                If True, convert value in subfield to upper-case.
            lower (bool):
                If True, convert value in subfield to lower-case.
            capitalize (bool, optional):
                If True, capitalize the first letter of the subfield value.
            title (bool, optional):
                If True, title-case the subfield value.
            length (int, optional):
                The maximum length for the subfield value.

        Returns:
            dict | list:
                The updated data with the cleansing applied to the subfield.

        """

        if isinstance(data, list):
            data = [
                (
                    self._cleanse_dictionary(
                        data=item,
                        dict_key=dict_key,
                        replacements=replacements,
                        upper=upper,
                        lower=lower,
                        capitalize=capitalize,
                        title=title,
                        length=length,
                    )
                    if item is not None and dict_key in item and not pd.isna(item[dict_key])
                    else item
                )
                for item in data
            ]
        elif isinstance(data, dict):
            data = self._cleanse_dictionary(
                data=data,
                dict_key=dict_key,
                replacements=replacements,
                upper=upper,
                lower=lower,
                capitalize=capitalize,
                title=title,
                length=length,
            )

        return data

    # end method definition

    def _apply_string_cleansing(
        self,
        value: str,
        replacements: dict[str, str],
        upper: bool,
        lower: bool,
        capitalize: bool,
        title: bool,
        length: int,
    ) -> str | None:
        """Apply string operations (upper, lower, capitalize, title-case, replacements) to a string.

        Args:
            value (str):
                The string value to which the operations will be applied.
            replacements (dict[str, str]):
                A dictionary of regular expression patterns (keys) and replacement strings (values) to apply to the string.
            upper (bool):
                If True, convert the string to uppercase.
            lower (bool):
                If True, convert the string to lowercase.
            capitalize (bool):
                If True, capitalize the first letter of the string and lowercase the rest. Default is False.
            title (bool):
                If True, convert the string to title-case (first letter of each word is capitalized). Default is False.
            length (int):
                If greater than 0, truncate the string to this length. Default is 0 (no truncation).

        Returns:
            str | None:
                The updated string with all the applied operations. None in case an error occured.

        Example:
            value = "hello world"
            replacements = {r"world": "there"}
            upper = True
            length = 5

            result = _apply_string_cleansing(value, replacements, upper, length=length)
            # result would be "HELLO"

        """

        if not isinstance(
            value,
            str,
        ):  # Only apply string operations if the value is a string
            return None

        if upper:
            value = value.upper()
        if lower:
            value = value.lower()
        if capitalize:
            value = value.capitalize()
        if title:
            value = value.title()

        # Handle regex replacements
        for regex_pattern, replacement in replacements.items():
            if regex_pattern:
                # Check if the pattern does NOT contain any regex special characters
                # (excluding dot and ampersand) and ONLY then use \b ... \b
                # Special regexp characters include: ^ $ * + ? ( ) | [ ] { } \
                if not re.search(r"[\\^$*+?()|[\]{}]", regex_pattern):
                    # Wrap with word boundaries for whole-word matching
                    # \b is a word boundary anchor in regular expressions.
                    # It matches a position where one side is a word character
                    # (like a letter or digit) and the other side is a non-word character
                    # (like whitespace or punctuation). It's used to match whole words.
                    # We want to have this to e.g. not replace "INT" with "INTERNATIONAL"
                    # if the word is already "INTERNATIONAL". It is important
                    # that the \b ... \b enclosure is ONLY used if regex_pattern is NOT
                    # a regular expression but just a normal string.
                    # TODO: we may reconsider if re.escape() is required or not:
                    regex_pattern = re.escape(regex_pattern)
                    regex_pattern = rf"\b{regex_pattern}\b"
                try:
                    value = re.sub(regex_pattern, replacement, value)
                except re.error:
                    self.logger.error(
                        "Invalid regex pattern -> '%s' in replacement processing!",
                        regex_pattern,
                    )
                    continue

        # Truncate to the specified length, starting from index 0
        if 0 < length < len(value):
            value = value[:length]

        return value

    # end method definition

    def filter(
        self,
        conditions: list,
        inplace: bool = True,
        reset_index: bool = True,
    ) -> pd.DataFrame | None:
        """Filter the data frame based on (multiple) conditions.

        Args:
            conditions (list):
                Conditions are a list of dictionaries with 3 items:
                * field (str): The name of a column in the data frame
                * value (str or list):
                    Expected value (filter criterium).
                    If it is a list then one of the list elements must match the field value (OR)
                * equal (bool):
                    Whether to test for equal or non-equal. If not specified equal is treated as True.
                * regex (bool):
                    This flag controls if the value is interpreted as a
                    regular expression. If there is no regex item in the
                    dictionary then the default is False (= values is NOT regex).
                * enabled (bool):
                    True or False. The filter is only applied if 'enabled = True'
                If there are multiple conditions in the list each has to evaluate to True (AND)
            inplace (bool, optional):
                Defines if the self._df is modified (inplace) or just
                a new data frame is returned. Defaults to True.
            reset_index (bool, optional):
                Filter removes rows. If filter_index = True then the numbering
                of the index is newly calculated

        Returns:
            pd.DataFrame | None:
                A new data frame or pointer to self._df (depending on the value of 'inplace').
                None in case of an error.

        """

        if self._df is None:
            self.logger.error("Data frame is not initialized.")
            return None

        if self._df.empty:
            self.logger.error("Data frame is empty.")
            return None

        # First filtered_df is the full data frame.
        # Then it is subsequentially reduced by each condition
        # at the end it is just those rows that match all conditions.
        filtered_df = self._df if inplace else self._df.copy()

        def list_matches(row: list, values: list) -> bool:
            """Check if any item in the 'values' list is present in the given 'row' list.

            Args:
                row (list):
                    A list of items from the data frame column.
                values (list):
                    A list of values to check for in the 'row'.

            Returns:
                bool:
                    True if any item in 'values' is found in 'row', otherwise False.

            """

            return any(item in values for item in row)

        def dict_matches(row: dict, key: str, values: list) -> bool:
            """Check if the value for the dictionary 'key' is in 'values'.

            Args:
                row (dict):
                    A dictionary from the data frame column.
                key (str):
                    The key to lookup in the dictionary.
                values (list):
                    A list of values to check for in the 'row'.

            Returns:
                bool:
                    True, if the value for the dictionary key is in 'values', otherwise False.

            """

            if not row or key not in row:
                return False

            return row[key] in values

        # We traverse a list of conditions. Each condition must evaluate to True
        # otherwise the current workspace or document (i.e. the data set for these objects)
        # will be skipped.
        for condition in conditions:
            # Check if the condition is enabled. If 'enabled' is not
            # in the condition dict then we assume it is enabled.
            if not condition.get("enabled", True):
                continue
            field = condition.get("field", None)
            if not field:
                self.logger.error(
                    "Missing value for filter condition 'field' in payload!",
                )
                continue
            if "." in field:
                field, sub = field.split(".", 1)
            else:
                sub = None

            if field not in self._df.columns:
                self.logger.warning(
                    "Filter condition field -> '%s' does not exist as column in the data frame! Data frame has these columns -> %s",
                    field,
                    str(self._df.columns),
                )
                continue  # Skip filtering for columns not present in data frame

            regex = condition.get("regex", False)
            # We need the column to be of type string if we want to use regular expressions
            # so if the column is not yet a string we convert the column to string:
            if regex and filtered_df[field].dtype != "object":
                # Change type of column to string:
                filtered_df[field] = filtered_df[field].astype(str)
                filtered_df[field] = filtered_df[field].fillna("")

            value = condition.get("value", None)
            if value is None:
                # Support alternative syntax using plural.
                value = condition.get("values", None)
            if value is None:
                self.logger.error(
                    "Missing filter value(s) for filter condition field -> '%s'!",
                    field,
                )
                continue

            # if a single string is passed as value we put
            # it into an 1-item list to simplify the following code:
            if not isinstance(value, list):
                value = [value]

            # If all values in the condition are strings then we
            # want the column also to be of type string:
            if all(isinstance(v, str) for v in value):
                # Change type of column to string:
                #                filtered_df[field] = filtered_df[field].astype(str)
                #                filtered_df[field] = filtered_df[field].fillna("").astype(str)
                #                filtered_df[field] = filtered_df[field].fillna("")

                # When inplace == True, filtered_df is just a reference to self._df.
                # Using .loc[:, field] ensures that Pandas updates the column correctly in self._df.
                # When inplace == False, filtered_df is a full copy (self._df.copy() above),
                # so modifications remain in filtered_df.
                # .loc[:, field] ensures no SettingWithCopyWarning, since filtered_df is now a separate DataFrame.
                filtered_df.loc[:, field] = filtered_df[field].fillna("").astype(str)

            self.logger.info(
                "Data frame has %s row(s) and %s column(s) before filter -> %s has been applied.",
                str(filtered_df.shape[0]),
                str(filtered_df.shape[1]),
                str(condition),
            )

            # Check if the column is boolean
            if pd.api.types.is_bool_dtype(filtered_df[field]):
                # Convert string representations of booleans to actual booleans
                value = [v.lower() in ["true", "1"] if isinstance(v, str) else bool(v) for v in value]

            # Do we want to test for equalitiy or non-equality?
            # For lists equality means: value is in the list
            # For lists non-equality means: value is NOT in the list
            test_for_equal = condition.get("equal", True)

            # Check if the column contains only lists (every non-empty element in the column is a list).
            # `filtered_df[field]`: Access the column with the name specified in 'field'.
            # `.dropna()`: Drop None or NaN rows for the test.
            # `.apply(lambda x: isinstance(x, list))`: For each element in the column, check if it is a list.
            # `.all()`: Ensure that all elements in the column satisfy the condition of being a list.
            if filtered_df[field].dropna().apply(lambda x: isinstance(x, list)).all():
                if not test_for_equal:
                    filtered_df = filtered_df[~filtered_df[field].apply(list_matches, values=value)]
                else:
                    filtered_df = filtered_df[filtered_df[field].apply(list_matches, values=value)]
            # Check if the column contains only dictionaries (every non-empty element in the column is a dict).
            # `filtered_df[field]`: Access the column with the name specified in 'field'.
            # `.dropna()`: Drop None or NaN rows for the test.
            # `.apply(lambda x: isinstance(x, dict))`: For each element in the column, check if it is a dict.
            # `.all()`: Ensure that all elements in the column satisfy the condition of being a dictionary.
            elif filtered_df[field].dropna().apply(lambda x: isinstance(x, dict)).all():
                if not sub:
                    self.logger.error(
                        "Filtering on dictionary values need a key. This needs to be provided with 'field.key' syntax!",
                    )
                    continue
                if not test_for_equal:
                    filtered_df = filtered_df[~filtered_df[field].apply(dict_matches, key=sub, values=value)]
                else:
                    filtered_df = filtered_df[filtered_df[field].apply(dict_matches, key=sub, values=value)]
            # Check if the column has boolean values:
            elif pd.api.types.is_bool_dtype(filtered_df[field]):
                # For a boolean filter we can drop NA values:
                filtered_df = filtered_df.dropna(subset=[field])
                if not test_for_equal:
                    filtered_df = filtered_df[~filtered_df[field].isin(value)]
                else:
                    filtered_df = filtered_df[filtered_df[field].isin(value)]
            elif not regex:
                if pd.api.types.is_string_dtype(filtered_df[field]):
                    filtered_df[field] = filtered_df[field].str.strip()
                if not test_for_equal:
                    filtered_df = filtered_df[~filtered_df[field].isin(value)]
                else:
                    filtered_df = filtered_df[filtered_df[field].isin(value)]
            else:
                # Create a pure boolean pd.Series as a filter criterium:
                regex_condition = filtered_df[field].str.contains(
                    "|".join(value),
                    regex=True,
                    na=False,
                )
                # Apply the boolean pd.Series named 'regex_condition' as
                # a filter - either non-negated or negated (using ~):
                filtered_df = filtered_df[~regex_condition] if not test_for_equal else filtered_df[regex_condition]

            self.logger.info(
                "Data frame has %s row(s) and %s column(s) after filter -> %s has been applied.",
                str(filtered_df.shape[0]),
                str(filtered_df.shape[1]),
                str(condition),
            )
        # end for condition

        if inplace:
            self._df = filtered_df

            if reset_index:
                self._df.reset_index(inplace=True, drop=True)

        return filtered_df

    # end method definition

    def fill_na_in_column(self, column_name: str, default_value: str | int) -> None:
        """Replace NA values in a column with a defined new default value.

        Args:
            column_name (str):
                The name of the column in the data frame.
            default_value (str | int):
                The value to replace NA with.

        """

        if column_name in self._df.columns:
            self._df[column_name] = self._df[column_name].fillna(value=default_value)
        else:
            self.logger.error(
                "Cannot replace NA values as column -> '%s' does not exist in the data frame! Available columns -> %s",
                column_name,
                str(self._df.columns),
            )

    # end method definition

    def fill_forward(self, inplace: bool) -> pd.DataFrame:
        """Fill the missing cells appropriately by carrying forward the values from the previous rows where necessary.

        This has applications if a hierarchy is represented by
        nested cells e.g. in an Excel sheet.

        Args:
            inplace (bool):
                Should the modification happen inplace or not.

        Returns:
            pd.DataFrame:
                The resulting data frame.

        """

        # To convert an Excel representation of a folder structure with nested
        # columns into a format appropriate for Pandas,
        # where all cells should be filled
        df_filled = self._df.ffill(inplace=inplace)

        return df_filled

    # end method definition

    def lookup_value(
        self,
        lookup_column: str,
        lookup_value: str,
        separator: str = "|",
        single_row: bool = True,
    ) -> pd.Series | pd.DataFrame | None:
        """Lookup row(s) that includes a lookup value in the value of a given column.

        Args:
            lookup_column (str):
                The name of the column to search in.
            lookup_value (str):
                The value to search for.
            separator (str):
                The string list delimiter / separator. The pipe symbol | is the default
                as it is unlikely to appear in a normal string (other than a plain comma).
                The separator is NOT looked for in the lookup_value but in the column that
                is given by lookup_column!
            single_row (bool, optional):
                This defines if we just return the first matching row if multiple matching rows
                are found. Default is True (= single row).

        Returns:
            pd.Series | pd.DataFrame | None:
                Data frame (multiple rows) or Series (row) that matches the lookup value.
                None if no match was found.

        """

        # Use the `apply` function to filter rows where the lookup value matches a
        # whole item in the separator-divided list:
        def match_lookup_value(string_list: str | None) -> bool:
            """Check if the lookup value is in a string list.

            For this the string list is converted to a python
            list. A separator is used for the splitting.

            Args:
                string_list (str):
                    Delimiter-separated string list like "a, b, c" or "a | b | c"

            Returns:
                bool:
                    True if lookup_value is equal to one of the delimiter-separated terms.

            """

            if pd.isna(string_list):  # Handle None/NaN safely
                return False

            # Ensure that the string is a string
            string_list = str(string_list)

            return lookup_value in [item.strip() for item in string_list.split(separator)]

        # end method definition

        if self._df is None:
            return None

        df = self._df

        if lookup_column not in self._df.columns:
            self.logger.error(
                "Cannot lookup value in column -> '%s'. Column does not exist in the data frame! Data frame has these columns -> %s",
                lookup_column,
                str(self._df.columns),
            )
            return None

        # Fill NaN or None values in the lookup column with empty strings
        # df[lookup_column] = df[lookup_column].fillna("")

        # Use the `apply` function to filter rows where the lookup value is in row cell
        # of column given by lookup_column. match_lookup_value() is called with
        # the content of the individual cell contents:
        matched_rows = df[df[lookup_column].apply(match_lookup_value)]

        # If nothing was found we return None:
        if matched_rows.empty:
            return None

        # If it is OK to have multiple matches (= multiple rows = pd.DataFrame).
        # We can just return the matched_rows now which should be a pd.DataFrame:
        if not single_row:
            return matched_rows

        # Check if more than one row matches, and log a warning if so
        if len(matched_rows) > 1:
            self.logger.warning(
                "More than one match found for lookup value -> '%s' in column -> '%s'. Returning the first match.",
                lookup_value,
                lookup_column,
            )

        # Return the first matched row, if any
        return matched_rows.iloc[0]

    # end method definition

    def set_value(self, column: str, value, condition: pd.Series | None = None) -> None:  # noqa: ANN001
        """Set the value in the data frame based on a condition.

        Args:
            column (str):
                The name of the column.
            value (Any):
                The value to set for those rows that fulfill the condition.
            condition (pd.Series, optional):
                This should be a boolean Series where each element is True or False,
                representing rows in the data frame that meet a certain condition.
                If None is provided then ALL rows get the 'value' in the given
                column.

        """

        if condition is None:
            self._df[column] = value  # Set value unconditionally
        else:
            self._df.loc[condition, column] = value  # Set value based on condition

    # end method definition

    def add_column(
        self,
        new_column: str,
        data_type: str = "string",
        source_column: str = "",
        reg_exp: str = "",
        prefix: str = "",
        suffix: str = "",
        length: int | None = None,
        group_chars: int | None = None,
        group_separator: str = ".",
        group_remove_leading_zero: bool = True,
    ) -> bool:
        """Add additional column to the data frame.

        Args:
            new_column (str):
                The name of the column to add.
            data_type (str, optional):
                The data type of the new column.
            source_column (str, optional):
                The name of the source column.
            reg_exp (str, optional):
                A regular expression to apply on the content of the source column.
            prefix (str, optional):
                Prefix to add in front of the value. Defaults to "".
            suffix (str, optional):
                Suffix to add at the end of the value. Defaults to "".
            length (int | None, optional):
                Length to reduce to. Defaults to None (= unlimited).
            group_chars (int | None, optional):
                Group the resulting string in characters of group_chars. Defaults to None.
                Usable e.g. for thousand seperator "."
            group_separator (str, optional):
                Separator string for the grouping. Defaults to ".".
            group_remove_leading_zero (bool, optional):
                Remove leading zeros from the groups. Defaults to True.

        Returns:
            bool:
                True = Success, False = Failure

        Side effects:
            self._df is modified in place.

        """

        if self._df is None:
            self.logger.error("Data frame is not initialized. Cannot add column -> %s!", new_column)
            return False

        # Check that the new column does not yet exist
        if new_column in self._df.columns:
            self.logger.error(
                "New column -> '%s' does already exist in data frame! Cannot add it. Data frame has these columns -> %s",
                new_column,
                str(self._df.columns),
            )
            return False

        # first we handle the very simple case to not have a source column but just add an empty new column.
        # It is important to add the index parameter as Series assignment is index-aligned, not positional:
        if not source_column:
            self._df[new_column] = pd.Series(index=self._df.index, dtype=data_type)
            return True

        # Check if the source column exists
        if source_column not in self._df.columns:
            self.logger.error(
                "Source column -> '%s' does not exist as column in data frame! Data frame has these columns -> %s",
                source_column,
                str(self._df.columns),
            )
            return False

        # Validate the regex pattern
        try:
            re.compile(reg_exp)  # Check if the pattern is a valid regex
        except re.error:
            self.logger.error(
                "Invalid regular expression -> %s. Cannot extract data for new column -> '%s'!",
                reg_exp,
                new_column,
            )
            return False

        # Ensure the source column is of type string (convert it, if necessary)
        if self._df[source_column].dtype != "object":
            self._df[source_column] = self._df[source_column].astype(str)

        # Use str.extract to apply the regular expression to the source column
        # and then assign this modified column to the variable "extracted":
        extracted = self._df[source_column].str.extract(pat=reg_exp, expand=False)

        # Limit the result to the specified length
        if length is not None:
            extracted = extracted.str[:length]

        if group_chars is not None:

            def process_grouping(x) -> str | None:  # noqa: ANN001
                if pd.isna(x):
                    return None
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

    def convert_to_lists(self, columns: list, delimiter: str = ",") -> None:
        """Intelligently convert string values to list values, in defined data frame columns.

        The delimiter to separate values in the string value can be configured.
        The method is ignoring delimiters that are inside quotes.

        Args:
            columns (list):
                The name of the columns whose values should be converted to lists.
            delimiter (str, optional):
                Character that delimits list items. Defaults to ",".

        Returns:
            None. self._df is modified in place.

        """

        # Regex to split by the delimiter, ignoring those inside quotes or double quotes
        def split_string_ignoring_quotes(s: str, delimiter: str) -> list:
            """Split a string into a list at positions that have a delimiter character.

            Args:
                s (str): the string to split
                delimiter (str): The single character that is used for splitting.

            Returns:
                A list of splitted values.

            """

            # Escaping the delimiter in case it's a special regex character
            delimiter = re.escape(delimiter)
            # Match quoted strings and unquoted delimiters separately
            pattern = rf'(?:"[^"]*"|\'[^\']*\'|[^{delimiter}]+)'
            return re.findall(pattern, s)

        for col in columns:
            self._df[col] = self._df[col].apply(
                lambda x: (split_string_ignoring_quotes(x, delimiter) if isinstance(x, str) and delimiter in x else x),
            )

    # end method definition

    def add_column_concat(
        self,
        source_columns: list,
        new_column: str,
        concat_char: str = "",
        upper: bool = False,
        lower: bool = False,
        capitalize: bool = False,
        title: bool = False,
    ) -> bool:
        """Add a column as a concatenation of the values of multiple source columns.

        Args:
            source_columns (list):
                The column names the list values are taken from.
            new_column (str):
                The name of the new column.
            concat_char (str, optional):
                Character to insert between the concatenated values. Default is "".
            upper (bool, optional):
                Convert result to uppercase if True.
            lower (bool, optional):
                Convert result to lowercase if True.
            capitalize (bool, optional):
                Capitalize the result if True.
            title (bool, optional):
                Convert result to title case if True.

        Returns:
            bool:
                True = Success, False = Failure

        Side effects:
            self._df is modified in place.

        """

        def concatenate(row: pd.Series) -> str:
            # Comprehension to create a list from all source column values:
            concatenated = concat_char.join(
                [str(row[col]) for col in source_columns if pd.notna(row[col])],
            )

            # Apply case transformations based on parameters
            if upper:
                concatenated = concatenated.upper()
            elif lower:
                concatenated = concatenated.lower()
            elif capitalize:
                concatenated = concatenated.capitalize()
            elif title:
                concatenated = concatenated.title()

            return concatenated

        # end method definition

        #
        # Validations:
        #

        # Check the data frame is initialized:
        if self._df is None:
            self.logger.error(
                "Data frame is not initialized. Cannot add a column -> '%s' via concatenation!", new_column
            )
            return False
        # Check we only do one case transformation as they are mutually exclusive:
        if sum([upper, lower, capitalize, title]) > 1:
            self.logger.warning("Only one case transformation can be applied for added data frame column.")
        # Check that the new column does not yet exist:
        if new_column in self._df.columns:
            self.logger.error(
                "New column -> '%s' does already exist in data frame! Cannot add it by concatenation of -> %s. Data frame has these columns -> %s",
                new_column,
                str(source_columns),
                str(self._df.columns),
            )
            return False
        # Check source columns are valid:
        if not isinstance(source_columns, (list, tuple)) or not source_columns:
            self.logger.error("Source columns must be a non-empty list of column names!")
            return False
        missing = [c for c in source_columns if c not in self._df.columns]
        if missing:
            self.logger.error(
                "Missing source columns -> %s. Cannot concat it to values of new column -> '%s'!",
                str(missing),
                new_column,
            )
            return False

        #
        # Execute the transformation:
        #
        self._df[new_column] = self._df.apply(concatenate, axis=1)

        return True

    # end method definition

    def add_column_list(self, source_columns: list, new_column: str) -> bool:
        """Add a column with list objects.

        The list items are taken from a list of source columns (row by row).

        Args:
            source_columns (list):
                The column names the list values are taken from.
            new_column (str):
                The name of the new column.

        Returns:
            bool:
                True = Success, False = Failure

        Side effects:
            self._df is modified in place.

        """

        def create_list(row: pd.Series) -> list:
            # Comprehension to create a list from all source column values:
            return [row[col] for col in source_columns]

        #
        # Validations:
        #

        # Check the data frame is initialized:
        if self._df is None:
            self.logger.error("Data frame is not initialized. Cannot add new list column -> '%s'!", new_column)
            return False
        # Check that the new column does not yet exist:
        if new_column in self._df.columns:
            self.logger.error("Column -> '%s' already exists in the data frame. Cannot add it!", new_column)
            return False
        # Check source columns are valid:
        if not isinstance(source_columns, (list, tuple)) or not source_columns:
            self.logger.error("Source columns must be a non-empty list of column names! Cannot add new list column.")
            return False
        missing = [c for c in source_columns if c not in self._df.columns]
        if missing:
            self.logger.error(
                "Missing source columns -> %s. Cannot transform its values to a new list column -> '%s'!",
                str(missing),
                new_column,
            )
            return False

        #
        # Execute the transformation:
        #
        self._df[new_column] = self._df.apply(create_list, axis=1)

        return True

    # end method definition

    def add_column_table(
        self,
        source_columns: list,
        new_column: str,
        delimiter: str = ",",
    ) -> bool:
        """Add a column with tabular objects (list of dictionaries).

        The source columns should include lists. The resulting dictionary
        keys are the column names for the source columns.

        Example (["X", "Y"] are the source_columns, "Table" is the new_column):
        X[1] = [1, 2, 3]         # row 1
        Y[1] = ["A", "B", "C"]   # row 1
        X[2] = [4, 5, 6]         # row 2
        Y[2] = ["D", "E", "F"]   # row 2

        Table[1] = [
            {
                "X": "1"
                "Y": "A"
            },
            {
                "X": "2"
                "Y": "B"
            },
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
            },
            {
                "X": "6"
                "Y": "F"
            }
        ]

        Args:
            source_columns (list):
                The column names the list values are taken from.
            new_column (str):
                The name of the new column.
            delimiter (str, optional):
                Character that delimits list items. Defaults to ",".

        Returns:
            bool:
                True = Success, False = Failure

        Side effects:
            self._df is modified in place.

        """

        # Sub-method to pad lists to the desired length
        def pad_list(lst: list, max_len: int) -> list:
            """Pad lists to the same length. None is used as the filler.

            Args:
                lst (list):
                    List to pad.
                max_len (int):
                    Desired length of the list.

            Returns:
                list:
                    The padded list.

            """

            return lst + [None] * (max_len - len(lst))

        # end sub-method

        def create_table(row: pd.Series) -> list:
            """Create a list of dictionaries representing the table value.

            Args:
                row (pd.Series):
                    Current row to process.

            Returns:
                list:
                    List of dictionaries representing the table value.

            """

            # Step 1: Determine maximum length across columns
            max_len = max(len(row[col]) if isinstance(row[col], list) else 1 for col in source_columns)

            # Step 2: Pad lists to the maximum length, leave scalar values as they are, don't change source columns:
            table_values = {}  # list of values padded to max_len. We use a separate variable to not change source columns.
            for col in source_columns:
                val = row[col]
                if isinstance(val, list):
                    table_values[col] = pad_list(val, max_len)
                elif not pd.isna(val):
                    table_values[col] = [
                        val,
                    ] * max_len  # Repeat scalar value to match the max length
                else:
                    table_values[col] = [None] * max_len  # fill missing values

            # Step 3: Create a list of dictionaries (table) for each row:
            table = [{col: table_values[col][i] for col in source_columns} for i in range(max_len)]

            return table

        # end sub-method

        #
        # Validations:
        #

        # Check the data frame is initialized:
        if self._df is None:
            self.logger.error("Data frame is not initialized. Cannot add new table column -> '%s'!", new_column)
            return False
        # Check that the new column does not yet exist:
        if new_column in self._df.columns:
            self.logger.error("Column -> '%s' already exists in the data frame. Cannot add it!", new_column)
            return False
        # Check source columns are valid:
        if not isinstance(source_columns, (list, tuple)) or not source_columns:
            self.logger.error("Source columns must be a non-empty list of column names!")
            return False
        missing = [c for c in source_columns if c not in self._df.columns]
        if missing:
            self.logger.error(
                "Missing source columns -> %s. Cannot transform it to table values in new column -> '%s'!",
                str(missing),
                new_column,
            )
            return False

        #
        # Execute the transformations:
        #

        # Call the convert_to_lists method to ensure the columns are converted
        self.convert_to_lists(columns=source_columns, delimiter=delimiter)

        # Apply the function to create a new column with table values:
        self._df[new_column] = self._df.apply(create_table, axis=1)

        return True

    # end method definition

    def drop_row(self, index: int | str) -> None:
        """Drop a single row from the DataFrame by its index.

        Args:
            index (int | str):
                The index value of the row to remove. Can be an integer or string
                depending on the DataFrame index type.

        """

        if index in self._df.index:
            self._df.drop(index=index, inplace=True)

    # end method definition

    def drop_rows(self, mask: pd.Series) -> None:
        """Drop rows from the DataFrame based on a boolean mask.

        Args:
            mask (pd.Series):
                A boolean Series where True indicates the rows to drop.

        """

        self._df = self._df[~mask]

    # end method definition

    def get_match_mask(self, match_with: Data | pd.DataFrame, on_columns: list[str]) -> pd.Series:
        """Find rows in this Data object that match another Data object or DataFrame.

        Args:
            match_with (Data | pd.DataFrame):
                The source of rows to match against.
            on_columns (list[str]):
                The columns to use for the comparison key.

        Returns:
            pd.Series:
                A boolean Series where True indicates a match.

        """

        # Ternary normalization
        match_df = match_with.get_data_frame() if isinstance(match_with, Data) else match_with

        if len(on_columns) == 1:
            # Optimized path for single-column (e.g., Node 'id')
            col = on_columns[0]
            return self._df[col].isin(match_df[col])
        else:
            # Optimized path for composite keys (e.g., Edge triple)
            match_index = pd.MultiIndex.from_frame(match_df[on_columns])
            self_index = pd.MultiIndex.from_frame(self._df[on_columns])
            return self_index.isin(match_index)

    # end method definition
