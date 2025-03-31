"""Payload List Module to implement methods to maintain and process a list of payload files.

This code typically runs in a container as part of the cloud automation.
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import os
import pprint
import threading
import time
import traceback
from datetime import datetime, timezone

from pydantic import ValidationError

from pyxecm.customizer.api.settings import api_settings

# OpenText specific modules:
from pyxecm.customizer.customizer import Customizer
from pyxecm.customizer.exceptions import StopOnError
from pyxecm.customizer.log import LogCountFilter, VictoriaLogsHandler
from pyxecm.customizer.payload import load_payload

default_logger = logging.getLogger("pyxecm.customizer.payload_list")

try:
    import pandas as pd

    pandas_installed = True
except ModuleNotFoundError:
    default_logger.warning(
        "Module pandas is not installed. Customizer will not support bulk workspace creation.",
    )
    pandas_installed = False


class PayloadList:
    """Manage a sorted list of payload items using a pandas data frame.

    Each payload item with metadata such as name, filename, dependency (referencing another item by index),
    logfile, and status. Provides list-like functionality with additional methods
    for adding, removing, and reordering items.
    """

    logger: logging.Logger = default_logger

    _stopped: bool = True
    payload_items: pd.DataFrame

    def __init__(self, logger: logging.Logger = default_logger) -> None:
        """Initialize the Payload List object.

        Args:
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """
        if logger != default_logger:
            self.logger = logging.getLogger(f"{logger.name}.payload_list")

        self.payload_items = pd.DataFrame(
            columns=[
                "name",
                "filename",
                "dependencies",
                "logfile",
                "status",
                "enabled",
                "git_url",
                "loglevel",
                "start_time",
                "stop_time",
                "duration",
                "log_debug",
                "log_info",
                "log_warning",
                "log_error",
                "log_critical",
            ],
        )

    # end method definition

    def calculate_payload_item_duration(self) -> None:
        """Update the dataframe column "duration" for all running items."""

        def calculate_duration(row: pd.Series) -> str:
            if row["status"] == "running":
                now = datetime.now(timezone.utc)
                start_time = pd.to_datetime(row["start_time"])

                duration = now - start_time
                hours, remainder = divmod(duration.total_seconds(), 3600)
                minutes, seconds = divmod(remainder, 60)
                formatted_duration = f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"

                return formatted_duration
            else:
                return str(row["duration"])  # or whatever the original value should be

        # updates the "duration" column of the DataFrame self.payload_items
        # by applying the method calculate_duration() to each row:
        self.payload_items["duration"] = self.payload_items.apply(
            calculate_duration,
            axis=1,
        )

    # end method definition

    def get_payload_items(self) -> pd.DataFrame:
        """Get the payload items in their current order in the PayloadList.

        Returns:
            pd.DataFrame:
                A data frame containing all items in their current order.

        """

        self.calculate_payload_item_duration()

        return self.payload_items

    # end method definition

    def get_payload_item(self, index: int) -> pd.Series:
        """Get the payload item by index if it exists, otherwise return None.

        Args:
            index (int): index of the row

        Returns:
            pd.Series: row with the matching index or None if there is no row with that index

        """

        self.calculate_payload_item_duration()

        if index not in self.payload_items.index:
            self.logger.error("Index -> %s is out of range", str(index))
            return None

        return self.payload_items.loc[index]

    # end method definition

    def get_payload_item_by_name(self, name: str) -> pd.Series:
        """Get the payload item by name if it exists, otherwise return None.

        Args:
            name (str):
                The name of the payload.

        Returns:
            pd.Series:
                Row with the matching name or None if there is no row with that index

        """

        self.calculate_payload_item_duration()

        df = self.get_payload_items()
        data = [{"index": idx, **row} for idx, row in df.iterrows()]

        return next((item for item in data if item.get("name") == name), None)

    # end method definition

    def get_payload_items_by_value(
        self,
        column: str,
        value: str,
    ) -> pd.DataFrame | None:
        """Filter the PayloadList by a given value in a specific column.

        Args:
            column (str):
                The column to filter by.
            value (str):
                The value to match in the specified column.

        Returns:
            pd.DataFrame: A DataFrame containing rows where the given column matches the value.

        Example:
            >>> payload_list = PayloadList()
            >>> payload_list.add_item("Task1", "task1.txt", status="running")
            >>> payload_list.add_item("Task2", "task2.txt", status="completed")
            >>> payload_list.add_item("Task3", "task3.txt", status="running")
            >>> payload_list.get_payload_items_by_value(column="status", value="running")
                name         file    dependencies  logfile   status    enabled
            0   Task1    task1.txt        NaN        None   running     True
            2   Task3    task3.txt        NaN        None   running     True

        """

        if column not in self.payload_items.columns:
            self.logger.error(
                "Column -> '%s' does not exist in the payload list!",
                str(column),
            )
            return None

        filtered_items = self.payload_items[self.payload_items[column] == value]

        return filtered_items

    # end method definition

    def add_payload_item(
        self,
        name: str,
        filename: str,
        logfile: str,
        dependencies: list | None = None,
        status: str = "pending",
        enabled: bool = True,
        git_url: str | None = None,
        loglevel: str = "INFO",
    ) -> dict:
        """Add a new item to the PayloadList.

        Args:
            name (str):
                The name of the item.
            filename (str):
                The file associated with the item.
            logfile (str):
                Log file information for the item. Defaults to None.
            dependencies (list):
                The index of another item this item depends on. Defaults to None.
            status (str):
                The status of the item. Must be one of 'planned', 'running',
                'completed', or 'failed'. Defaults to 'planned'.
            enabled (bool):
                True if the payload is enabled. False otherwise.
            git_url (str):
                Link to the payload in the GIT repository.
            loglevel (str):
                The log level for processing the payload. Either "INFO" or "DEBUG".

        """

        new_item = {
            "name": name if name else filename,
            "filename": filename,
            "dependencies": dependencies if dependencies else [],
            "logfile": logfile,
            "status": status,
            "enabled": enabled,
            "git_url": git_url,
            "loglevel": loglevel,
            "log_debug": 0,
            "log_info": 0,
            "log_warning": 0,
            "log_error": 0,
            "log_critical": 0,
        }
        self.payload_items = pd.concat(
            [self.payload_items, pd.DataFrame([new_item])],
            ignore_index=True,
        )

        new_item = self.payload_items.tail(1).to_dict(orient="records")[0]
        new_item["index"] = self.payload_items.index[-1]

        return new_item

    # end method definition

    def update_payload_item(
        self,
        index: int,
        update_data: dict,
    ) -> bool:
        """Update an existing item in the PayloadList.

        Args:
            index (int):
                The position of the payload.
            update_data (str):
                The data of the item.

        Returns:
            bool:
                True = success, False = error.

        """

        if index not in self.payload_items.index:
            self.logger.error("Illegal index -> %s for payload update!", index)
            return False

        for column in self.payload_items.columns:
            if column in update_data:
                tmp = self.payload_items.loc[index].astype(object)
                tmp[column] = update_data[column]
                self.payload_items.loc[index] = tmp

        return True

    # end method definition

    def remove_payload_item(self, index: int) -> bool:
        """Remove an item by its index from the PayloadList.

        Args:
            index (int):
                The index of the item to remove.

        Returns:
            bool:
                True = success. False = failure.

        Raises:
            IndexError: If the index is out of range.

        """

        if index not in self.payload_items.index:
            self.logger.error("Index -> %s is out of range!", index)
            return False

        self.payload_items.drop(index, inplace=True)

        return True

    # end method definition

    def move_payload_item_up(self, index: int) -> int | None:
        """Move an item up by one position in the PayloadList.

        Args:
            index (int): The index of the item to move up.

        Results:
            bool: False, if the index is out of range or the item is already at the top.
                  True otherwise

        """

        if index <= 0 or index >= len(self.payload_items):
            self.logger.error(
                "Index -> %s is out of range or already at the top!",
                str(index),
            )
            return None

        self.payload_items.iloc[[index - 1, index]] = self.payload_items.iloc[[index, index - 1]].to_numpy()

        new_postion = self.payload_items.index.get_loc(index)

        return new_postion

    # end method definition

    def move_payload_item_down(self, index: int) -> int | None:
        """Move an item down by one position in the PayloadList.

        Args:
            index (int):
                The index of the item to move down.

        Returns:
            int:
                The new position of the payload item.

        """

        if index < 0 or index >= len(self.payload_items) - 1:
            self.logger.error(
                "Index -> %s is out of range or already at the bottom!",
                str(index),
            )
            return None

        self.payload_items.iloc[[index, index + 1]] = self.payload_items.iloc[[index + 1, index]].to_numpy()

        new_postion = self.payload_items.index.get_loc(index)

        return new_postion

    # end method definition

    def __len__(self) -> int:
        """Return the number of items in the PayloadList.

        Returns:
            int:
                The count of items in the list.

        """

        return len(self.payload_items)

    # end method definition

    def __getitem__(self, index: int) -> pd.Series:
        """Get an item by its index using the "[index]" syntax.

        Args:
            index (int):
                The index of the item to retrieve.

        Returns:
            pd.Series:
                The item at the specified index as a Series.

        Raises:
            IndexError: If the index is out of range.

        Example:
            >>> payload_list = PayloadList()
            >>> payload_list.add_item("Task1", "task1.txt")
            >>> payload_list[0]
            name        Task1
            file    task1.txt
            dependencies    NaN
            logfile      None
            status    planned
            Name: 0, dtype: object

        """

        if index not in self.payload_items.index:
            exception = "Index -> {} is out of range".format(index)
            raise IndexError(exception)

        return self.payload_items.loc[index]

    # end method definition

    def __setitem__(self, index: int, value: dict) -> None:
        """Set an item at the specified index using the "[index]" syntax.

        Args:
            index (int): The index to set the item at.
            value (dict): The item dictionary to set, which must include 'name' and 'file' keys.

        Raises:
            IndexError: If the index is out of range.
            ValueError: If the provided value is not a valid item dictionary.

        Example:
            >>> payload_list = PayloadList()
            >>> payload_list.add_item("Task1", "task1.txt")
            >>> payload_list[0]
            name        Task1
            filename    task1.txt
            dependencies    NaN
            logfile      None
            status    planned
            Name: 0, dtype: object
            >>> payload_list[0] = {"name": "Updated Task1", "file": "updated_task1.txt", "status": "completed"}
            >>> payload_list[0]
            name        Updated Task1
            filename    updated_task1.txt
            dependencies    NaN
            logfile      None
            status    completed
            Name: 0, dtype: object

        """

        if not {"name", "filename"}.issubset(value):
            exception = ("Value must be a dictionary with at least 'name' and 'filename' keys",)
            raise ValueError(
                exception,
            )

        if index not in self.payload_items.index:
            exception = "Index -> {} is out of range".format(index)
            raise IndexError(exception)

        self.payload_items.loc[index] = value

    # end method definition

    def __delitem__(self, index: int) -> None:
        """Delete an item by its index.

        Args:
            index (int): The index of the item to delete.

        Raises:
            IndexError: If the index is out of range.

        """

        self.remove_item(index=index)

    # end method definition

    def __getattr__(self, attribute: str) -> pd.Series:
        """Provide dynamic access to columns using the "." syntax.

        For example, `payload_list.name` will return the 'name' column values.

        Args:
            attribute (str): The column name to retrieve.

        Returns:
            pd.Series: The specified column as a pandas Series.

        Example:
            >>> payload_list = PayloadList()
            >>> payload_list.add_item("Task1", "task1.txt")
            >>> payload_list.name
            0    Task1
            Name: name, dtype: object

        """

        if attribute in self.payload_items.columns:
            return self.payload_items[attribute]

        self.logger.error("Payload list has no attribute -> '%s'", attribute)
        return None

    # end method definition

    def __repr__(self) -> str:
        """Return a string representation of the PayloadList for logging and debugging.

        Returns:
            str:
                A string representing the items in the DataFrame.

        """

        return self.payload_items.to_string(index=True)

    # end method definition

    def __iter__(self) -> iter:
        """Iterate over the rows of the PayloadList.

        Returns:
            iterator: An iterator over the rows of the payload_items DataFrame.

        Example:
            >>> payload_list = PayloadList()
            >>> payload_list.add_item("Task1", "task1.txt")
            >>> payload_list.add_item("Task2", "task2.txt")
            >>> for payload in payload_list:
            >>>     print(payload)
            name        Task1
            filename    task1.txt
            dependencies    NaN
            logfile      None
            status    planned
            Name: 0, dtype: object
            name        Task2
            file    task2.txt
            dependencies    NaN
            logfile      None
            status    planned
            Name: 1, dtype: object

        """

        # Return an iterator for the rows of the DataFrame
        for _, row in self.payload_items.iterrows():
            yield row

    # end method definition

    def pick_runnables(self) -> pd.DataFrame:
        """Pick all PayloadItems with status "planned" and no dependencies on items that are not in status "completed".

        Returns:
            pd.DataFrame:
                A list of runnable payload items.

        """

        def is_runnable(row: pd.Series) -> bool:
            # Check if item is enabled:
            if not row["enabled"]:
                return False

            # Check if all dependencies have been completed
            dependencies: list[int] = row["dependencies"]

            return all(self.payload_items.loc[dep, "status"] == "completed" for dep in dependencies or [])

        # end sub-method definition

        if self.payload_items.empty:
            return None

        # Filter payload items to find runnable items
        runnable_df: pd.DataFrame = self.payload_items[
            (self.payload_items["status"] == "planned") & self.payload_items.apply(is_runnable, axis=1)
        ].copy()

        # Add index as a column to the resulting DataFrame
        runnable_df["index"] = runnable_df.index

        # Log each runnable item
        for _, row in runnable_df.iterrows():
            self.logger.info(
                "Added payload file -> '%s' with index -> %s to runnable queue.",
                row["name"] if row["name"] else row["filename"],
                row["index"],
            )

        return runnable_df

    # end method definition

    def process_payload_list(self) -> None:
        """Process runnable payloads.

        Continuously checks for runnable payload items and starts their
        "process_payload" method in separate threads.
        Runs as a daemon until the customizer ends.
        """

        def run_and_complete_payload(payload_item: pd.Series) -> None:
            """Run the payload's process_payload method and marks the status as completed afterward."""

            start_time = datetime.now(timezone.utc)
            self.update_payload_item(payload_item["index"], {"start_time": start_time})

            # Create a logger with thread_id:
            thread_logger = logging.getLogger(
                name="Payload_{}".format(payload_item["index"]),
            )

            thread_logger.setLevel(level=payload_item["loglevel"])

            # Check if the logger already has handlers. If it does, they are removed before creating new ones.
            if thread_logger.hasHandlers():
                thread_logger.handlers.clear()

            # Create a handler for the logger:
            handler = logging.FileHandler(filename=payload_item.logfile)

            # Create a formatter:
            formatter = logging.Formatter(
                fmt="%(asctime)s %(levelname)s [%(name)s] [%(threadName)s] %(message)s",
                datefmt="%d-%b-%Y %H:%M:%S",
            )
            # Add the formatter to the handler
            handler.setFormatter(fmt=formatter)
            thread_logger.addHandler(hdlr=handler)

            # If hostname is set, configure log handler so forward logs
            if api_settings.victorialogs_host:
                handler_kwargs = {
                    "host": api_settings.victorialogs_host,
                    "port": api_settings.victorialogs_port,
                    "app": "Customizer",
                    "payload_item": payload_item["index"],
                    "payload_file": payload_item["filename"],
                }

                # Read namespace if available and add as kwarg to loghandler
                file_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
                if os.path.isfile(file_path):
                    with open(file_path) as file:
                        handler_kwargs["namespace"] = file.read()

                thread_logger.addHandler(VictoriaLogsHandler(**handler_kwargs))

            if len(thread_logger.filters) == 0:
                thread_logger.debug("Adding log count filter to logger")
                thread_logger.addFilter(
                    LogCountFilter(
                        payload_items=self.payload_items,
                        index=payload_item["index"],
                    ),
                )

            thread_logger.info(
                "Start processing of payload -> '%s' (%s) from filename -> '%s'",
                payload_item["name"],
                payload_item["index"],
                payload_item["filename"],
            )

            local = threading.local()

            # Read customizer Settings from customizerSettings in the payload:
            payload = load_payload(payload_item["filename"])

            if not payload:
                success = False

            if payload:
                customizer_settings = payload.get("customizerSettings", {})

                # Overwrite the customizer settings with the payload specific ones:
                customizer_settings.update(
                    {
                        "cust_payload": payload_item["filename"],
                        "cust_payload_gz": "",
                        "cust_payload_external": "",
                        "cust_log_file": payload_item.logfile,
                    },
                )

                try:
                    local.customizer_thread_object = Customizer(
                        settings=customizer_settings,
                        logger=thread_logger,
                    )
                    thread_logger.info("Customizer initialized successfully.")

                    thread_logger.debug(
                        "Customizer Settings -> \n %s",
                        pprint.pformat(
                            local.customizer_thread_object.settings.model_dump(),
                        ),
                    )

                    if customizer_settings.get("profiling", False):
                        from pyinstrument import Profiler

                        profiler = Profiler()
                        profiler.start()

                    if customizer_settings.get("cprofiling", False):
                        import cProfile
                        import pstats

                        cprofiler = cProfile.Profile()
                        cprofiler.enable()

                    success = local.customizer_thread_object.customization_run()

                    if customizer_settings.get("cprofiling", False):
                        cprofiler.disable()

                    if customizer_settings.get("profiling", False):
                        profiler.stop()

                    now = datetime.now(timezone.utc)
                    log_path = os.path.dirname(payload_item.logfile)
                    profile_log_prefix = (
                        f"{log_path}/{payload_item['index']}_{payload_item['name']}_{now.strftime('%Y-%m-%d_%H-%M-%S')}"
                    )

                    if customizer_settings.get("cprofiling", False):
                        import io

                        s = io.StringIO()
                        stats = pstats.Stats(cprofiler, stream=s).sort_stats("cumtime")
                        stats.print_stats()
                        with open(f"{profile_log_prefix}.log", "w+") as f:
                            f.write(s.getvalue())
                        stats.dump_stats(filename=f"{profile_log_prefix}.cprof")

                    if customizer_settings.get("profiling", False):
                        with open(f"{profile_log_prefix}.html", "w") as f:
                            f.write(profiler.output_html())

                except ValidationError:
                    thread_logger.error("Validation error!")
                    success = False

                except StopOnError:
                    success = False
                    thread_logger.error(
                        "StopOnErrorException occurred. Stopping payload processing...",
                    )

                except Exception:
                    success = False
                    thread_logger.error(
                        "An exception occurred: \n%s",
                        traceback.format_exc(),
                    )

            if not success:
                thread_logger.error(
                    "Failed to initialize payload -> '%s'!",
                    payload_item["filename"],
                )
                # Update the status to "failed" in the DataFrame after processing finishes
                self.update_payload_item(payload_item["index"], {"status": "failed"})

            else:
                # Update the status to "completed" in the DataFrame after processing finishes
                self.update_payload_item(payload_item["index"], {"status": "completed"})

            stop_time = datetime.now(timezone.utc)
            duration = stop_time - start_time

            # Format duration in hh:mm:ss
            hours, remainder = divmod(duration.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            formatted_duration = f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"

            self.update_payload_item(
                payload_item["index"],
                {"stop_time": stop_time, "duration": formatted_duration},
            )

        # end  def run_and_complete_payload()

        while not self._stopped:
            # Get runnable items as subset of the initial data frame:
            runnable_items: pd.DataFrame = self.pick_runnables()

            # Start a thread for each runnable item (item is a pd.Series)
            if runnable_items is not None:
                for _, item in runnable_items.iterrows():
                    # Update the status to "running" in the data frame to prevent re-processing
                    self.payload_items.loc[
                        self.payload_items["name"] == item["name"],
                        "status",
                    ] = "running"

                    # Start the process_payload method in a new thread
                    thread = threading.Thread(
                        target=run_and_complete_payload,
                        args=(item,),
                        name=item["name"],
                    )
                    thread.start()
                    break

            # Sleep briefly to avoid a busy wait loop
            time.sleep(1)

    # end method definition

    def run_payload_processing(self) -> None:
        """Start the `process_payload_list` method in a daemon thread."""

        scheduler_thread = threading.Thread(
            target=self.process_payload_list,
            daemon=True,
            name="Scheduler",
        )

        self.logger.info(
            "Starting '%s' thread for payload list processing...",
            str(scheduler_thread.name),
        )
        self._stopped = False
        scheduler_thread.start()

        self.logger.info(
            "Waiting for thread -> '%s' to complete...",
            str(scheduler_thread.name),
        )
        scheduler_thread.join()
        self.logger.info("Thread -> '%s' has completed.", str(scheduler_thread.name))

    # end method definition

    def stop_payload_processing(self) -> None:
        """Set a stop flag which triggers the stopping of further payload processing."""

        self._stopped = True

    # end method definition
