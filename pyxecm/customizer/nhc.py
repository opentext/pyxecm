"""NHC stands for National Hurricane Center.

It is a comprehensive data source for tropical storms around the US (Atlantic + Pacific basin).

See: https://www.nhc.noaa.gov
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import multiprocessing
import os
import tempfile
import threading
import time

from pyxecm.helper import Data

default_logger = logging.getLogger("pyxecm.customizer.nhc")

try:
    import pandas as pd

    pandas_installed = True
except ModuleNotFoundError:
    default_logger.warning(
        "Module pandas is not installed. Customizer will not support bulk workspace creation.",
    )
    pandas_installed = False

try:
    import matplotlib as mpl
    from tropycal import rain, tracks

    mpl.use("Agg")
    tropycal_installed = True
except ModuleNotFoundError:
    default_logger.warning(
        "Module tropycal is not installed. Customizer will not support NHC storm data source.",
    )
    tropycal_installed = False

STORM_IMAGE_BASE_PATH = "nhc/images/"
STORM_DATA_BASE_PATH = "nhc/data/"
STORM_IMAGE_PLOT_MAX_RETRY = 7

STORM_NUMBERS = {
    "01": "ONE",
    "02": "TWO",
    "03": "THREE",
    "04": "FOUR",
    "05": "FIVE",
    "06": "SIX",
    "07": "SEVEN",
    "08": "EIGHT",
    "09": "NINE",
    "10": "TEN",
    "11": "ELEVEN",
    "12": "TWELVE",
    "13": "THIRTEEN",
    "14": "FOURTEEN",
    "15": "FIFTEEN",
    "16": "SIXTEEN",
    "17": "SEVENTEEN",
    "18": "EIGHTEEN",
    "19": "NINETEEN",
    "20": "TWENTY",
    "21": "TWENTY-ONE",
    "22": "TWENTY-TWO",
    "23": "TWENTY-THREE",
    "24": "TWENTY-FOUR",
    "25": "TWENTY-FIVE",
    "26": "TWENTY-SIX",
    "27": "TWENTY-SEVEN",
    "28": "TWENTY-EIGHT",
    "29": "TWENTY-NINE",
    "30": "THIRTY",
    "31": "THIRTY-ONE",
    "32": "THIRTY-TWO",
    "33": "THIRTY-THREE",
    "34": "THIRTY-FOUR",
    "35": "THIRTY-FIVE",
    "36": "THIRTY-SIX",
    "37": "THIRTY-SEVEN",
    "38": "THIRTY-EIGHT",
    "39": "THIRTY-NINE",
    "40": "FORTY",
    "41": "FORTY-ONE",
    "42": "FORTY-TWO",
    "43": "FORTY-THREE",
    "44": "FORTY-FOUR",
    "45": "FORTY-FIVE",
    "46": "FORTY-SIX",
    "47": "FORTY-SEVEN",
    "48": "FORTY-Eight",
    "49": "FORTY-Nine",
    "50": "FIFTY",
    "51": "FIFTY-ONE",
    "52": "FIFTY-TWO",
    "53": "FIFTY-THREE",
    "54": "FIFTY-FOUR",
    "55": "FIFTY-FIVE",
    "56": "FIFTY-SIX",
    "57": "FIFTY-SEVEN",
    "58": "FIFTY-EIGHT",
    "59": "FIFTY-NINE",
    "60": "SIXTY",
    "61": "SIXTY-ONE",
    "62": "SIXTY-TWO",
    "63": "SIXTY-THREE",
    "64": "SIXTY-FOUR",
    "65": "SIXTY-FIVE",
    "66": "SIXTY-SIX",
    "67": "SIXTY-SEVEN",
    "68": "SIXTY-EIGHT",
    "69": "SIXTY-NINE",
    "70": "SEVENTY",
    "71": "SEVENTY-ONE",
    "72": "SEVENTY-TWO",
    "73": "SEVENTY-THREE",
    "74": "SEVENTY-FOUR",
    "75": "SEVENTY-FIVE",
    "76": "SEVENTY-SIX",
    "77": "SEVENTY-SEVEN",
    "78": "SEVENTY-EIGHT",
    "79": "SEVENTY-NINE",
    "80": "EIGHTY",
    "81": "EIGHTY-ONE",
    "82": "EIGHTY-TWO",
    "83": "EIGHTY-THREE",
    "84": "EIGHTY-FOUR",
    "85": "EIGHTY-FIVE",
    "86": "EIGHTY-SIX",
    "87": "EIGHTY-SEVEN",
    "88": "EIGHTY-EIGHT",
    "89": "EIGHTY-NINE",
    "90": "NINETY",
    "91": "NINETY-ONE",
    "92": "NINETY-TWO",
    "93": "NINETY-THREE",
    "94": "NINETY-FOUR",
    "95": "NINETY-FIVE",
    "96": "NINETY-SIX",
    "97": "NINETY-SEVEN",
    "98": "NINETY-EIGHT",
    "99": "NINETY-NINE",
}


class NHC:
    """Class NHC is used to retrieve data from National Hurricane Center."""

    logger: logging.Logger = default_logger

    _basin: str | None = None
    _basin_data = None  # don't use tropycal specific data types here - this clashes if the module is not installed!
    _rain_data: pd.DataFrame
    # currently the rain data source seems to only go from ... to 2020
    _rain_min_year: int | None = None
    _rain_max_year: int | None = None
    _session = None

    _download_dir_images: str
    _download_dir_data: str

    _strom_plot_exclusions = None

    def __init__(
        self,
        basin: str = "both",
        source: str = "hurdat",
        load_rain_data: bool = True,
        include_btk: bool = True,
        storm_plot_exclusions: list | None = None,
        download_dir_images: str = STORM_IMAGE_BASE_PATH,
        download_dir_data: str = STORM_DATA_BASE_PATH,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the NHC object.

        Args:
            basin (str, optional):
                The name of the basin. Possible values:
                - "north_atlantic" (using HURDAT2 and IBTrACS data source)
                - "east_pacific" (using HURDAT2 and IBTrACS data source)
                - "both" ("north_atlantic" & "east_pacific" combined)
                - "west_pacific" (using IBTrACS data source)
                - "north_indian" (using IBTrACS data source)
                - "south_indian" (using IBTrACS data source)
                - "australia" (using IBTrACS* : special case)
                - "south_pacific" (using IBTrACS)
                - "south_atlantic" (using IBTrACS)
                - "all" (suing all IBTrACS)
            source (str, optional):
                Data source to read in. Default is HURDAT2.
                Possible values:
                "hurdat" - HURDAT2 data source for the North Atlantic and East/Central Pacific basins
                "ibtracs" - ibtracs data source for regional or global data
            load_rain_data (bool ,optional):
                Controls whether or not the rain data is loaded as well.
                This usees a Pandas data frame.
            include_btk (bool, optional):
                If True, the best track data from NHC for the most recent years where it doesn't
                exist in HURDAT2 will be added into the dataset. Valid for “north_atlantic” and
                “east_pacific” basins. Default is True.
            storm_plot_exclusions (list | None, optional):
                An optional list of storms to exclude from plotting. Defaults to None.
                Use the storm codes like "AL022018" as values for the exclusion list.
            download_dir_images (str, optional):
                Where to store the downloaded storm images. It can be a relative or absolute path.
                If it is a relative path the default tmp path of the operating system will be used
                as a prefix.
            download_dir_data (str, optional):
                Where to store the downloaded storm data files. It can be a relative or absolute path.
                If it is a relative path the default tmp path of the operating system will be used
                as a prefix.
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("nhc")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        # Store the credentials and parameters in a config dictionary:

        if basin:
            # Load the storm basin dataset
            self._basin_data = tracks.TrackDataset(basin=basin, source=source, include_btk=include_btk)
            self._basin = basin

        # rain data from Weather Prediction Center (WPC) data source
        if load_rain_data:
            self._rain_data = rain.RainDataset()
            if self._rain_data:
                self._rain_min_year = int(self._rain_data.rain_df["Year"].min())
                self._rain_max_year = int(self._rain_data.rain_df["Year"].max())
        else:
            self._rain_data = None

        self._data = Data(logger=self.logger)

        self._download_dir_images = download_dir_images
        self._download_dir_data = download_dir_data

        self._strom_plot_exclusions = storm_plot_exclusions

    # end method definition

    def get_data(self) -> Data:
        """Get the Data object that holds all processed PHT products.

        Returns:
            Data:
                Datastructure with all processed NHC storm data.

        """

        return self._data

    # end method definition

    def get_basin_data(self) -> tracks.TrackDataset:
        """Return the tracks data set.

        Returns:
            tracks.TrackDataset:
                The track data set for the basin(s).

        """

        return self._basin_data

    # end method definition

    def get_rain_data(self) -> pd.DataFrame | None:
        """Get the complete rainfall data.

        Returns:
            pd.DataFrame:
                Rain data from Weather Prediction Center (WPC) data source.
                None in case there's no data.

        """

        if not self._rain_data:
            self._rain_data = rain.RainDataset()

        return self._rain_data.rain_df

    # end method definition

    def get_season(self, year: int, basin: str = "both", source: str = "hurdat") -> tracks.Season | None:
        """Get data on a storm season (all stroms in a particular year).

        See: https://tropycal.github.io/tropycal/api/generated/tropycal.tracks.TrackDataset.html

        Args:
            year (int):
                The year of the storm, e.g. 2005.
            basin (str, optional):
                The basic of the storm, values can be:
                * "north_atlantic" (using HURDAT2 and IBTrACS data source)
                * "east_pacific" (using HURDAT2 and IBTrACS data source)
                * "both" ("north_atlantic" & "east_pacific" combined)
                * "west_pacific" (using IBTrACS data source)
                * "north_indian" (using IBTrACS data source)
                * "south_indian" (using IBTrACS data source)
                * "australia" (using IBTrACS* : special case)
                * "south_pacific" (using IBTrACS)
                * "south_atlantic" (using IBTrACS)
                * "all" (suing all IBTrACS)
            source (str, optional):
                Data source to read in. Default is HURDAT2.
                Possible values:
                "hurdat" - HURDAT2 data source for the North Atlantic and East/Central Pacific basins
                "ibtracs" - ibtracs data source for regional or global data

        Returns:
            tracks.Season:
                Season data object or None in case of an error.

        """

        # Load the storm basin dataset
        if not self._basin_data:
            self._basin_data = tracks.TrackDataset(basin=basin, source=source)

        # Get storm data by name and year
        try:
            season_data = self._basin_data.get_season(year=year)
        except ValueError as e:
            self.logger.info(
                "Cannot find season data for year -> %s!; error -> %s",
                str(year),
                str(e),
            )
            return None

        return season_data

    # end method definition

    def get_storm(
        self,
        name: str | None = None,
        year: int | None = None,
        storm_id: str | None = None,
        basin: str = "both",
    ) -> tracks.Storm:
        """Get data on a particular storm.

        Args:
            name (str):
                The nickname of the storm, like 'Katrina'.
            year (int):
                The year of the storm, e.g. 2005.
            storm_id (str):
                Alternatively to name and year you can provide the id of the storm
            basin (str):
                The basic of the storm, values can be:
                * "north_atlantic" (using HURDAT2 and IBTrACS data source)
                * "east_pacific" (using HURDAT2 and IBTrACS data source)
                * "both" ("north_atlantic" & "east_pacific" combined)
                * "west_pacific" (using IBTrACS data source)
                * "north_indian" (using IBTrACS data source)
                * "south_indian" (using IBTrACS data source)
                * "australia" (using IBTrACS* : special case)
                * "south_pacific" (using IBTrACS)
                * "south_atlantic" (using IBTrACS)
                * "all" (suing all IBTrACS)

        Returns:
            dict:
                The storm data or None in case of an error.

        """

        # Load the storm basin dataset
        if not self._basin_data:
            self._basin_data = tracks.TrackDataset(basin=basin)

        # Get storm data by name and year
        try:
            storm_data = (
                self._basin_data.get_storm(storm=storm_id)
                if storm_id
                else self._basin_data.get_storm(storm=(name, year))
            )
        except (ValueError, KeyError) as e:
            self.logger.info(
                "Cannot find storm data for storm -> '%s'%s; error -> %s",
                name if name else storm_id,
                " and year -> {}".format(str(year)) if year else "",
                str(e),
            )
            return None

        return storm_data

    # end method definition

    def get_storm_rainfall(self, storm_data: tracks.Storm) -> pd.DataFrame:
        """Get the rainfall data of a given storm.

        Args:
            storm_data (tracks.Storm): Storm data. This needs to be retrieved
                                       with get_storm() before.

        Returns:
            pd.DataFrame: Pandas data frame with the storm rain data.

        """

        if not self._rain_data:
            self._rain_data = rain.RainDataset()

        try:
            storm_rain = self._rain_data.get_storm_rainfall(storm_data)
        except RuntimeError as re:
            self.logger.info(
                "Cannot find rain data for storm -> '%s' in year -> %s; message -> %s",
                storm_data["name"],
                str(storm_data["season"]),
                str(re),
            )
            return None

        return storm_rain

    # end method definition

    def get_storm_image_path(self) -> str:
        """Get the path to the filesystem directory where storm plot images should be saved.

        Returns:
            str:
                The path to the filesystem directory where storm plot images should be saved.

        """

        return os.path.join(tempfile.gettempdir(), self._download_dir_images)

    # end method definition

    def get_storm_data_path(self) -> str:
        """Get the path to the filesystem directory where storm data should be saved.

        Returns:
            str:
                The path to the filesystem directory where storm data should be saved.

        """

        return os.path.join(tempfile.gettempdir(), self._download_dir_data)

    # end method definition

    def get_storm_file_name(self, storm_id: str, file_type: str, suffix: str = "") -> str:
        """Determine the save path and filename of the plot image or data files of a given storm.

        Args:
            storm_id (str):
                The ID of the storm.
            file_type (str):
                The file type. Can be "svg", "png", "json", ...
            suffix (str, optional):
                For special image files (like rain) we want to add a special name suffix.

        """

        file_name = storm_id
        # Add a suffix for special cases:
        if suffix:
            file_name += suffix
        file_name += "." + file_type

        return file_name

    # end method definition

    def save_storm_track_image(
        self,
        storm_data: tracks.Storm,
        image_path: str,
        domain: str | dict = "dynamic",
    ) -> tuple[bool, str]:
        """Save an image (map) file of a given storm track.

        Args:
            storm_data (tracks.Storm):
                The storm data.
            image_path (str):
                Where to store the image file.  If the directory
                does not exist it is created.
            domain (str | dict, optional):
                Zoom area in geo coordinates. Defaults to "dynamic".

        Returns:
            bool:
                True = success
                False = error (at least issues
            str:
                Error / warning message.

        """

        retries = 0

        # Loop for retries:
        while True:
            try:
                storm_data.plot(
                    domain=domain,
                    save_path=image_path,
                )
            except Exception as plot_error:
                if retries > STORM_IMAGE_PLOT_MAX_RETRY:
                    return (False, str(plot_error))
                retries += 1
            else:
                return (True, "Success" if retries == 0 else "Success after {} retries".format(retries))

    # end method definition

    def save_storm_track_data(
        self,
        storm_data: tracks.Storm,
        data_path: str,
        save_general_storm_attributes: bool = False,
    ) -> None:
        """Save a data file of a given storm track (this is a data series over time).

        Args:
            storm_data (tracks.Storm):
                The storm object (retreived by get_storm() before).
            data_path (str):
                Where to store the data file.
            save_general_storm_attributes (bool, optional):
                Do we want to have (repeatedly) the
                general storm attributes in the data set?

        """

        data = Data(
            storm_data.to_dataframe(attrs_as_columns=save_general_storm_attributes),
            logger=self.logger,
        )
        if not data:
            return
        if ("basin" not in data.get_columns() or []) and ("wmo_basin" in data.get_columns() or []):
            data.rename_column(old_column_name="wmo_basin", new_column_name="basin")
        data.drop_columns(
            column_names=["extra_obs", "special", "operational_id", "wmo_basin"],
        )
        data.rename_column(old_column_name="lat", new_column_name="latitude")
        data.rename_column(old_column_name="lon", new_column_name="longitude")
        if data_path.endswith("json"):
            result = data.save_json_data(json_path=data_path)
        elif data_path.endswith("xlsx"):
            result = data.save_excel_data(excel_path=data_path)
        else:
            self.logger.error("Illegal file type for storm track data!")
            return

        # We try to be nice to memory consumption:
        del data

        if result:
            self.logger.info(
                "Successfully saved track data of storm -> '%s' (%s) to file -> '%s'",
                storm_data["name"],
                storm_data["id"],
                data_path,
            )
        else:
            self.logger.error(
                "Failed to save track data of storm -> '%s' (%s) to file -> '%s'",
                storm_data["name"],
                storm_data["id"],
                data_path,
            )

    # end method definition

    def save_storm_rain_image(
        self,
        storm_data: tracks.Storm,
        image_path: str,
        domain: str | dict = "dynamic",
    ) -> tuple[bool, str]:
        """Save an image file for a given storm rainfall.

        Args:
            storm_data (tracks.Storm):
                The storm object (retreived by get_storm() before).
            image_path (str):
                Where to store the image file. If the directory
                does not exist it is created.
            domain (str | dict, optional):
                Zoom area in geo coordinates. Defaults to "dynamic".

        Returns:
            bool:
                True = success
                False = error (at least issues
            str:
                Error / warning message.

        """

        retries = 0

        # Loop for retries:
        while True:
            try:
                # Interpolate to grid
                grid = self._rain_data.interpolate_to_grid(storm_data, return_xarray=True)
                levels = [1, 2, 4, 8, 12, 16, 20, 30, 40, 50, 60]
                self._rain_data.plot_rain_grid(
                    storm_data,
                    grid,
                    levels,
                    domain=domain,
                    save_path=image_path,
                )
            except Exception as plot_error:
                if retries > STORM_IMAGE_PLOT_MAX_RETRY:
                    return (False, str(plot_error))
                retries += 1
            else:
                return (True, "Success" if retries == 0 else "Success after {} retries".format(retries))

    # end method definition

    def save_storm_rain_data(
        self,
        storm_data: tracks.Storm,
        data_path: str,
    ) -> None:
        """Save a data file for a given storm rainfall.

        Args:
            storm_data (tracks.Storm):
                The storm object (retreived by get_storm() before).
            data_path (str):
                Where to store the data file.

        """

        data = Data(self._rain_data.get_storm_rainfall(storm_data), logger=self.logger)
        if not data:
            return
        if data_path.endswith("json"):
            result = data.save_json_data(json_path=data_path)
        elif data_path.endswith("xlsx"):
            result = data.save_excel_data(excel_path=data_path)
        else:
            self.logger.error("Illegal file type!")
            return

        if result:
            self.logger.info(
                "Successfully saved rainfall data of storm -> '%s' (%s) to file -> '%s'",
                storm_data["name"],
                storm_data["id"],
                data_path,
            )
        else:
            self.logger.error(
                "Failed to save rainfall data of storm -> '%s' (%s) to file -> '%s'",
                storm_data["name"],
                storm_data["id"],
                data_path,
            )

    # end method definition

    def load_storms(
        self,
        year_start: int,
        year_end: int,
        save_track_images: list | None = None,
        save_track_data: list | None = None,
        save_rain_images: list | None = None,
        save_rain_data: list | None = None,
        skip_existing_files: bool = True,
        load_async: bool = True,
        async_processes: int = 8,
    ) -> bool:
        """Load storm into a data frame and save files for storm tracks and rainfall (data and image files).

        Args:
            year_start (int):
                The start year (season).
            year_end (int):
                The end year (season).
            save_track_images (list, optional):
                A list of image types, e.g. ["svg", "png"], to save the storm track.
            save_track_data (list, optional):
                A list of data types, e.g. ["json", "xlsx"], to save the storm track.
            save_rain_images (list, optional):
                A list of image types, e.g. ["svg", "png"], to save the storm rainfall.
            save_rain_data (list, optional):
                A list of data types, e.g. ["json", "xlsx"], to save the storm rainfall.
            skip_existing_files (bool, optional):
                Skip files that have been saved before.
            load_async (bool, optional):
                Whether or not we want the plot method to run asynchronous. Default
                is True. In case of issues or deadlocks you may want to set it to False.
            async_processes (int, optional):
                Number of async processes to generate the plot files.
                Default is 5.

        """

        data = self.get_data()
        image_dir = self.get_storm_image_path()
        # Create folder if it does not exist
        if not os.path.exists(image_dir):
            os.makedirs(image_dir)
        data_dir = self.get_storm_data_path()
        # Create folder if it does not exist
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)

        self.logger.info(
            "Loading data from National Hurricane Center from year -> %s to year -> %s for basin -> '%s'",
            year_start,
            year_end,
            self._basin,
        )

        if save_track_images:
            self.logger.info("Generate track plot files -> %s", str(save_track_images))
        if save_track_data:
            self.logger.info("Generate track data files -> %s", str(save_track_data))
        if save_rain_images:
            self.logger.info("Generate rain plot files -> %s", str(save_rain_images))
        if save_rain_data:
            self.logger.info("Generate rain data files -> %s", str(save_rain_data))
        self.logger.info("Existing plot files will %sbe reused.", "" if skip_existing_files else "not ")

        if load_async:
            self.logger.info("Initiate plot storm worker pool of size -> %d (asynchronous)...", async_processes)
        else:
            self.logger.info("Initiate plot storm worker pool of size -> %d (synchronous)...", async_processes)

        # Create the pool with a given number of processes.
        # maxtasksperchild=1 makes sure that the processes really
        # terminate after the called method completes. We want
        # to do this to really free up the memory as the plot()
        # methods tend to "memory leak" and pods will be evicted
        # over time.
        pool = multiprocessing.Pool(processes=async_processes, maxtasksperchild=1)
        # Collect the results of the processes in this list:
        results = []

        if load_async:
            done_event = threading.Event()

            # Start the result collector thread before submitting plot tasks.
            # This thread is used for printing success or failure messages.
            # We don't want to do this in the actual plot files as this
            # causes issues (deadlock) if printing log messages in the process
            # worker methods.
            collector_thread = threading.Thread(
                name="NHC Result Collector",
                target=self.result_collector,
                args=(results, done_event),
            )
            self.logger.info("Start collector thread for logging plot process results...")
            collector_thread.start()

        for year in range(year_start, year_end + 1):
            season = self.get_season(year=year)
            data.append(season.to_dataframe())
            for storm_id, storm_value in season.dict.items():
                storm_name = storm_value["name"]
                storm_operational_id = storm_value.get("operational_id", storm_id)
                if storm_operational_id and storm_operational_id != storm_id:
                    self.logger.info(
                        "Storm '%s' has an operational ID -> '%s' which is different from the storm ID -> '%s",
                        storm_name,
                        storm_operational_id,
                        storm_id,
                    )
                storm_data = self.get_storm(storm_id=storm_id)
                if not storm_data:
                    self.logger.debug("Cannot get storm data form storm -> '%s' (%s)", storm_name, storm_id)
                    return False
                storm_dict = storm_data.to_dict()
                if storm_name == "UNNAMED":
                    # Tropycal (based on HURDAT) has unnamed storms with name "UNNAMED"
                    # while most other data sources have them as English number names
                    # like "Two" or "Eight". For this reason we change the name of unnamed
                    # storms here as well and write it back into the data frame and
                    # the storm data structure:
                    storm_name = STORM_NUMBERS[storm_id[2:4]]
                    storm_data["name"] = storm_name
                    data.set_value(
                        column="name",
                        value=storm_name,
                        condition=(data["id"] == storm_id),  # this is a boolean pd.Series
                    )
                self.logger.info(
                    "Processing storm -> '%s' (%s) in year -> %s...",
                    storm_name,
                    storm_id,
                    year,
                )
                # The category ("type") of the storm is a time series as the storm has
                # a different category over time. We want the peak category:
                type_series = storm_dict.get("type", None)
                if type_series:
                    peak_index = storm_data.dict["vmax"].index(
                        max(storm_data.dict["vmax"]),
                    )
                    storm_type = type_series[peak_index]

                    # Add storm type as this is not included in season.to_dataframe():
                    if "type" not in data.get_columns():
                        data.add_column(new_column="type", data_type="string")
                    data.set_value(
                        column="type",
                        value=storm_type,
                        condition=(data["id"] == storm_id),  # this is a boolean pd.Series
                    )

                # Add year as this is not included in season.to_dataframe():
                if "year" not in data.get_columns():
                    data.add_column(new_column="year", data_type="Int64")
                data.set_value(
                    column="year",
                    value=year,
                    condition=(data["id"] == storm_id),
                )
                # Add basin as this is not included in season.to_dataframe():
                if "basin" not in data.get_columns():
                    data.add_column(new_column="basin", data_type="string")
                data.set_value(
                    column="basin",
                    value=storm_data["basin"],
                    condition=(data["id"] == storm_id),  # boolean pd.Series
                )
                # Add counter (number of storm in season) as this is not included in season.to_dataframe():
                if "counter" not in data.get_columns():
                    data.add_column(new_column="counter", data_type="string")
                data.set_value(
                    column="counter",
                    value=storm_data["id"][2:4],
                    condition=(data["id"] == storm_id),  # boolean pd.Series
                )
                # Add counter (number of storm in season) as this is not included in season.to_dataframe():
                if "source_info" not in data.get_columns():
                    data.add_column(new_column="source_info", data_type="string")
                data.set_value(
                    column="source_info",
                    value=storm_data["source_info"],
                    condition=(data["id"] == storm_id),  # boolean pd.Series
                )

                if not self._strom_plot_exclusions or storm_id not in self._strom_plot_exclusions:
                    # Create the image files of the storm track:
                    for image_type in save_track_images or []:
                        image_file = self.get_storm_file_name(storm_id=storm_data["id"], file_type=image_type)
                        data.set_value(
                            column="image_file_" + image_type,
                            value=image_file,
                            condition=(data["id"] == storm_id),  # boolean pd.Series
                        )
                        image_path = os.path.join(image_dir, image_file)
                        if skip_existing_files and os.path.exists(image_path):
                            self.logger.info(
                                "Storm track image file -> '%s' has been saved before - skipping...",
                                image_path,
                            )
                            continue
                        self.logger.info(
                            "Plot storm track image file -> '%s'%s...",
                            image_path,
                            " (replace existing file)" if os.path.exists(image_path) else "",
                        )
                        success_message = (
                            "Successfully saved track image for storm -> '{}' ({}) to file -> '{}'".format(
                                storm_name,
                                storm_data["id"],
                                image_path,
                            )
                        )
                        failure_message = (
                            "Issues while plotting track image for storm -> '{}' ({}) to file -> '{}'".format(
                                storm_name,
                                storm_data["id"],
                                image_path,
                            )
                        )
                        if load_async:
                            result = pool.apply_async(self.save_storm_track_image, args=(storm_data, image_path))
                            results.append(
                                (
                                    result,
                                    success_message,
                                    failure_message,
                                    "image_file_" + image_type,
                                    storm_id,
                                    image_path,
                                ),
                            )
                        else:
                            result = pool.apply(self.save_storm_track_image, args=(storm_data, image_path))
                            if result:
                                self.logger.info(success_message)
                            else:
                                self.logger.warning(failure_message)
                                continue
                    # end for image_type in save_track_images or []
                # end if not self._strom_plot_exclusions or storm_key not in self._strom_plot_exclusions

                # Create the data files of the storm track:
                for data_type in save_track_data or []:
                    data_file = self.get_storm_file_name(storm_id=storm_data["id"], file_type=data_type)
                    data.set_value(
                        column="data_file_" + data_type,
                        value=data_file,
                        condition=(data["id"] == storm_id),  # boolean pd.Series
                    )
                    data_path = os.path.join(data_dir, data_file)
                    if skip_existing_files and os.path.exists(data_path):
                        self.logger.info(
                            "Storm track data file -> '%s' has been saved before - skipping...",
                            data_path,
                        )
                        continue
                    self.save_storm_track_data(
                        storm_data=storm_data,
                        data_path=data_path,
                    )

                # Sadly, rain data is only available up to year 2020.
                if year < self._rain_min_year or year > self._rain_max_year:
                    self.logger.debug(
                        "There's no rain data for year -> %s. Skipping rain plots for this year...",
                        year,
                    )
                    continue

                storm_rain_data = self.get_storm_rainfall(storm_data=storm_data)
                if storm_rain_data is None:
                    self.logger.debug(
                        "There's no rain data for storm -> '%s' in year -> %s. Skipping rain plots for this storm...",
                        storm_name,
                        year,
                    )
                    continue

                if not self._strom_plot_exclusions or storm_id not in self._strom_plot_exclusions:
                    # Create the images of the storm rain:
                    for image_type in save_rain_images or []:
                        image_file_rain = self.get_storm_file_name(
                            storm_id=storm_data["id"],
                            file_type=image_type,
                            suffix="-rainfall",
                        )
                        data.set_value(
                            column="image_file_rain_" + image_type,
                            value=image_file_rain,
                            condition=(data["id"] == storm_id),  # boolean pd.Series
                        )
                        image_path_rain = os.path.join(image_dir, image_file_rain)
                        if skip_existing_files and os.path.exists(image_path_rain):
                            self.logger.info(
                                "Storm rain image file -> '%s' has been saved before - skipping...",
                                image_path_rain,
                            )
                            continue
                        self.logger.info(
                            "Plot storm rain image file -> '%s'...",
                            image_path_rain,
                        )
                        success_message = "Successfully saved rain image for storm -> '{}' ({}) to file -> '{}'".format(
                            storm_data["name"],
                            storm_data["id"],
                            image_path_rain,
                        )
                        failure_message = (
                            "Issues while plotting rain image for storm -> '{}' ({}) to file -> '{}'".format(
                                storm_data["name"],
                                storm_data["id"],
                                image_path_rain,
                            )
                        )
                        if load_async:
                            result = pool.apply_async(self.save_storm_rain_image, args=(storm_data, image_path_rain))
                            results.append(
                                (
                                    result,
                                    success_message,
                                    failure_message,
                                    "image_file_rain_" + image_type,
                                    storm_id,
                                    image_path_rain,
                                ),
                            )
                        else:
                            result = pool.apply(self.save_storm_rain_image, args=(storm_data, image_path_rain))
                            if result:
                                self.logger.info(success_message)
                            else:
                                self.logger.warning(failure_message)
                                continue
                    # end for image_type in save_rain_images or []
                # end if not self._strom_plot_exclusions or storm_key not in self._strom_plot_exclusions

                # Create the data files of the storm rain:
                for data_type in save_rain_data or []:
                    data_file_rain = self.get_storm_file_name(
                        storm_id=storm_data["id"],
                        file_type=data_type,
                        suffix="-rainfall",
                    )
                    data.set_value(
                        column="data_file_rain_" + data_type,
                        value=data_file_rain,
                        condition=(data["id"] == storm_id),  # boolean pd.Series
                    )
                    data_path_rain = os.path.join(data_dir, data_file_rain)
                    if skip_existing_files and os.path.exists(data_path_rain):
                        self.logger.info(
                            "Storm rain data file -> '%s' has been saved before - skipping...",
                            data_path_rain,
                        )
                        continue
                    self.save_storm_rain_data(
                        storm_data=storm_data,
                        data_path=data_path_rain,
                    )
                # end for data_type in save_rain_data
            # end for storm_key, storm_value in season.dict.items()
        # end for year in range(year_start, year_end + 1)

        # Add a column with the image directory and the data directory
        # (value is the same for all rows that's why we do it outside the loop):
        data.set_value(
            column="image_dir",
            value=image_dir,
        )
        data.set_value(
            column="data_dir",
            value=data_dir,
        )

        self.logger.info("Close plot storm worker pool...")
        pool.close()  # Close the pool to new tasks
        self.logger.info("Plot storm worker pool is closed.")

        if load_async:
            self.logger.info("Send 'done' event to collector thread...")
            done_event.set()

            # Wait for the collector thread to finish (this will be after pool join)
            self.logger.info("Waiting for plot collector thread to finish...")
            collector_thread.join()
            self.logger.info("Plot collector thread is finished.")

        # Run the termination and cleanup in a daemon thread to not block the code if
        # a worker process refuses to terminate:
        daemon_thread = threading.Thread(
            name="NHC Termination & Cleanup",
            target=self.terminate_and_cleanup,
            args=(pool,),
        )
        daemon_thread.daemon = True  # Set as a daemon thread, so it won't block program exit
        daemon_thread.start()

        return True

    # end method definition

    def result_collector(self, results: list, done_event: threading.Event) -> None:
        """Collect results from async processes and logs them.

        Args:
            results (list):
                A list of tuples containing task metadata, async results, and pre-baked log messages.
            done_event (threading.Event):
                Event signaling that no more tasks will be submitted.

        """

        self.logger.info("Collector thread for plot results started...")

        # Keep running while results remain or not signalled 'done':
        while not done_event.is_set() or results:
            # Iterate over a copy of the list of tuples:
            for result in results[:]:
                # Unpack the result tuple:
                async_result, success_message, failure_message, column_name, storm_id, image_file = result
                # Check if the process has finished:
                if async_result.ready():
                    try:
                        # Retrieve result (ensuring no exception):
                        success, message = async_result.get()
                        if success:
                            self.logger.info(
                                "%s. %s",
                                success_message,
                                "Plot result: " + message if message else "",
                            )
                        elif os.path.exists(image_file):
                            self.logger.warning(
                                "%s. %s",
                                failure_message,
                                "Plot result: " + message if message else "",
                            )
                        else:
                            self.logger.warning("%s. %s", failure_message, "Plot result: " + message if message else "")
                            self.get_data().set_value(
                                column=column_name,
                                value="",  # set to empty to make sure the bulk loader are not trying to find the non-existing file
                                condition=(self.get_data()["id"] == storm_id),  # boolean pd.Series
                            )
                    except Exception:
                        self.logger.warning(failure_message)
                    # Remove logged result:
                    results.remove(result)
            # Prevent excessive CPU usage:
            time.sleep(0.5)

        self.logger.info("Collector thread for plot results got 'done' event and no further results to process.")

    # end method definition

    def terminate_and_cleanup(self, pool: multiprocessing.pool.Pool) -> None:
        """Terminate and clean up the worker pool in a daemon thread.

        Args:
            pool (multiprocessing.pool.Pool):
                The pool of worker processes to terminate.

        """

        for worker in pool._pool or []:  # noqa: SLF001
            if not worker.is_alive() and worker.exitcode is None:
                self.logger.warning("Worker with PID -> %s is defunct (zombie state).", worker.pid)
            elif worker.is_alive():
                self.logger.warning("Worker with PID -> %s is still alive.", worker.pid)
            else:
                self.logger.info(
                    "Worker with PID -> %s finished with exit code -> %s.",
                    worker.pid,
                    str(worker.exitcode),
                )

        self.logger.info("Terminating the worker pool due to potentially hanging tasks...")
        pool.terminate()  # Terminate the pool to stop all workers
        self.logger.info("Plot storm worker pool terminated.")

        self.logger.info("Joining plot storm worker pool...")
        pool.join()  # Timeout after 10 seconds
        self.logger.info("Plot storm worker pool is finished (joined).")

    # end method definition
