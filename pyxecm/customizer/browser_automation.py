"""
browser_automation Module to implement a class to automate configuration
via a browser interface. These are typically used as fallback options if
no REST API or LLConfig can be used.

Class: BrowserAutomation
Methods:

__init__ : class initializer
set_chrome_options: Sets chrome options for Selenium. Chrome options for headless browser is enabled
run_otcs_login: Login to OTCS via the browser
run_configure_vertex_datasource: Run the configuration of the Aviator Vertex datasource
end_session: End the browser session
"""

import os
import logging

logger = logging.getLogger("pyxecm.customizer.browser_automation")

# For backwards compatibility we also want to handle
# cases where the selenium and chromedriver_autoinstaller
# modules have not been installed in the customizer container:
try:
    from selenium.webdriver.chrome.options import Options
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.common.exceptions import (
        WebDriverException,
        NoSuchElementException,
        ElementNotInteractableException,
        ElementClickInterceptedException,
    )
except ModuleNotFoundError as module_exception:
    logger.warning("Module selenium is not installed")

    class Options:
        """Dummy class to avoid errors if selenium module cannot be imported"""

    class By:
        """Dummy class to avoid errors if selenium module cannot be imported"""

        ID: str = ""


try:
    import chromedriver_autoinstaller
except ModuleNotFoundError as module_exception:
    logger.warning("Module chromedriver_autoinstaller is not installed")


class BrowserAutomation:
    """Class to automate settings via a browser interface."""

    def __init__(
        self,
        base_url: str,
        user_name: str,
        user_password: str,
        download_directory: str = "/tmp",
    ) -> None:
        self.base_url = base_url
        self.user_name = user_name
        self.user_password = user_password
        self.logged_in = False
        self.download_directory = download_directory

        chromedriver_autoinstaller.install()
        self.browser = webdriver.Chrome(options=self.set_chrome_options())

    # end method definition

    def __del__(self):
        if self.browser:
            self.browser.close()
            del self.browser
            self.browser = None

    def set_chrome_options(self) -> Options:
        """Sets chrome options for Selenium.
           Chrome options for headless browser is enabled.

        Returns:
            Options: Options to call the browser with
        """

        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_prefs = {}
        chrome_options.experimental_options["prefs"] = chrome_prefs
        chrome_prefs["profile.default_content_settings"] = {"images": 2}

        chrome_options.add_experimental_option(
            "prefs", {"download.default_directory": self.download_directory}
        )

        return chrome_options

    # end method definition

    def get_page(self, url: str = "") -> bool:
        """Load a page into the browser based on a given URL.
           Required authorization need

        Args:
            url (str): URL to load. If empty just the base URL will be used
        Returns:
            bool: True if successful, False otherwise
        """

        page_url = self.base_url + url

        try:
            logger.info("Load page -> %s", page_url)
            self.browser.get(page_url)
        except WebDriverException as exception:
            logger.error("Cannot load page -> %s; error -> %s", page_url, exception)
            return False

        logger.info("Page title get page -> %s", self.browser.title)

        return True

    # end method definition

    def find_elem_and_click(self, find_elem: str, find_method: str = By.ID) -> bool:
        """Find an page element and click it.

        Args:
            find_elem (str): name of the page element
            find_method (str): either By.ID, By.NAME, By.CLASS_NAME, BY.XPATH
        Returns:
            bool: True if successful, False otherwise
        """

        # We don't want to expose class "By" outside this module,
        # so we map the string values to the By class values:
        if find_method == "id":
            find_method = By.ID
        elif find_method == "name":
            find_method = By.NAME
        elif find_method == "class_name":
            find_method = By.CLASS_NAME
        elif find_method == "xpath":
            find_method = By.XPATH
        else:
            logger.error("Unsupported find method!")
            return False

        try:
            elem = self.browser.find_element(by=find_method, value=find_elem)
        except NoSuchElementException as exception:
            logger.error(
                "Cannot find page element -> %s by -> %s; error -> %s",
                find_elem,
                find_method,
                exception,
            )
            return False

        try:
            elem.click()
        except ElementClickInterceptedException as exception:
            logger.error(
                "Cannot click page element -> %s; error -> %s", find_elem, exception
            )
            return False

        return True

    # end method definition

    def find_elem_and_set(
        self, find_elem: str, elem_value: str, find_method: str = By.ID
    ) -> bool:
        """Find an page element and fill it with a new text.

        Args:
            find_elem (str): name of the page element
            elem_value (str): new text string for the page element
            find_method (str): either By.ID, By.NAME, By.CLASS_NAME, or By.XPATH
        Returns:
            bool: True if successful, False otherwise
        """

        # We don't want to expose class "By" outside this module,
        # so we map the string values to the By class values:
        if find_method == "id":
            find_method = By.ID
        elif find_method == "name":
            find_method = By.NAME
        elif find_method == "class_name":
            find_method = By.CLASS_NAME
        elif find_method == "xpath":
            find_method = By.XPATH
        else:
            logger.error("Unsupported find method!")
            return False

        logger.info("Try to find element -> %s by -> %s...", find_elem, find_method)

        try:
            elem = self.browser.find_element(find_method, find_elem)
        except NoSuchElementException as exception:
            logger.error(
                "Cannot find page element -> %s by -> %s; error -> %s",
                find_elem,
                find_method,
                exception,
            )
            return False

        logger.info("Set element -> %s to value -> %s...", find_elem, elem_value)

        try:
            elem.clear()  # clear existing text in the input field
            elem.send_keys(elem_value)  # write new text into the field
        except ElementNotInteractableException as exception:
            logger.error(
                "Cannot set page element -> %s to value -> %s; error -> %s",
                find_elem,
                elem_value,
                exception,
            )
            return False

        return True

    # end method definition

    def find_element_and_download(
        self, find_elem: str, find_method: str = By.ID, download_time: int = 30
    ) -> str | None:
        """Clicks a page element to initiate a download

        Args:
            find_elem (str): page element to click for download
            find_method (str, optional): method to find the element. Defaults to By.ID.
            download_time (int, optional): time in seconds to wait for the download to complete
        Returns:
            str | None: filename of the download
        """

        # Record the list of files in the download directory before the download
        initial_files = set(os.listdir(self.download_directory))

        if not self.find_elem_and_click(
            find_elem=find_elem,
            find_method=find_method,
        ):
            return None

        # Wait for the download to complete
        #        time.sleep(download_time)

        self.browser.implicitly_wait(download_time)

        # Record the list of files in the download directory after the download
        current_files = set(os.listdir(self.download_directory))

        # Determine the name of the downloaded file
        new_file = (current_files - initial_files).pop()

        return new_file

    # end method definition

    def run_login(
        self,
        user_field: str = "otds_username",
        password_field: str = "otds_password",
        login_button: str = "loginbutton",
    ) -> bool:
        """Login to target system via the browser"""

        self.logged_in = False

        if (
            not self.get_page()  # assuming the base URL leads towards the login page
            or not self.find_elem_and_set(
                find_elem=user_field, elem_value=self.user_name
            )
            or not self.find_elem_and_set(
                find_elem=password_field, elem_value=self.user_password
            )
            or not self.find_elem_and_click(find_elem=login_button)
        ):
            logger.error("Cannot log into target system using URL -> %s", self.base_url)
            return False

        logger.info("Page title after login -> %s", self.browser.title)
        if "Verify" in self.browser.title:
            logger.error(
                "Site is asking for a Verification Token. You may need to whitelist your IP!"
            )
            return False

        self.logged_in = True

        return True

    # end method definition

    def implict_wait(self, wait_time: float):
        """Waits for the browser to finish tasks (e.g. fully loading a page)

        Args:
            wait_time (float): time in seconds to wait
        """

        logger.info("Implicit wait for max -> %s seconds...", str(wait_time))
        self.browser.implicitly_wait(wait_time)

    def end_session(self):
        """End the browser session"""

        self.browser.close()
        self.logged_in = False

    # end method definition
