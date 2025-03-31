"""browser_automation Module to automate configuration via a browser interface.

These are typically used as fallback options if no REST API or LLConfig can be used.
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"


import logging
import os
import tempfile
import time

import urllib3

default_logger = logging.getLogger("pyxecm.customizer.browser_automation")

# For backwards compatibility we also want to handle
# cases where the selenium and chromedriver_autoinstaller
# modules have not been installed in the customizer container:
try:
    from selenium import webdriver
    from selenium.common.exceptions import (
        ElementClickInterceptedException,
        ElementNotInteractableException,
        InvalidElementStateException,
        MoveTargetOutOfBoundsException,
        NoSuchElementException,
        StaleElementReferenceException,
        TimeoutException,
        WebDriverException,
    )
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.action_chains import ActionChains
    from selenium.webdriver.common.by import By
    from selenium.webdriver.remote.webelement import WebElement
    from selenium.webdriver.support.ui import Select

except ModuleNotFoundError:
    default_logger.warning("Module selenium is not installed")

    class Options:
        """Dummy class to avoid errors if selenium module cannot be imported."""

    class By:
        """Dummy class to avoid errors if selenium module cannot be imported."""

        ID: str = ""

    class WebElement:
        """Dummy class to avoid errors if selenium module cannot be imported."""


try:
    import chromedriver_autoinstaller
except ModuleNotFoundError:
    default_logger.warning("Module chromedriver_autoinstaller is not installed!")


class BrowserAutomation:
    """Class to automate settings via a browser interface."""

    logger: logging.Logger = default_logger

    def __init__(
        self,
        base_url: str = "",
        user_name: str = "",
        user_password: str = "",
        download_directory: str | None = None,
        take_screenshots: bool = False,
        automation_name: str = "",
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the object.

        Args:
            base_url (str, optional):
                The base URL of the website to automate. Defaults to "".
            user_name (str, optional): _description_. Defaults to "".
                If an authentication at the web site is required, this is the user name.
                Defaults to "".
            user_password (str, optional):
                If an authentication at the web site is required, this is the user password.
                Defaults to "".
            download_directory (str | None, optional):
                A download directory used for download links. If None,
                a temporary directory is automatically used.
            take_screenshots (bool, optional):
                For debugging purposes, screenshots can be taken.
                Defaults to False.
            automation_name (str, optional):
                The name of the automation. Defaults to "screen".
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if not download_directory:
            download_directory = os.path.join(
                tempfile.gettempdir(),
                "browser_automations",
                automation_name,
                "downloads",
            )

        if logger != default_logger:
            self.logger = logger.getChild("browserautomation")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        self.base_url = base_url
        self.user_name = user_name
        self.user_password = user_password
        self.logged_in = False
        self.download_directory = download_directory

        self.take_screenshots = take_screenshots
        self.screenshot_names = automation_name
        self.screen_counter = 1

        self.screenshot_directory = os.path.join(
            tempfile.gettempdir(),
            "browser_automations",
            automation_name,
            "screenshots",
        )

        if self.take_screenshots and not os.path.exists(self.screenshot_directory):
            os.makedirs(self.screenshot_directory)
        chromedriver_autoinstaller.install()
        self.browser = webdriver.Chrome(options=self.set_chrome_options())

    # end method definition

    def __del__(self) -> None:
        """Object destructor."""

        try:
            if self.browser:
                self.browser.quit()
                self.browser = None
        except (WebDriverException, AttributeError, TypeError, OSError):
            # Log or silently handle exceptions during interpreter shutdown
            pass

    # end method definition

    def set_chrome_options(self) -> Options:
        """Set chrome options for Selenium.

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

        chrome_options.add_experimental_option(
            "prefs",
            {"download.default_directory": self.download_directory},
        )

        return chrome_options

    # end method definition

    def take_screenshot(self) -> bool:
        """Take a screenshot of the current browser window and save it as PNG file.

        Returns:
            bool:
                True if successful, False otherwise

        """

        screenshot_file = "{}/{}-{}.png".format(
            self.screenshot_directory,
            self.screenshot_names,
            self.screen_counter,
        )
        self.logger.debug("Save browser screenshot to -> %s", screenshot_file)
        result = self.browser.get_screenshot_as_file(screenshot_file)
        self.screen_counter += 1

        return result

    def get_page(self, url: str = "") -> bool:
        """Load a page into the browser based on a given URL.

        Args:
            url (str):
                URL to load. If empty just the base URL will be used
        Returns:
            bool:
                True if successful, False otherwise

        """

        page_url = self.base_url + url

        try:
            self.logger.debug("Load page -> %s", page_url)
            self.browser.get(page_url)

        except (WebDriverException, urllib3.exceptions.ReadTimeoutError):
            self.logger.error(
                "Cannot load page -> %s!",
                page_url,
            )
            return False

        self.logger.debug("Page title after get page -> %s", self.browser.title)

        if self.take_screenshots:
            self.take_screenshot()

        # Wait a second before proceeding
        time.sleep(1)

        return True

    # end method definition

    def get_title(self) -> str:
        """Get the browser title.

        This is handy to validate a certain page is loaded after get_page()

        Returns:
            str:
                The title of the browser window.

        """

        if not self.browser:
            self.logger.error("Browser not initialized!")
            return None

        return self.browser.title

    # end method definition

    def scroll_to_element(self, element: WebElement) -> None:
        """Scroll an element into view to make it clickable.

        Args:
            element (WebElement):
                Web element that has been identified before.

        """

        if not element:
            self.logger.error("Undefined element!")
            return

        try:
            actions = ActionChains(self.browser)
            actions.move_to_element(element).perform()
        except NoSuchElementException:
            self.logger.error("Element not found in the DOM!")
        except TimeoutException:
            self.logger.error(
                "Timed out waiting for the element to be present or visible!",
            )
        except ElementNotInteractableException:
            self.logger.error("Element is not interactable!")
        except MoveTargetOutOfBoundsException:
            self.logger.error("Element is out of bounds!")
        except WebDriverException:
            self.logger.error("WebDriverException occurred!")

    # end method definition

    def find_elem(
        self,
        find_elem: str,
        find_method: str = By.ID,
        show_error: bool = True,
    ) -> WebElement:
        """Find an page element.

        Args:
            find_elem (str):
                The name of the page element.
            find_method (str, optional):
                Either By.ID, By.NAME, By.CLASS_NAME, BY.XPATH
            show_error (bool, optional):
                Show an error if the element is not found or not clickable.

        Returns:
            WebElement:
                The web element or None in case an error occured.

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
            self.logger.error("Unsupported find method!")
            return None

        try:
            elem = self.browser.find_element(by=find_method, value=find_elem)
        except NoSuchElementException:
            if show_error:
                self.logger.error(
                    "Cannot find page element -> %s by -> %s",
                    find_elem,
                    find_method,
                )
                return None
            else:
                self.logger.warning(
                    "Cannot find page element -> %s by -> %s",
                    find_elem,
                    find_method,
                )
                return None
        except TimeoutException:
            self.logger.error(
                "Timed out waiting for the element to be present or visible!",
            )
            return None
        except ElementNotInteractableException:
            self.logger.error("Element is not interactable!")
            return None
        except MoveTargetOutOfBoundsException:
            self.logger.error("Element is out of bounds!")
            return None
        except WebDriverException:
            self.logger.error("WebDriverException occurred!")
            return None

        self.logger.debug("Found page element -> %s by -> %s", find_elem, find_method)

        return elem

    # end method definition

    def find_elem_and_click(
        self,
        find_elem: str,
        find_method: str = By.ID,
        scroll_to_element: bool = True,
        desired_checkbox_state: bool | None = None,
        show_error: bool = True,
    ) -> bool:
        """Find an page element and click it.

        Args:
            find_elem (str):
                The identifier of the page element.
            find_method (str, optional):
                Either By.ID, By.NAME, By.CLASS_NAME, BY.XPATH
            scroll_to_element (bool, optional):
                Scroll the element into view.
            desired_checkbox_state (bool | None, optional):
                If True/False, ensures checkbox matches state.
                If None then click it in any case.
            show_error (bool, optional):
                Show an error if the element is not found or not clickable.

        Returns:
            bool:
                True if click is successful (or checkbox already in desired state),
                False otherwise.

        """

        if not find_elem:
            if show_error:
                self.logger.error("Missing element name! Cannot find HTML element!")
            else:
                self.logger.warning("Missing element name! Cannot find HTML element!")
            return False

        elem = self.find_elem(
            find_elem=find_elem,
            find_method=find_method,
            show_error=show_error,
        )

        if not elem:
            return not show_error

        is_checkbox = elem.get_attribute("type") == "checkbox"
        checkbox_state = None

        try:
            if scroll_to_element:
                self.scroll_to_element(elem)

            # Handle checkboxes
            if is_checkbox and desired_checkbox_state is not None:
                checkbox_state = elem.is_selected()
                if checkbox_state == desired_checkbox_state:
                    self.logger.debug(
                        "Checkbox -> '%s' already in desired state -> %s",
                        find_elem,
                        desired_checkbox_state,
                    )
                    return True  # No need to click
                else:
                    self.logger.debug("Checkbox -> '%s' state mismatch. Clicking to change state.", find_elem)

            elem.click()
            time.sleep(1)

            # Handle checkboxes
            if is_checkbox and desired_checkbox_state is not None:
                # Re-locate the element after clicking to avoid stale reference
                elem = self.find_elem(
                    find_elem=find_elem,
                    find_method=find_method,
                    show_error=show_error,
                )
                # Is the element still there?
                if elem:
                    checkbox_state = elem.is_selected() if is_checkbox else None

        except (
            ElementClickInterceptedException,
            ElementNotInteractableException,
            StaleElementReferenceException,
            InvalidElementStateException,
        ):
            if show_error:
                self.logger.error(
                    "Cannot click page element -> %s!",
                    find_elem,
                )
                return False
            else:
                self.logger.warning("Cannot click page element -> %s", find_elem)
                return True
        except TimeoutException:
            if show_error:
                self.logger.error("Timeout waiting for element -> %s to be clickable!", find_elem)
            return not show_error

        if checkbox_state is not None:
            if checkbox_state == desired_checkbox_state:
                self.logger.debug(
                    "Successfully clicked checkbox element -> %s. It's state is now -> %s",
                    find_elem,
                    checkbox_state,
                )
            else:
                self.logger.error(
                    "Failed to flip checkbox element -> %s to desired state. It's state is still -> %s and not -> %s",
                    find_elem,
                    checkbox_state,
                    desired_checkbox_state,
                )
        else:
            self.logger.debug(
                "Successfully clicked element -> %s",
                find_elem,
            )

        if self.take_screenshots:
            self.take_screenshot()

        return True

    # end method definition

    def find_elem_and_set(
        self,
        find_elem: str,
        elem_value: str,
        find_method: str = By.ID,
        is_sensitive: bool = False,
    ) -> bool:
        """Find an page element and fill it with a new text.

        Args:
            find_elem (str): name of the page element
            elem_value (str): new text string for the page element
            find_method (str, optional): either By.ID, By.NAME, By.CLASS_NAME, or By.XPATH
            is_sensitive (bool, optional): True for suppressing sensitive information in logging
        Returns:
            bool: True if successful, False otherwise

        """

        elem = self.find_elem(
            find_elem=find_elem,
            find_method=find_method,
            show_error=True,
        )

        if not elem:
            return False

        if not elem.is_enabled():
            self.logger.error("Cannot set elem -> %s to value -> %s. It is not enabled!", find_elem, elem_value)
            return False

        if not is_sensitive:
            self.logger.debug(
                "Set element -> %s to value -> %s...",
                find_elem,
                elem_value,
            )
        else:
            self.logger.debug("Set element -> %s to value -> <sensitive>...", find_elem)

        try:
            # Check if element is a drop-down (select element)
            if elem.tag_name.lower() == "select":
                select = Select(elem)
                try:
                    select.select_by_visible_text(elem_value)  # Select option by visible text
                except NoSuchElementException:
                    self.logger.error("Option -> '%s' not found in drop-down -> '%s'", elem_value, find_elem)
                    return False
            else:
                elem.clear()  # clear existing text in the input field
                elem.send_keys(elem_value)  # write new text into the field
        except (ElementNotInteractableException, InvalidElementStateException):
            self.logger.error(
                "Cannot set page element -> %s to value -> %s",
                find_elem,
                elem_value,
            )
            return False

        if self.take_screenshots:
            self.take_screenshot()

        return True

    # end method definition

    def find_element_and_download(
        self,
        find_elem: str,
        find_method: str = By.ID,
        download_time: int = 30,
    ) -> str | None:
        """Click a page element to initiate a download.

        Args:
            find_elem (str):
                The page element to click for download.
            find_method (str, optional):
                A method to find the element. Defaults to By.ID.
            download_time (int, optional):
                Time in seconds to wait for the download to complete

        Returns:
            str | None:
                The filename of the download.

        """

        # Record the list of files in the download directory before the download
        initial_files = set(os.listdir(self.download_directory))

        if not self.find_elem_and_click(
            find_elem=find_elem,
            find_method=find_method,
        ):
            return None

        # Wait for the download to complete
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
        page: str = "",
    ) -> bool:
        """Login to target system via the browser.

        Args:
            user_field (str, optional):
                The name of the web HTML field to enter the user name. Defaults to "otds_username".
            password_field (str, optional):
                The name of the HTML field to enter the password. Defaults to "otds_password".
            login_button (str, optional):
                The name of the HTML login button. Defaults to "loginbutton".
            page (str, optional):
                The URL to the login page. Defaults to "".

        Returns:
            bool: True = success, False = error.

        """

        self.logged_in = False

        if (
            not self.get_page(
                url=page,
            )  # assuming the base URL leads towards the login page
            or not self.find_elem_and_set(
                find_elem=user_field,
                elem_value=self.user_name,
            )
            or not self.find_elem_and_set(
                find_elem=password_field,
                elem_value=self.user_password,
                is_sensitive=True,
            )
            or not self.find_elem_and_click(find_elem=login_button)
        ):
            self.logger.error(
                "Cannot log into target system using URL -> %s and user -> %s",
                self.base_url,
                self.user_name,
            )
            return False

        self.logger.debug("Page title after login -> %s", self.browser.title)

        # Some special handling for Salesforce login:
        if "Verify" in self.browser.title:
            self.logger.error(
                "Site is asking for a Verification Token. You may need to whitelist your IP!",
            )
            return False
        if "Login" in self.browser.title:
            self.logger.error(
                "Authentication failed. You may have given the wrong password!",
            )
            return False

        self.logged_in = True

        return True

    # end method definition

    def implicit_wait(self, wait_time: float) -> None:
        """Wait for the browser to finish tasks (e.g. fully loading a page).

        This setting is valid for the whole browser session and not just
        for a single command.

        Args:
            wait_time (float): time in seconds to wait

        """

        self.logger.debug("Implicit wait for max -> %s seconds...", str(wait_time))
        self.browser.implicitly_wait(wait_time)

    # end method definition

    def end_session(self) -> None:
        """End the browser session. This is just like closing a tab not ending the browser."""

        self.browser.close()
        self.logged_in = False

    # end method definition
