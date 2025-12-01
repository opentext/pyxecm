"""browser_automation Module to automate configuration via a browser interface.

These are typically used as fallback options if no REST API or LLConfig can be used.

This module uses playwright: https://playwright.dev for broweser-based automation
and testing.

Core Playwright data types and their relationships:

Playwright
 └── BrowserType (chromium / firefox / webkit)
      └── Browser
           └── BrowserContext
                └── Page
                     ├── Frame
                     ├── Locator (preferred for element interactions)
                     ├── ElementHandle (lower-level DOM reference)
                     └── JSHandle (handle to any JS object)

| Type               | Description                                                                                                    |
| ------------------ | -------------------------------------------------------------------------------------------------------------- |
| **Playwright**     | Entry point via `sync_playwright()` or `async_playwright()`. Gives access to browser types.                    |
| **BrowserType**    | Represents Chromium, Firefox, or WebKit. Used to launch a `Browser`.                                           |
| **Browser**        | A running browser instance. Use `.new_context()` to create sessions.                                           |
| **BrowserContext** | Isolated incognito-like browser profile. Contains pages.                                                       |
| **Page**           | A single browser tab. Main interface for navigation and interaction.                                           |
| **Frame**          | Represents a `<frame>` or `<iframe>`. Like a mini `Page`.                                                      |
| **Locator**        | Lazily-evaluated, auto-waiting reference to one or more elements. **Preferred** for interacting with elements. |
| **ElementHandle**  | Static reference to a single DOM element. Useful for special interactions or JS execution.                     |
| **JSHandle**       | Handle to any JavaScript object, not just DOM nodes. Returned by `evaluate_handle()`.                          |

Here are few few examples of the most typical page matches with the different selector types:

| **Element to Match**     | **CSS**                        | **XPath**                                         | **Playwright `get_by_*` Method**          |
| ------------------------ | ------------------------------ | ------------------------------------------------- | ----------------------------------------- |
| Element with ID          | `#myId`                        | `//*[@id='myId']`                                 | *Not available directly; use `locator()`* |
| Element with class       | `.myClass`                     | `//*[@class='myClass']`                           | *Not available directly; use `locator()`* |
| Button with exact text   | `button:has-text("Submit")`    | `//button[text()='Submit']`                       | `get_by_role("button", name="Submit")`    |
| Button with partial text | `button:has-text("Sub")`       | `//button[contains(text(), 'Sub')]`               | `get_by_text("Sub")`                      |
| Input with name          | `input[name="email"]`          | `//input[@name='email']`                          | *Not available directly; use `locator()`* |
| Link by text             | `a:has-text("Home")`           | `//a[text()='Home']`                              | `get_by_role("link", name="Home")`        |
| Element with title       | `[title="Info"]`               | `//*[@title='Info']`                              | `get_by_title("Info")`                    |
| Placeholder text         | `input[placeholder="Search"]`  | `//input[@placeholder='Search']`                  | `get_by_placeholder("Search")`            |
| Label text (form input)  | `label:has-text("Email")`      | `//label[text()='Email']`                         | `get_by_label("Email")`                   |
| Alt text (image)         | `img[alt="Logo"]`              | `//img[@alt='Logo']`                              | `get_by_alt_text("Logo")`                 |
| Role and name (ARIA)     | `[role="button"][name="Save"]` | `//*[@role='button' and @name='Save']`            | `get_by_role("button", name="Save")`      |
| Visible text anywhere    | `:text("Welcome")`             | `//*[contains(text(), "Welcome")]`                | `get_by_text("Welcome")`                  |
| nth element in a list    | `ul > li:nth-child(2)`         | `(//ul/li)[2]`                                    | `locator("ul > li").nth(1)`               |
| Element with attribute   | `[data-test-id="main"]`        | `//*[@data-test-id='main']`                       | *Not available directly; use `locator()`* |
| Nested element           | `.container .button`           | `//div[@class='container']//div[@class='button']` | `locator(".container .button")`           |

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import os
import re
import subprocess
import tempfile
import time
import traceback
from http import HTTPStatus
from types import TracebackType

default_logger = logging.getLogger("pyxecm_customizer.browser_automation")

# For backwards compatibility we also want to handle
# cases where the playwright modules have not been installed
# in the customizer container:
try:
    from playwright.sync_api import (
        Browser,
        BrowserContext,
        Locator,
        Page,
        sync_playwright,
    )
    from playwright.sync_api import Error as PlaywrightError
except ModuleNotFoundError:
    default_logger.warning("Module playwright is not installed")

# We use "networkidle" as default "wait until" strategy as
# this seems to best harmonize with OTCS. Especially login
# procedure for OTDS / OTCS seems to not work with the "load"
# "wait until" strategy.
DEFAULT_WAIT_UNTIL_STRATEGY = "networkidle"

REQUEST_TIMEOUT = 30.0
REQUEST_RETRY_DELAY = 4.0
REQUEST_MAX_RETRIES = 3


class BrowserAutomation:
    """Class to automate settings via a browser interface."""

    page: Page = None
    browser: Browser = None
    context: BrowserContext = None
    playwright = None
    proxy = None

    logger: logging.Logger = default_logger

    def __init__(
        self,
        base_url: str = "",
        user_name: str = "",
        user_password: str = "",
        download_directory: str | None = None,
        take_screenshots: bool = False,
        automation_name: str = "",
        headless: bool = True,
        logger: logging.Logger = default_logger,
        wait_until: str | None = None,
        browser: str | None = None,
    ) -> None:
        """Initialize the object.

        Args:
            base_url (str, optional):
                The base URL of the website to automate. Defaults to "".
            user_name (str, optional):
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
                The name of the automation. Defaults to "".
            headless (bool, optional):
                If True, the browser will be started in headless mode. Defaults to True.
            wait_until (str | None, optional):
                Wait until a certain condition. Options are:
                * "commit" - does not wait at all - commit the request and continue
                * "load" - waits for the load event (after all resources like images/scripts load)
                * "networkidle" - waits until there are no network connections for at least 500 ms.
                * "domcontentloaded" - waits for the DOMContentLoaded event (HTML is parsed,
                  but subresources may still load).
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.
            browser (str | None, optional):
                The browser to use. Defaults to None, which takes the global default or from the ENV "BROWSER".

        """

        if not download_directory:
            download_directory = os.path.join(
                tempfile.gettempdir(),
                "browser_automations",
                self.sanitize_filename(filename=automation_name),
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
        self.headless = headless

        # Screenshot configurations:
        self.take_screenshots = take_screenshots
        self.screenshot_names = self.sanitize_filename(filename=automation_name)
        self.screenshot_counter = 1
        self.screenshot_full_page = True

        self.wait_until = wait_until if wait_until else DEFAULT_WAIT_UNTIL_STRATEGY

        self.screenshot_directory = os.path.join(
            tempfile.gettempdir(),
            "browser_automations",
            self.screenshot_names,
            "screenshots",
        )
        self.logger.debug("Creating screenshot directory... -> %s", self.screenshot_directory)
        if self.take_screenshots and not os.path.exists(self.screenshot_directory):
            os.makedirs(self.screenshot_directory)

        if os.getenv("HTTP_PROXY"):
            self.proxy = {
                "server": os.getenv("HTTP_PROXY"),
            }
            self.logger.info("Using HTTP proxy -> %s", os.getenv("HTTP_PROXY"))

        browser = browser or os.getenv("BROWSER", "webkit")
        self.logger.info("Using browser -> '%s'...", browser)

        if not self.setup_playwright(browser=browser):
            msg = "Failed to initialize Playwright browser automation!"
            self.logger.error(msg)
            raise RuntimeError(msg)

        self.logger.info("Creating browser context...")
        self.context: BrowserContext = self.browser.new_context(
            accept_downloads=True,
        )

        self.logger.info("Creating page...")
        self.page: Page = self.context.new_page()
        self.main_page = self.page
        self.logger.info("Browser automation initialized.")

    # end method definition

    def setup_playwright(self, browser: str) -> bool:
        """Initialize Playwright browser automation.

        Args:
            browser (str):
                Name of the browser engine. Supported:
                * chromium
                * chrome
                * msedge
                * webkit
                * firefox

        Returns:
            bool:
                True = Success, False = Error.

        """

        try:
            self.logger.debug("Creating Playwright instance...")
            self.playwright = sync_playwright().start()
        except Exception as e:
            self.logger.error("Failed to start Playwright! Error -> %s", str(e))
            return False

        result = True

        # Install and launch the selected browser in Playwright:
        match browser:
            case "chromium":
                try:
                    self.browser: Browser = self.playwright.chromium.launch(
                        headless=self.headless, slow_mo=100 if not self.headless else None, proxy=self.proxy
                    )
                except Exception:
                    result = self.install_browser(browser=browser)
                    if result:
                        self.browser: Browser = self.playwright.chromium.launch(
                            headless=self.headless, slow_mo=100 if not self.headless else None, proxy=self.proxy
                        )

            case "chrome":
                try:
                    self.browser: Browser = self.playwright.chromium.launch(
                        channel="chrome",
                        headless=self.headless,
                        slow_mo=100 if not self.headless else None,
                        proxy=self.proxy,
                    )
                except Exception:
                    result = self.install_browser(browser=browser)
                    if result:
                        self.browser: Browser = self.playwright.chromium.launch(
                            channel="chrome",
                            headless=self.headless,
                            slow_mo=100 if not self.headless else None,
                            proxy=self.proxy,
                        )

            case "msedge":
                try:
                    self.browser: Browser = self.playwright.chromium.launch(
                        channel="msedge",
                        headless=self.headless,
                        slow_mo=100 if not self.headless else None,
                        proxy=self.proxy,
                    )
                except Exception:
                    result = self.install_browser(browser=browser)
                    if result:
                        self.browser: Browser = self.playwright.chromium.launch(
                            channel="msedge",
                            headless=self.headless,
                            slow_mo=100 if not self.headless else None,
                            proxy=self.proxy,
                        )

            case "webkit":
                try:
                    self.browser: Browser = self.playwright.webkit.launch(
                        headless=self.headless, slow_mo=100 if not self.headless else None, proxy=self.proxy
                    )
                except Exception:
                    result = self.install_browser(browser=browser)
                    if result:
                        self.browser: Browser = self.playwright.webkit.launch(
                            headless=self.headless, slow_mo=100 if not self.headless else None, proxy=self.proxy
                        )

            case "firefox":
                try:
                    self.browser: Browser = self.playwright.firefox.launch(
                        headless=self.headless, slow_mo=100 if not self.headless else None, proxy=self.proxy
                    )
                except Exception:
                    result = self.install_browser(browser=browser)
                    if result:
                        self.browser: Browser = self.playwright.firefox.launch(
                            headless=self.headless, slow_mo=100 if not self.headless else None, proxy=self.proxy
                        )
            case _:
                self.logger.error("Unknown browser -> '%s'. Cannot install and launch it.", browser)
                result = False

        return result

    # end method definition

    def install_browser(self, browser: str) -> bool:
        """Install a browser with a provided name in Playwright.

        Args:
            browser (str):
                Name of the browser to be installed.

        Returns:
            bool: True = installation successful, False = installation failed.

        """

        self.logger.info("Installing Browser -> '%s'...", browser)
        process = subprocess.Popen(
            ["playwright", "install", browser],  # noqa: S607
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        output, error = process.communicate()
        if process.returncode == 0:  # 0 = success
            self.logger.info("Successfuly completed installation of browser -> '%s'.", browser)
            self.logger.debug(output.decode())
        else:
            self.logger.error("Installation of browser -> '%s' failed! Error -> %s", browser, error.decode())
            self.logger.error(output.decode())
            return False

        return True

    # end method definition

    def sanitize_filename(self, filename: str) -> str:
        """Sanitize a string to be safe for use as a filename.

        - Replaces spaces with underscores
        - Removes unsafe characters
        - Converts to lowercase
        - Trims length and dots

        Args:
            filename (str):
                The filename to sanitize.

        """

        filename = filename.lower()
        filename = filename.replace(" ", "_")
        filename = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "", filename)  # Remove unsafe chars
        filename = re.sub(r"\.+$", "", filename)  # Remove trailing dots
        filename = filename.strip()
        if not filename:
            filename = "untitled"

        return filename

    # end method definition

    def take_screenshot(self, suffix: str = "") -> bool:
        """Take a screenshot of the current browser window and save it as PNG file.

        Args:
            suffix (str, optional):
                Optional suffix to append to the screenshot filename.

        Returns:
            bool:
                True if successful, False otherwise

        """

        screenshot_file = "{}/{}-{:02d}{}.png".format(
            self.screenshot_directory, self.screenshot_names, self.screenshot_counter, suffix
        )
        self.logger.debug("Save browser screenshot to -> %s", screenshot_file)

        try:
            self.page.screenshot(path=screenshot_file, full_page=self.screenshot_full_page)
            self.screenshot_counter += 1
        except Exception as e:
            self.logger.error("Failed to take screenshot; error -> %s", e)
            return False

        return True

    # end method definition

    def get_page(self, url: str = "", wait_until: str | None = None) -> bool:
        """Load a page into the browser based on a given URL.

        Args:
            url (str):
                URL to load. If empty just the base URL will be used.
            wait_until (str | None, optional):
                Wait until a certain condition. Options are:
                * "commit" - does not wait at all - commit the request and continue
                * "load" - waits for the load event (after all resources like images/scripts load)
                  This is the safest strategy for pages that keep loading content in the background
                  like Salesforce.
                * "networkidle" - waits until there are no network connections for at least 500 ms.
                  This seems to be the safest one for OpenText Content Server.
                * "domcontentloaded" - waits for the DOMContentLoaded event (HTML is parsed,
                  but subresources may still load).

        Returns:
            bool:
                True if successful, False otherwise.

        """

        # If no specific wait until strategy is provided in the
        # parameter, we take the one from the browser automation class:
        if wait_until is None:
            wait_until = self.wait_until

        page_url = self.base_url + url

        try:
            self.logger.debug("Load page -> %s (wait until -> '%s')", page_url, wait_until)

            # The Playwright Response object is different from the requests.response object!
            response = self.page.goto(page_url, wait_until=wait_until)
            if response is None:
                self.logger.warning("Loading of page -> %s completed but no response object was returned.", page_url)
            elif not response.ok:
                # Try to get standard phrase, fall back if unknown
                try:
                    phrase = HTTPStatus(response.status).phrase
                except ValueError:
                    phrase = "Unknown Status"
                self.logger.error(
                    "Response for page -> %s is not OK. Status -> %s/%s",
                    page_url,
                    response.status,
                    phrase,
                )
                return False

        except PlaywrightError as e:
            self.logger.error("Navigation to page -> %s has failed; error -> %s", page_url, str(e))
            return False

        if self.take_screenshots:
            self.take_screenshot()

        return True

    # end method definition

    def get_title(
        self,
        wait_until: str | None = None,
    ) -> str | None:
        """Get the browser title.

        This is handy to validate a certain page is loaded after get_page()

        Retry-safe way to get the page title, even if there's an in-flight navigation.

        Args:
            wait_until (str | None, optional):
                Wait until a certain condition. Options are:
                * "commit" - does not wait at all - commit the request and continue
                * "load" - waits for the load event (after all resources like images/scripts load)
                  This is the safest strategy for pages that keep loading content in the background
                  like Salesforce.
                * "networkidle" - waits until there are no network connections for at least 500 ms.
                  This seems to be the safest one for OpenText Content Server.
                * "domcontentloaded" - waits for the DOMContentLoaded event (HTML is parsed,
                  but subresources may still load).

        Returns:
            str:
                The title of the browser page.

        """

        for attempt in range(REQUEST_MAX_RETRIES):
            try:
                if wait_until:
                    self.page.wait_for_load_state(state=wait_until, timeout=REQUEST_TIMEOUT)
                title = self.page.title()
                if title:
                    return title
                time.sleep(REQUEST_RETRY_DELAY)
                self.logger.info("Retry attempt %d/%d", attempt + 1, REQUEST_MAX_RETRIES)
            except Exception as e:
                if "Execution context was destroyed" in str(e):
                    self.logger.info(
                        "Execution context was destroyed, retrying after %s seconds...", REQUEST_RETRY_DELAY
                    )
                    time.sleep(REQUEST_RETRY_DELAY)
                    self.logger.info("Retry attempt %d/%d", attempt + 1, REQUEST_MAX_RETRIES)
                    continue
                self.logger.error("Could not get page title; error -> %s", str(e))
                break

        return None

    # end method definition

    def scroll_to_element(self, element: Locator) -> None:
        """Scroll an element into view to make it clickable.

        Args:
            element (Locator):
                Web element that has been identified before.

        """

        if not element:
            self.logger.error("Undefined element! Cannot scroll to it.")
            return

        try:
            element.scroll_into_view_if_needed()
        except PlaywrightError as e:
            self.logger.warning("Cannot scroll element -> %s into view; error -> %s", str(element), str(e))

    # end method definition

    def get_locator(
        self,
        selector: str,
        selector_type: str,
        role_type: str | None = None,
        exact_match: bool | None = None,
        iframe: str | None = None,
        regex: bool = False,
        filter_has_text: str | None = None,
        filter_has: Locator | None = None,
        filter_has_not_text: str | None = None,
        filter_has_not: Locator | None = None,
    ) -> Locator | None:
        """Determine the locator for the given selector type and (optional) role type.

        Args:
            selector (str):
                The selector to find the element on the page.
            selector_type (str):
                One of "id", "name", "class_name", "xpath", "css", "role", "text", "title",
                "label", "placeholder", "alt".
                When using css, the selector becomes a raw CSS selector, and you can skip attribute
                and value filtering entirely if your selector already narrows it down.
                Examples for CSS:
                * selector="img" - find all img tags (images)
                * selector="img[title]" - find all img tags (images) that have a title attribute - independent of its value
                * selector="img[title*='Microsoft Teams']" - find all images with a title that contains "Microsoft Teams"
                * selector=".toolbar button" - find all buttons inside a .toolbar class
            role_type (str | None, optional):
                ARIA role when using selector_type="role", e.g., "button", "textbox".
                If irrelevant then None should be passed for role_type.
            exact_match (bool | None, optional):
                 Controls whether the text or name must match exactly.
                 Default is None (not set, i.e. using playwrights default).
            iframe (str | None):
                Is the element in an iFrame? Then provide the name of the iframe with this parameter.
            regex (bool, optional):
                Should the name be interpreted as a regular expression?
            filter_has_text (str | None, optional):
                Applies `locator.filter(has_text=...)` to narrow the selection based on text content.
            filter_has (Locator | None, optional):
                Applies `locator.filter(has=...)` to match elements containing a descendant matching the given Locator.
            filter_has_not_text (str | None, optional):
                Applies `locator.filter(has_not_text=...)` to exclude elements with matching text content.
            filter_has_not (Locator | None, optional):
                Applies `locator.filter(has_not=...)` to exclude elements containing a matching descendant.

        """

        try:
            name_or_text = re.compile(selector) if regex else selector

            match selector_type:
                case "id":
                    locator = self.page.locator("#{}".format(selector))
                case "name":
                    locator = self.page.locator("[name='{}']".format(selector))
                case "class_name":
                    locator = self.page.locator(".{}".format(selector))
                case "xpath":
                    locator = self.page.locator("xpath={}".format(selector))
                case "css":
                    if iframe is None:
                        locator = self.page.locator(selector)
                    else:
                        locator = self.page.locator("iframe[name='{}']".format(iframe)).content_frame.locator(selector)
                case "text":
                    if iframe is None:
                        locator = self.page.get_by_text(text=name_or_text)
                    else:
                        locator = self.page.locator("iframe[name='{}']".format(iframe)).content_frame.get_by_text(
                            name_or_text
                        )
                case "title":
                    locator = self.page.get_by_title(text=name_or_text)
                case "label":
                    locator = self.page.get_by_label(text=name_or_text)
                case "placeholder":
                    locator = self.page.get_by_placeholder(text=name_or_text)
                case "alt":
                    locator = self.page.get_by_alt_text(text=name_or_text)
                case "role":
                    if not role_type:
                        self.logger.error("Role type must be specified when using find method 'role'!")
                        return None
                    if iframe is None:
                        if regex:
                            locator = self.page.get_by_role(role=role_type, name=name_or_text)
                        else:
                            locator = self.page.get_by_role(role=role_type, name=selector, exact=exact_match)
                    else:
                        content_frame = self.page.locator("iframe[name='{}']".format(iframe)).content_frame
                        if regex:
                            locator = content_frame.get_by_role(role=role_type, name=name_or_text)
                        else:
                            locator = content_frame.get_by_role(role=role_type, name=selector, exact=exact_match)
                case _:
                    self.logger.error("Unsupported selector type -> '%s'", selector_type)
                    return None

            # Apply filter if needed
            if any([filter_has_text, filter_has, filter_has_not_text, filter_has_not]):
                locator = locator.filter(
                    has_text=filter_has_text, has=filter_has, has_not_text=filter_has_not_text, has_not=filter_has_not
                )

        except PlaywrightError as e:
            self.logger.error("Failure to determine page locator; error -> %s", str(e))
            return None

        return locator

    # end method definition

    def find_elem(
        self,
        selector: str,
        selector_type: str = "id",
        role_type: str | None = None,
        wait_state: str = "visible",
        exact_match: bool | None = None,
        regex: bool = False,
        occurrence: int = 1,
        iframe: str | None = None,
        repeat_reload: int | None = None,
        repeat_reload_delay: int = 60,
        show_error: bool = True,
    ) -> Locator | None:
        """Find a page element.

        Args:
            selector (str):
                The name of the page element or accessible name (for role).
            selector_type (str, optional):
                One of "id", "name", "class_name", "xpath", "css", "role", "text", "title",
                "label", "placeholder", "alt".
            role_type (str | None, optional):
                ARIA role when using selector_type="role", e.g., "button", "textbox".
                If irrelevant then None should be passed for role_type.
            wait_state (str, optional):
                Defines if we wait for attached (element is part of DOM) or
                if we wait for elem to be visible (attached, displayed, and has non-zero size).
                Possible values are:
                * "attached" - the element is present in the DOM.
                * "detached" - the element is not present in the DOM.
                * "visible" - the element is visible (attached, displayed, and has non-zero size).
                * "hidden" - the element is hidden (attached, but not displayed).
                Default is "visible".
            exact_match (bool | None, optional):
                If an exact matching is required. Default is None (not set).
            regex (bool, optional):
                Should the name be interpreted as a regular expression?
            occurrence (int, optional):
                If multiple elements match the selector, this defines which one to return.
                Default is 1 (the first one).
            iframe (str | None):
                Is the element in an iFrame? Then provide the name of the iframe with this parameter.
            repeat_reload (int | None):
                For pages that are not dynamically updated and require a reload to show an update
                a number of page reloads can be configured.
            repeat_reload_delay (float | None):
                Number of seconds to wait.
            show_error (bool, optional):
                Show an error if not found or not visible.


        Returns:
            Locator:
                The web element or None in case an error occured.

        """

        failure_message = "Cannot find {} page element with selector -> '{}' ({}){}{}{}{}".format(
            "occurence #{} of".format(occurrence) if occurrence > 1 else "any",
            selector,
            selector_type,
            " and role type -> '{}'".format(role_type) if role_type else "",
            " in iframe -> '{}'".format(iframe) if iframe else "",
            ", occurrence -> {}".format(occurrence) if occurrence > 1 else "",
            ", waiting for state -> '{}'".format(wait_state),
        )
        success_message = "Found {} page element with selector -> '{}' ('{}'){}{}{}".format(
            "occurence #{} of".format(occurrence) if occurrence > 1 else "a",
            selector,
            selector_type,
            " and role type -> '{}'".format(role_type) if role_type else "",
            " in iframe -> '{}'".format(iframe) if iframe else "",
            ", occurrence -> {}".format(occurrence) if occurrence > 1 else "",
        )

        def do_find() -> Locator | None:
            # Determine the locator for the element:
            locator = self.get_locator(
                selector=selector,
                selector_type=selector_type,
                role_type=role_type,
                exact_match=exact_match,
                iframe=iframe,
                regex=regex,
            )
            if not locator:
                if show_error:
                    self.logger.error(failure_message)
                else:
                    self.logger.warning(failure_message)
                return None

            # Wait for the element to be visible - don't use logic like
            # locator.count() as this does not wait but fail immideately if elements
            # are not yet loaded:

            try:
                index = occurrence - 1  # convert to 0-based index
                if index < 0:  # basic validation
                    self.logger.error("Occurrence must be >= 1")
                    return None
                self.logger.debug(
                    "Wait for locator to find %selement with selector -> '%s' (%s%s%s) and state -> '%s'%s...",
                    "occurrence #{} of ".format(occurrence) if occurrence > 1 else "",
                    selector,
                    "selector type -> '{}'".format(selector_type),
                    ", role type -> '{}'".format(role_type) if role_type else "",
                    ", using regular expression" if regex else "",
                    wait_state,
                    " in iframe -> '{}'".format(iframe) if iframe else "",
                )

                locator = locator.first if occurrence == 1 else locator.nth(index)
                # Wait for the element to be in the desired state:
                locator.wait_for(state=wait_state)
            except PlaywrightError as pe:
                if show_error and repeat_reload is None:
                    self.logger.error("%s (%s)", failure_message, str(pe))
                else:
                    self.logger.warning("%s", failure_message)
                return None
            else:
                self.logger.debug(success_message)

            return locator

        # end def do_find():

        locator = do_find()

        # Retry logic for pages that are not updated dynamically:
        if locator is None and repeat_reload is not None:
            for i in range(repeat_reload):
                self.logger.warning(
                    "Wait %f seconds before reloading page -> %s to retrieve updates from server...",
                    repeat_reload_delay,
                    self.page.url,
                )
                time.sleep(repeat_reload_delay)
                self.logger.warning(
                    "Reloading page -> %s (retry %d) to retrieve updates from server...", self.page.url, i + 1
                )
                self.page.reload()
                locator = do_find()
                if locator:
                    break
            else:
                self.logger.error(failure_message)

        return locator

    # end method definition

    def find_elem_and_click(
        self,
        selector: str,
        selector_type: str = "id",
        role_type: str | None = None,
        occurrence: int = 1,
        scroll_to_element: bool = True,
        desired_checkbox_state: bool | None = None,
        is_navigation_trigger: bool = False,
        is_popup_trigger: bool = False,
        is_page_close_trigger: bool = False,
        wait_until: str | None = None,
        wait_time: float = 0.0,
        wait_state: str = "visible",
        exact_match: bool | None = None,
        regex: bool = False,
        hover_only: bool = False,
        iframe: str | None = None,
        force: bool | None = None,
        click_button: str | None = None,
        click_count: int | None = None,
        click_modifiers: list | None = None,
        repeat_reload: int | None = None,
        repeat_reload_delay: float = 60.0,
        show_error: bool = True,
    ) -> bool:
        """Find a page element and click it.

        Args:
            selector (str):
                The selector of the page element.
            selector_type (str, optional):
                One of "id", "name", "class_name", "xpath", "css", "role", "text", "title",
                "label", "placeholder", "alt".
            role_type (str | None, optional):
                ARIA role when using selector_type="role", e.g., "button", "textbox".
                If irrelevant then None should be passed for role_type.
            occurrence (int, optional):
                If multiple elements match the selector, this defines which one to return.
                Default is 1 (the first one).
            scroll_to_element (bool, optional):
                Scroll the element into view.
            desired_checkbox_state (bool | None, optional):
                If True/False, ensures checkbox matches state.
                If None then click it in any case.
            is_navigation_trigger (bool, optional):
                Is the click causing a navigation. Default is False.
            is_popup_trigger (bool, optional):
                Is the click causing a new browser window to open?
            is_page_close_trigger (bool, optional):
                Is the click causing the page to close?
            wait_until (str | None, optional):
                Wait until a certain condition. Options are:
                * "commit" - does not wait at all - commit the request and continue
                * "load" - waits for the load event (after all resources like images/scripts load)
                  This is the safest strategy for pages that keep loading content in the background
                  like Salesforce.
                * "networkidle" - waits until there are no network connections for at least 500 ms.
                  This seems to be the safest one for OpenText Content Server.
                * "domcontentloaded" - waits for the DOMContentLoaded event (HTML is parsed,
                  but subresources may still load).
            wait_time (float, optional):
                Time in seconds to wait for elements to appear. Default is 0.0 (no wait).
            wait_state (str, optional):
                Defines if we wait for attached (element is part of DOM) or
                if we wait for elem to be visible (attached, displayed, and has non-zero size).
                Possible values are:
                * "attached" - the element is present in the DOM.
                * "detached" - the element is not present in the DOM.
                * "visible" - the element is visible (attached, displayed, and has non-zero size).
                * "hidden" - the element is hidden (attached, but not displayed).
                Default is "visible".
            exact_match (bool | None, optional):
                If an exact matching is required. Default is None (not set).
            regex (bool, optional):
                Should the name be interpreted as a regular expression?
            hover_only (bool, optional):
                Should we only hover over the element and not click it? Helpful for
                menus that are opening on hovering.
            iframe (str | None, optional):
                Is the element in an iFrame? Then provide the name of the iframe with this parameter.
            force (bool | None, optional):
                If sure the element is interactable and visible (even partly), you can bypass visibility checks
                by setting this option to True. Default is None (undefined, i.e. using the playwright default which is False)
            click_button (Literal['left', 'middle', 'right'] | None, optional):
                Which mouse button to use to do the click. The default is "left". This will be used by playwright if None
                is passed.
            click_count (int | None, optional):
                Number of clicks. E.g. 2 for a "double-click".
            click_modifiers (list | None, optional):
                Key pressed together with the mouse click.
                Possible values:'Alt', 'Control', 'ControlOrMeta', 'Meta', 'Shift'.
                Default is None = no key pressed.
            repeat_reload (int | None):
                For pages that are not dynamically updated and require a reload to show an update
                a number of page reloads can be configured.
            repeat_reload_delay (float | None):
                Number of seconds to wait.
            show_error (bool, optional):
                Show an error if the element is not found or not clickable.

        Returns:
            bool:
                True if click is successful (or checkbox already in desired state),
                False otherwise.

        """

        if not selector:
            failure_message = "Missing element selector! Cannot find page element!"
            if show_error:
                self.logger.error(failure_message)
            else:
                self.logger.warning(failure_message)
            return False

        success = True  # Final return value

        # If no specific wait until strategy is provided in the
        # parameter, we take the one from the browser automation class:
        if wait_until is None:
            wait_until = self.wait_until

        # Some operations that are done server-side and dynamically update
        # the page may require a waiting time:
        if wait_time > 0.0:
            self.logger.info("Wait for %d milliseconds before clicking...", wait_time * 1000)
            self.page.wait_for_timeout(wait_time * 1000)

            if self.take_screenshots:
                self.take_screenshot(suffix="_wait_before_click")

        elem = self.find_elem(
            selector=selector,
            selector_type=selector_type,
            role_type=role_type,
            wait_state=wait_state,
            exact_match=exact_match,
            regex=regex,
            occurrence=occurrence,
            iframe=iframe,
            repeat_reload=repeat_reload,
            repeat_reload_delay=repeat_reload_delay,
            show_error=show_error,
        )
        if not elem:
            return not show_error

        try:
            if scroll_to_element:
                self.scroll_to_element(elem)

            # Handle checkboxes if requested:
            if desired_checkbox_state is not None and elem.get_attribute("type") == "checkbox":
                # Let Playwright handle checkbox state:
                elem.set_checked(desired_checkbox_state)
                self.logger.debug("Set checkbox -> '%s' to value -> %s.", selector, desired_checkbox_state)
            # Handle non-checkboxes:
            else:
                # Will this click trigger a naviagation?
                if is_navigation_trigger:
                    self.logger.debug(
                        "Clicking on navigation-triggering element -> '%s' (%s%s) and wait until -> '%s'...",
                        selector,
                        "selector type -> '{}'".format(selector_type),
                        ", role type -> '{}'".format(role_type) if role_type else "",
                        wait_until,
                    )
                    with self.page.expect_navigation(wait_until=wait_until):
                        elem.click(force=force, button=click_button, click_count=click_count, modifiers=click_modifiers)
                # Will this click trigger a a new popup window?
                elif is_popup_trigger:
                    with self.page.expect_popup() as popup_info:
                        elem.click(force=force, button=click_button, click_count=click_count, modifiers=click_modifiers)
                    if not popup_info or not popup_info.value:
                        self.logger.info("Popup window did not open as expected!")
                        success = False
                    else:
                        self.page = popup_info.value
                        self.logger.info("Move browser automation to popup window -> %s...", self.page.url)
                elif hover_only:
                    self.logger.debug(
                        "Hovering over element -> '%s' (%s%s)...",
                        selector,
                        "selector type -> '{}'".format(selector_type),
                        ", role type -> '{}'".format(role_type) if role_type else "",
                    )
                    elem.hover()
                else:
                    self.logger.debug(
                        "Clicking on non-navigating element -> '%s' (%s%s)...",
                        selector,
                        "selector type -> '{}'".format(selector_type),
                        ", role type -> '{}'".format(role_type) if role_type else "",
                    )
                    elem.click(force=force, button=click_button, click_count=click_count, modifiers=click_modifiers)
                    time.sleep(1)
                if success:
                    self.logger.debug(
                        "Successfully %s element -> '%s' (%s%s)",
                        "clicked" if not hover_only else "hovered over",
                        selector,
                        "selector type -> '{}'".format(selector_type),
                        ", role type -> '{}'".format(role_type) if role_type else "",
                    )

        except PlaywrightError as e:
            if show_error:
                self.logger.error(
                    "Cannot click page element -> '%s' (%s); error -> %s", selector, selector_type, str(e)
                )
            else:
                self.logger.warning(
                    "Cannot click page element -> '%s' (%s); warning -> %s", selector, selector_type, str(e)
                )
            success = not show_error

        if is_page_close_trigger:
            if self.page == self.main_page:
                self.logger.error("Unexpected try to close main page! Popup page not active! This is not supported!")
                success = False
            else:
                self.page = self.main_page
                self.logger.info("Move browser automation back to main window -> %s...", self.page.url)

        if self.take_screenshots:
            self.take_screenshot()

        return success

    # end method definition

    def find_elem_and_set(
        self,
        selector: str,
        value: str | bool,
        selector_type: str = "id",
        role_type: str | None = None,
        occurrence: int = 1,
        is_sensitive: bool = False,
        press_enter: bool = False,
        exact_match: bool | None = None,
        regex: bool = False,
        iframe: str | None = None,
        typing: bool = False,
        show_error: bool = True,
    ) -> bool:
        """Find an page element and fill it with a new text.

        Args:
            selector (str):
                The name of the page element.
            value (str | bool):
                The new value (text string) for the page element.
            selector_type (str, optional):
                One of "id", "name", "class_name", "xpath", "css", "role", "text", "title",
                "label", "placeholder", "alt".
            role_type (str | None, optional):
                ARIA role when using selector_type="role", e.g., "button", "textbox".
                If irrelevant then None should be passed for role_type.
            occurrence (int, optional):
                If multiple elements match the selector, this defines which one to return.
                Default is 1 (the first one).
            is_sensitive (bool, optional):
                True for suppressing sensitive information in logging.
            press_enter (bool, optional):
                Whether or not to press "Enter" after entering
            exact_match (bool | None, optional):
                If an exact matching is required. Default is None (not set).
            regex (bool, optional):
                Should the name be interpreted as a regular expression?
            iframe (str | None):
                Is the element in an iFrame? Then provide the name of the iframe with this parameter.
            typing (bool, optional):
                Not just set the value of the elem but simulate real typing.
                This is required for pages with fields that do react in a "typeahead" manner.
            show_error (bool, optional):
                Show an error if the element is not found or not clickable.

        Returns:
            bool:
                True if successful, False otherwise

        """

        success = False  # Final return value

        elem = self.find_elem(
            selector=selector,
            selector_type=selector_type,
            role_type=role_type,
            exact_match=exact_match,
            regex=regex,
            occurrence=occurrence,
            iframe=iframe,
            show_error=True,
        )
        if not elem:
            return not show_error

        is_enabled = elem.is_enabled()
        if not is_enabled:
            message = "Cannot set elem -> '{}' ({}) to value -> '{}'. It is not enabled!".format(
                selector, selector_type, value
            )
            if show_error:
                self.logger.error(message)
            else:
                self.logger.warning(message)

            if self.take_screenshots:
                self.take_screenshot()

            return False

        self.logger.info(
            "Set element -> '%s' to value -> '%s'...", selector, value if not is_sensitive else "<sensitive>"
        )

        try:
            # HTML '<select>' can only be identified based on its tag name:
            tag_name = elem.evaluate("el => el.tagName.toLowerCase()")
            # Checkboxes have tag name '<input type="checkbox">':
            input_type = elem.get_attribute("type")

            if tag_name == "select":
                options = elem.locator("option")
                options_count = options.count()
                option_values = [options.nth(i).inner_text().strip().replace("\n", "") for i in range(options_count)]

                if value not in option_values:
                    self.logger.warning(
                        "Provided value -> '%s' is not in available drop-down options -> %s. Cannot set it!",
                        value,
                        option_values,
                    )
                else:
                    # We set the value over the (visible) label:
                    elem.select_option(label=value)
                    success = True
            elif tag_name == "input" and input_type == "checkbox":
                # Handle checkbox
                if not isinstance(value, bool):
                    self.logger.error("Checkbox value must be a boolean!")
                else:
                    retry = 0
                    while elem.is_checked() != value and retry < 5:
                        try:
                            elem.set_checked(checked=value)
                        except Exception:
                            self.logger.warning("Cannot set checkbox to value -> '%s'. (retry %s).", value, retry)
                        finally:
                            retry += 1

                    success = retry < 5  # True is less than 5 retries were needed
            else:
                if typing:
                    elem.type(value, delay=50)
                else:
                    elem.fill(value)
                if press_enter:
                    self.page.keyboard.press("Enter")
                success = True
        except PlaywrightError as e:
            message = "Cannot set page element selected by -> '{}' ({}) to value -> '{}'; error -> {}".format(
                selector, selector_type, value, str(e)
            )
            if show_error:
                self.logger.error(message)
            else:
                self.logger.warning(message)
            success = not show_error

        if self.take_screenshots:
            self.take_screenshot()

        return success

    # end method definition

    def find_element_and_download(
        self,
        selector: str,
        selector_type: str = "id",
        role_type: str | None = None,
        exact_match: bool | None = None,
        regex: bool = False,
        iframe: str | None = None,
        download_time: int = 30,
    ) -> str | None:
        """Click a page element to initiate a download.

        Args:
            selector (str):
                The page element to click for download.
            selector_type (str, optional):
                One of "id", "name", "class_name", "xpath", "css", "role", "text", "title",
                "label", "placeholder", "alt".
            role_type (str | None, optional):
                ARIA role when using selector_type="role", e.g., "button", "textbox".
                If irrelevant then None should be passed for role_type.
            exact_match (bool | None, optional):
                If an exact matching is required. Default is None (not set).
            regex (bool, optional):
                Should the name be interpreted as a regular expression?
            iframe (str | None):
                Is the element in an iFrame? Then provide the name of the iframe with this parameter.
            download_time (int, optional):
                Time in seconds to wait for the download to complete.

        Returns:
            str | None:
                The full file path of the downloaded file.

        """

        try:
            with self.page.expect_download(timeout=download_time * 1000) as download_info:
                clicked = self.find_elem_and_click(
                    selector=selector,
                    selector_type=selector_type,
                    role_type=role_type,
                    exact_match=exact_match,
                    regex=regex,
                    iframe=iframe,
                )
                if not clicked:
                    self.logger.error("Element not found to initiate download.")
                    return None

            download = download_info.value
            filename = download.suggested_filename
            save_path = os.path.join(self.download_directory, filename)
            download.save_as(save_path)
        except Exception as e:
            self.logger.error("Download failed; error -> %s", str(e))
            return None

        self.logger.info("Downloaded file to -> %s", save_path)

        return save_path

    # end method definition

    def check_elems_exist(
        self,
        selector: str,
        selector_type: str = "id",
        role_type: str | None = None,
        value: str | None = None,
        exact_match: bool | None = None,
        attribute: str | None = None,
        substring: bool = True,
        iframe: str | None = None,
        min_count: int = 1,
        wait_time: float = 0.0,
        wait_state: str = "visible",
        show_error: bool = True,
    ) -> tuple[bool | None, int]:
        """Check if (multiple) elements with defined attributes exist on page and return the number.

        Args:
            selector (str):
                The selector to find the element on the page.
            selector_type (str):
                One of "id", "name", "class_name", "xpath", "css", "role", "text", "title",
                "label", "placeholder", "alt".
                When using css, the selector becomes a raw CSS selector, and you can skip attribute
                and value filtering entirely if your selector already narrows it down.
                Examples for CSS:
                * selector="img" - find all img tags (images)
                * selector="img[title]" - find all img tags (images) that have a title attribute - independent of its value
                * selector="img[title*='Microsoft Teams']" - find all images with a title that contains "Microsoft Teams"
                * selector=".toolbar button" - find all buttons inside a .toolbar class
            role_type (str | None, optional):
                ARIA role when using selector_type="role", e.g., "button", "textbox".
                If irrelevant then None should be passed for role_type.
            value (str, optional):
                Value to match in attribute or element content.
            exact_match (bool | None, optional):
                If an exact matching is required. Default is None (not set).
            attribute (str, optional):
                Attribute name to inspect. If None, uses element's text.
            substring (bool):
                If True, allow partial match.
            iframe (str | None):
                Is the element in an iFrame? Then provide the name of the iframe with this parameter.
            min_count (int):
                Minimum number of required matches (# elements on page).
            wait_time (float, optional):
                Time in seconds to wait for elements to appear. Default is 0.0 (no wait).
            wait_state (str, optional):
                Defines if we wait for attached (element is part of DOM) or
                if we wait for elem to be visible (attached, displayed, and has non-zero size).
            show_error (bool, optional):
                Whether to log warnings/errors. Default is True.

        Returns:
            bool | None:
                True if sufficient elements exist. False otherwise.
                None if an error occurs.
            int:
                Number of matched elements.

        """

        failure_message = "No matching page element found with selector -> '{}' ({}){}{}".format(
            selector,
            selector_type,
            " and role type -> '{}'".format(role_type) if role_type else "",
            " in iframe -> '{}'".format(iframe) if iframe else "",
        )

        # Determine the locator for the elements:
        locator = self.get_locator(
            selector=selector,
            selector_type=selector_type,
            role_type=role_type,
            exact_match=exact_match,
            iframe=iframe,
        )
        if not locator:
            self.logger.error(
                "Failed to check if elements -> '%s' (%s) exist! Locator is undefined.", selector, selector_type
            )
            return (None, 0)

        self.logger.info(
            "Check if at least %d element%s found by selector -> '%s' (%s%s)%s%s%s...",
            min_count,
            "s are" if min_count > 1 else " is",
            selector,
            "selector type -> '{}'".format(selector_type),
            ", role type -> {}".format(role_type) if role_type else "",
            " with value -> '{}'".format(value) if value else "",
            " in attribute -> '{}'".format(attribute) if attribute and value else "",
            " in iframe -> '{}'".format(iframe) if iframe else "",
        )

        # Wait for the element to be visible - don't immediately use logic like
        # locator.count() as this does not wait but then fail immideately
        try:
            self.logger.info(
                "Wait for locator to find first matching element with selector -> '%s' (%s%s) and state -> '%s'%s...",
                selector,
                "selector type -> '{}'".format(selector_type),
                ", role type -> {}".format(role_type) if role_type else "",
                wait_state,
                " in iframe -> '{}'".format(iframe) if iframe else "",
            )
            self.logger.info("Locator count before waiting: %d", locator.count())

            # IMPORTANT: We wait for the FIRST element. otherwise we get errors like
            # 'Locator.wait_for: Error: strict mode violation'.
            # IMPORTANT: if the first match does not comply to the
            # wait_state this will block and then timeout. Check your
            # selector to make sure it delivers a visible first element!
            locator.first.wait_for(state=wait_state)
        except PlaywrightError as e:
            # This is typically a timeout error indicating the element does not exist
            # in the defined timeout period.
            if show_error:
                self.logger.error("%s (timeout); error -> %s", failure_message, str(e))
            else:
                self.logger.warning("%s (timeout)", failure_message)
            return (None, 0)

        # Some operations that are done server-side and dynamically update
        # the page with additional matching elements that may require a waiting time:
        if wait_time > 0.0:
            self.logger.info("Wait additional %d milliseconds before checking...", wait_time * 1000)
            self.page.wait_for_timeout(wait_time * 1000)

        count = locator.count()
        if count == 0:
            if show_error:
                self.logger.error("No elements found using selector -> '%s' ('%s')", selector, selector_type)

            if self.take_screenshots:
                self.take_screenshot()

            return (None, 0)

        self.logger.info(
            "Found %d element%s matching selector -> '%s' (%s%s).",
            count,
            "s" if count > 1 else "",
            selector,
            "selector type -> '{}'".format(selector_type),
            ", role type -> '{}'".format(role_type) if role_type else "",
        )

        if value:
            self.logger.info(
                "Checking if their %s %s -> '%s'...",
                "attribute -> '{}'".format(attribute) if attribute else "content",
                "has value" if not substring else "contains",
                value,
            )

        matching_elems = []

        # Iterate over all elements found by the locator and check if
        # they comply with the additional value conditions (if provided).
        # We collect all matching elements in a list:
        for i in range(count):
            elem = locator.nth(i)
            if not elem:
                continue

            if value is None:
                # If value is None we do no filtering, accept all elements:
                matching_elems.append(elem)
                continue

            # Get attribute or text content
            attr_value = elem.get_attribute(attribute) if attribute else elem.text_content()

            if not attr_value:
                # Nothing to compare with - continue:
                continue

            # If substring is True we check with "in" otherwise we use the eual operator (==):
            if (substring and value in attr_value) or (not substring and value == attr_value):
                matching_elems.append(elem)

        matching_elements_count = len(matching_elems)

        if matching_elements_count < min_count:
            success = False
            if show_error:
                self.logger.error(
                    "%s matching element%s found, expected at least %d",
                    "Only {}".format(matching_elements_count) if matching_elems else "No",
                    "s" if matching_elements_count > 1 else "",
                    min_count,
                )
        else:
            success = True
            self.logger.info(
                "Found %d matching element%s.%s",
                matching_elements_count,
                "s" if matching_elements_count > 1 else "",
                " This is {} the minimum {} element{} probed for.".format(
                    "exactly" if matching_elements_count == min_count else "more than",
                    min_count,
                    "s" if min_count > 1 else "",
                ),
            )

        if self.take_screenshots:
            self.take_screenshot()

        return (success, matching_elements_count)

    # end method definition

    def run_login(
        self,
        user_field: str = "otds_username",
        password_field: str = "otds_password",
        login_button: str = "loginbutton",
        page: str = "",
        wait_until: str | None = None,
        selector_type: str = "id",
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
            wait_until (str | None, optional):
                Wait until a certain condition. Options are:
                * "commit" - does not wait at all - commit the request and continue
                * "load" - waits for the load event (after all resources like images/scripts load)
                  This is the safest strategy for pages that keep loading content in the background
                  like Salesforce.
                * "networkidle" - waits until there are no network connections for at least 500 ms.
                  This seems to be the safest one for OpenText Content Server.
                * "domcontentloaded" - waits for the DOMContentLoaded event (HTML is parsed,
                  but subresources may still load).
            selector_type (str, optional):
                One of "id", "name", "class_name", "xpath", "css", "role", "text", "title",
                "label", "placeholder", "alt".
                Default is "id".

        Returns:
            bool:
                True = success, False = error.

        """

        # If no specific wait until strategy is provided in the
        # parameter, we take the one from the browser automation class:
        if wait_until is None:
            wait_until = self.wait_until

        self.logged_in = False

        if (
            not self.get_page(url=page, wait_until=wait_until)
            or not self.find_elem_and_set(selector=user_field, selector_type=selector_type, value=self.user_name)
            or not self.find_elem_and_set(
                selector=password_field, selector_type=selector_type, value=self.user_password, is_sensitive=True
            )
            or not self.find_elem_and_click(
                selector=login_button, selector_type=selector_type, is_navigation_trigger=True, wait_until=wait_until
            )
        ):
            self.logger.error(
                "Cannot log into target system using URL -> %s and user -> '%s'!",
                self.base_url,
                self.user_name,
            )
            return False

        self.logger.debug("Wait for -> '%s' to assure login is completed and target page is loaded.", wait_until)
        self.page.wait_for_load_state(wait_until)

        title = self.get_title()
        if not title:
            self.logger.error(
                "Cannot read page title after login - you may have the wrong 'wait until' strategy configured! Strategy used -> '%s'.",
                wait_until,
            )
            return False

        if "Verify" in title:
            self.logger.error("Site is asking for a verification token. You may need to whitelist your IP!")
            return False
        if "Login" in title:
            self.logger.error("Authentication failed. You may have given the wrong password!")
            return False

        self.logger.info("Login completed successfully! Page title -> '%s'", title)
        self.logged_in = True

        return True

    # end method definition

    def set_timeout(self, wait_time: float) -> None:
        """Wait for the browser to finish tasks (e.g. fully loading a page).

        This setting is valid for the whole browser session and not just
        for a single command.

        Args:
            wait_time (float):
                The time in seconds to wait.

        """

        self.logger.debug("Setting default timeout to -> %.2f seconds...", wait_time)
        self.page.set_default_timeout(wait_time * 1000)
        self.logger.debug("Setting navigation timeout to -> %.2f seconds...", wait_time)
        self.page.set_default_navigation_timeout(wait_time * 1000)

    # end method definition

    def end_session(self) -> None:
        """End the browser session and close the browser."""

        self.logger.info("Close browser page...")
        self.page.close()
        self.logger.info("Close browser context...")
        self.context.close()
        self.logger.info("Close browser...")
        self.browser.close()
        self.logged_in = False
        self.logger.info("Stop Playwright instance...")
        self.playwright.stop()
        self.logger.info("Browser automation has ended.")

    # end method definition

    def __enter__(self) -> object:
        """Enable use with 'with' statement (context manager block)."""

        return self

    # end method definition

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback_obj: TracebackType | None
    ) -> None:
        """Handle cleanup when exiting a context manager block ('with' statement).

        Ensures all browser-related resources are released. If an unhandled exception
        occurs within the context block, it will be logged before cleanup.

        Args:
            exc_type (type[BaseException] | None):
                The class of the raised exception, if any.
            exc_value (BaseException | None):
                The exception instance raised, if any.
            traceback_obj (TracebackType | None):
                The traceback object associated with the exception, if any.

        """

        if exc_type is not None:
            self.logger.error(
                "Unhandled exception in browser automation context -> %s",
                "".join(traceback.format_exception(exc_type, exc_value, traceback_obj)),
            )

        self.end_session()

    # end method definition
