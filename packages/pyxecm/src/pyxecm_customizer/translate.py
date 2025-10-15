"""Experimental module to automate translations."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging

import requests

default_logger = logging.getLogger("pyxecm_customizer.translate")

REQUEST_TIMEOUT = 60.0


class Translator:
    """Class Translator is used for translation of of strings based on the Google Translate API.

    The class supports V2 and V3 translation APIs.
    """

    logger: logging.Logger = default_logger

    _config = None
    _headers = None

    def __init__(
        self,
        api_key: str,
        project_key: str = "",
        domain: str = "",
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the Translate objects.

        Args:
            api_key (str):
                The Google Translate API key.
            project_key (str, optional):
                The Google project. Defaults to "".
            domain (str, optional):
                The domain. Defaults to "".
            logger (logging.Logger, optional):
                The logging object to log all messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("translator")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        translate_config = {}

        translate_config["apiKey"] = api_key
        translate_config["translateUrlV2"] = "https://translation.googleapis.com/language/translate/v2"
        translate_config["translateUrlV3"] = "https://translation.googleapis.com/v3/projects/{}:translateText".format(
            project_key,
        )
        translate_config["project"] = project_key
        translate_config["parent"] = "projects/{}/locations/global".format(project_key)
        translate_config["model"] = f"nmt{':{}'.format(domain) if domain else ''}"

        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json; charset=utf-8",
        }

        self._config = translate_config

    def config(self) -> dict:
        """Return the configuration parameters.

        Returns:
            dict:
                The onfiguration parameters.

        """

        return self._config

    def translate(self, source_language: str, target_language: str, text: str) -> str:
        """Translate a string from one language to another using the Google Translate V2 API.

        Args:
            source_language (str):
                The source language.
            target_language (str):
                The target language.
            text (str):
                The string to translate.

        Returns:
            str:
                The translated string.

        """

        params = {
            "key": self.config()["apiKey"],
            "q": text,
            "source": source_language,
            "target": target_language,
        }

        request_url = self.config()["translateUrlV2"]

        response = requests.post(
            url=request_url,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            self.logger.error("Failed to translate text -> %s", response.content)
            return None

        translated_text = response.json()["data"]["translations"][0]["translatedText"]

        return translated_text

    # end method definition

    def translate_v3(self, source_language: str, target_language: str, text: str) -> str:
        """Translate a string from one language to another using the Google Translate V3 API.

        Args:
            source_language (str):
                The source language.
            target_language (str):
                The destination language.
            text (str):
                The string to translate.

        Returns:
            str:
                The translated string.

        """

        data = {
            "source_language_code": source_language,
            "target_language_code": target_language,
            "contents": [text],
        }

        request_header = self._headers
        request_url = self.config()["translateUrlV3"]

        try:
            response = requests.post(
                url=request_url,
                headers=request_header,
                json=data,
                timeout=REQUEST_TIMEOUT,
            )

            if response.status_code != 200:
                self.logger.error("Failed to translate text -> %s", response.content)
                return None

        except Exception as error:
            self.logger.error("Failed translation request; error -> %s", str(error))

        translated_text = response.json()["data"]["translations"][0]["translatedText"]

        return translated_text

    # end method definition
