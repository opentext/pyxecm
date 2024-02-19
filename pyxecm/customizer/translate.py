"""
Experimental module to automate translations

Class: Translator
Methods:

__init__ : class initializer
config: Return the configuration parameters
translate: Translate a string from one language to another using the Google Translate V2 API
translateV3: Translate a string from one language to another using the Google Translate V3 API

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import requests

logger = logging.getLogger("pyxecm.customizer.translate")


class Translator:
    """Class for translation of of strings based on the Google Translate API.
    The class supports V2 and V3 translation APIs
    """

    _config = None
    _headers = None

    def __init__(self, api_key: str, project_key: str = "", domain: str = ""):
        translateConfig = {}

        translateConfig["apiKey"] = api_key
        translateConfig[
            "translateUrlV2"
        ] = "https://translation.googleapis.com/language/translate/v2"
        translateConfig[
            "translateUrlV3"
        ] = "https://translation.googleapis.com/v3/projects/{}:translateText".format(
            project_key
        )
        translateConfig["project"] = project_key
        translateConfig["parent"] = "projects/{}/locations/global".format(project_key)
        translateConfig["model"] = f'nmt{":{}".format(domain) if domain else ""}'

        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json; charset=utf-8",
        }

        self._config = translateConfig

    def config(self) -> dict:
        """Return the configuration parameters

        Returns:
            dict: configuration parameters
        """

        return self._config

    def translate(self, source_language: str, target_language: str, text: str) -> str:
        """Translate a string from one language to another using the Google Translate V2 API

        Args:
            source_language (str): source language
            target_language (str): destination language
            text (str): string to translate

        Returns:
            str: translated string
        """

        params = {
            "key": self.config()["apiKey"],
            "q": text,
            "source": source_language,
            "target": target_language,
        }

        request_url = self.config()["translateUrlV2"]

        response = requests.post(url=request_url, params=params, timeout=None)

        if response.status_code != 200:
            logger.error("Failed to translate text -> %s", response.content)
            return None

        translated_text = response.json()["data"]["translations"][0]["translatedText"]

        return translated_text

    # end method definition

    def translateV3(self, source_language: str, target_language: str, text: str) -> str:
        """Translate a string from one language to another using the Google Translate V3 API

        Args:
            source_language (str): source language
            target_language (str): destination language
            text (str): string to translate

        Returns:
            str: translated string
        """

        data = {
            "source_language_code": source_language,
            "target_language_code": target_language,
            "contents": [text],
        }

        request_header = self._headers
        request_url = self.config()["translateUrlV3"]

        response = requests.post(
            url=request_url, headers=request_header, json=data, timeout=None
        )

        if response.status_code != 200:
            logger.error("Failed to translate text -> %s", response.content)
            return None

        translated_text = response.json()["data"]["translations"][0]["translatedText"]

        return translated_text

    # end method definition
