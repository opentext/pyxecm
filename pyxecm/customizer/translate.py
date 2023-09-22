__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2023, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging

import requests

logger = logging.getLogger("pyxecm.customizer.translate")


class Translator:
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

    def config(self):
        return self._config

    def translate(self, source_language: str, target_language: str, text: str) -> str:
        params = {
            "key": self.config()["apiKey"],
            "q": text,
            "source": source_language,
            "target": target_language,
        }

        request_url = self.config()["translateUrlV2"]

        response = requests.post(request_url, params=params)

        if response.status_code != 200:
            logger.error("Failed to translate text -> {}".format(response.content))
            return None

        translated_text = response.json()["data"]["translations"][0]["translatedText"]

        return translated_text

    # end method definition

    def translateV3(self, source_language: str, target_language: str, text: str) -> str:
        data = {
            "source_language_code": source_language,
            "target_language_code": target_language,
            "contents": [text],
            #            "parent": self._parent
        }

        request_header = self._headers
        request_url = self.config()["translateUrlV3"]

        response = requests.post(request_url, headers=request_header, json=data)

        if response.status_code != 200:
            logger.error("Failed to translate text -> {}".format(response.content))
            return None

        translated_text = response.json()["data"]["translations"][0]["translatedText"]

        return translated_text

    # end method definition
