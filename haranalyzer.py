import json
import re
import logging
from urllib.parse import urlparse, parse_qs, urlencode
import hashlib
import time


class HARAnalyzer:
    def __init__(self, har_file_path, main_website, auth_mode="permissive"):
        """
        Initializes HARAnalyzer with the provided parameters.
        :param har_file_path: The path to the .har file to be analyzed.
        :param main_website: The URL of the main website.
        :param auth_mode: Authentication mode for API calls. Can be 'permissive' or 'strict'.
        """
        self.har_file_path = har_file_path
        self.main_website = main_website
        self.auth_mode = auth_mode

        # Accepted file extensions for an API call.
        self.extensions = [
            "css",
            "js",
            "png",
            "jpg",
            "jpeg",
            "svg",
            "gif",
            "ico",
            "woff",
            "ttf",
            "woff2",
        ]

    def analyze(self):
        """
        Analyze the .har file and extract API calls.
        :return: List of API call entries. Each entry is a dictionary.
        """
        entries = self.read_har_file()
        return self.extract_api_calls(entries) if entries else []

    def read_har_file(self):
        """
        Reads the .har file and returns its entries.
        :return: List of entries in the .har file. Each entry is a dictionary.
        """
        try:
            with open(self.har_file_path, "r") as file:
                har_data = json.load(file)
                return (
                    har_data["log"]["entries"]
                    if "log" in har_data and "entries" in har_data["log"]
                    else []
                )
        except FileNotFoundError:
            logging.warning("HAR file not found.")
        except json.JSONDecodeError:
            logging.warning("Invalid JSON format in HAR file.")
        return []

    def extract_api_calls(self, entries):
        """
        Extracts API calls from the entries of the .har file.
        :param entries: The entries of the .har file.
        :return: List of API call entries. Each entry is a dictionary.
        """
        api_entries = []
        processed_entries = set()
        processed_params = set()

        for entry in entries:
            try:
                url, parameters = self.remove_parameters_from_url(
                    entry["request"]["url"]
                )
                if self.auth_mode == "strict":
                    auth_condition = self.has_authorization(entry)
                elif self.auth_mode == "permissive":
                    auth_condition = True
                else:
                    raise ValueError(
                        f"Invalid auth_mode {self.auth_mode}. Please, specify a valid auth_mode type."
                    )

                if (
                    self.is_internal_call(url)
                    and self.is_api_call(url)
                    and auth_condition
                ):
                    self.process_entry(
                        entry,
                        url,
                        parameters,
                        processed_entries,
                        processed_params,
                        api_entries,
                    )
            except Exception as e:
                logging.warning(f"Failed to process entry: {e}")

        if not api_entries:
            logging.warning("No API entries found.")
        return api_entries

    def process_entry(
        self, entry, url, parameters, processed_entries, processed_params, api_entries
    ):
        """
        Processes an entry, adding it to the list of API entries if it passes all checks.
        :param entry: The entry to be processed.
        :param url: The URL of the entry.
        :param parameters: The parameters of the URL.
        :param processed_entries: A set of processed entries.
        :param processed_params: A set of processed parameters.
        :param api_entries: The list of API entries.
        """
        param_hash = self.generate_unique_hash(parameters)
        if (param_hash, url) in processed_params:
            return

        processed_params.add((param_hash, url))

        entry["request"]["url_parameters"] = [parameters]
        entry["request"]["haranalyzer_id"] = self.generate_unique_hash(entry)

        entry_hash = self.generate_unique_hash(entry)
        if entry_hash not in processed_entries:
            processed_entries.add(entry_hash)
            entry["request"]["url"] = url.split("?")[0]
            api_entries.append(entry)

    @staticmethod
    def generate_unique_hash(data, type="entry"):
        """
        Generates a unique hash for the given data.
        :param data: The data for which a hash is to be generated.
        :param type: The type of data.
        :return: The generated hash.
        """
        if type == "entry":
            data = json.dumps(data, sort_keys=True)
        elif type != "string":
            raise ValueError("Not known hash type. Please, specify a valid hash type.")
        return hashlib.md5(data.encode()).hexdigest()

    @staticmethod
    def remove_parameters_from_url(url):
        """
        Removes parameters from the URL.
        :param url: The URL from which parameters are to be removed.
        :return: The URL without parameters, and the parameters as a dictionary.
        """
        parsed_url = urlparse(url)
        parameters = parse_qs(parsed_url.query)
        parsed_url = parsed_url._replace(query="")
        cleaned_url = parsed_url.geturl()
        sorted_parameters = {k: parameters[k] for k in sorted(parameters)}
        return cleaned_url, dict(sorted_parameters) if parameters else {}

    def is_internal_call(self, url):
        """
        Checks whether the URL is an internal call.
        :param url: The URL to be checked.
        :return: True if the URL is an internal call, False otherwise.
        """
        http_scheme = "http://"
        https_scheme = "https://"

        # Remove the scheme from self.main_website
        main_website_base = (
            self.main_website[len(http_scheme) :]
            if self.main_website.startswith(http_scheme)
            else self.main_website[len(https_scheme) :]
        )

        # Check if url starts with http/https scheme and main_website or starts with a forward slash
        return (
            url.startswith(http_scheme + main_website_base)
            or url.startswith(https_scheme + main_website_base)
            or url.startswith("/")
        )

    def is_api_call(self, url):
        """
        Checks whether the URL is an API call.
        :param url: The URL to be checked.
        :return: True if the URL is an API call, False otherwise.
        """
        return self.check_file_extension(url)

    def check_file_extension(self, url):
        """
        Checks whether the file extension of the URL is in the list of accepted extensions.
        :param url: The URL to be checked.
        :return: True if the file extension is not in the list, False otherwise.
        """
        return not any("." + ext in url for ext in self.extensions)

    @staticmethod
    def has_authorization(entry):
        """
        Checks whether the entry has an authorization header.
        :param entry: The entry to be checked.
        :return: True if the entry has an authorization header, False otherwise.
        """
        headers = entry["request"]["headers"]
        return any(header["name"].lower() == "authorization" for header in headers)

    @staticmethod
    def save_output_to_file(output_path, entries):
        """
        Saves the entries to a file in JSON format.
        :param output_path: The path of the file where the entries are to be saved.
        :param entries: The entries to be saved.
        """
        with open(output_path, "w") as file:
            file.write(json.dumps(entries))
