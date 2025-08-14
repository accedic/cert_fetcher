#!/usr/bin/env python3
# Requirements:
#   - httpx
#   - rich
#   - rich-argparse
#
# Install with:
#   pip install httpx rich rich-argparse

import importlib.util
import re
import logging
import argparse
import traceback
import os
import sys
import subprocess
from urllib.parse import urlparse, parse_qs

import httpx
from rich.logging import RichHandler
from rich_argparse import RichHelpFormatter
from rich.console import Console


class CertFetcher:
    """CertFetcher is a client for automating login and SSL certificate retrieval
    from a web-based certificate management interface (such as HestiaCP).
    This class handles the full login flow, session management, and extraction of SSL certificate
    data for domains managed by the remote service. It supports writing the retrieved certificates,
    keys, and CA bundles to files, and provides detailed logging for debugging and auditing.
    Attributes:
        args: Namespace or object containing configuration parameters (e.g., url, username, password, etc.).
        base_url: The base URL of the certificate management web interface.
        user_agent: The User-Agent string used for HTTP requests.
        token: CSRF or session token extracted from HTML forms.
        session_id: Session identifier (e.g., HESTIASID cookie value).
        cookies: httpx.Cookies object for managing session cookies.
        headers: Dictionary of HTTP headers for requests.
        client: httpx.Client instance for making HTTP requests.
        logger: Logger instance for logging messages.
        output_dir: Directory to write certificate files to.
        domain: Optional; specific domain to fetch certificates for.
        write_to_file: Boolean; whether to write certificates to files.
        debug: Boolean; enables debug logging if True.
    Methods:
        __init__(self, args): Initializes the client with the given arguments.
        set_http_client(self): Sets up the HTTP client, cookies, and headers.
        _display_namespace_vars(self): Logs all instance variables for debugging.
        set_args(self): Sets instance attributes from the provided args.
        setup_logging(self): Configures logging based on debug flag.
        _update_cookies_and_headers(self, response): Updates cookies and headers from HTTP responses.
        _extract_token(self, html): Extracts CSRF/session token from HTML.
        get_login_page(self): Fetches the login page and extracts token/cookies.
        post_username(self): Submits the username to the login form.
        post_password(self): Submits the password to the login form.
        get_front_page(self): Retrieves the main page listing managed domains.
        fetch_domain_certificate_page(self, domain_edit_url, domain_name): Fetches and parses the certificate page for a domain.
        parse_certificate_page(self, html, domain_name): Extracts certificate, key, and CA values from HTML.
        set_domain_name(self, domain_url): Extracts the domain name from a domain URL.
        full_login_flow(self): Executes the full login and certificate retrieval flow.
        run(self): Runs the main workflow, optionally writing certificates to files.
        write_certificate_to_file(self, domain_data): Writes certificate, key, CA, and fullchain to files.
    Usage:
        Instantiate with configuration arguments, then call run() to perform the login and certificate retrieval process.
    """

    def __init__(self, args):
        """
        Initializes the class with the provided arguments.
        Args:
            args: Arguments required for class initialization.
        Performs the following actions:
            - Stores the provided arguments.
            - Sets additional arguments using set_args().
            - Configures logging via setup_logging().
            - Initializes the HTTP client with set_http_client().
        """
        self.args = args
        self.set_args()
        self.setup_logging()
        self.set_http_client()

    def set_http_client(self):
        """
        Initializes and configures the HTTP client for the instance.
        Sets up the base URL, user agent, authentication tokens, session ID, cookies, and default headers
        required for making HTTP requests. Instantiates an `httpx.Client` with the configured parameters,
        enabling automatic redirect following and disabling SSL verification.
        Attributes set:
            - self.base_url: The base URL for HTTP requests, stripped of trailing slashes.
            - self.user_agent: The user agent string for HTTP requests.
            - self.token: Placeholder for authentication token (initialized as None).
            - self.session_id: Placeholder for session ID (initialized as None).
            - self.cookies: An httpx.Cookies object for managing cookies.
            - self.headers: A dictionary of default HTTP headers for requests.
            - self.client: An httpx.Client instance configured with the above parameters.
        """

        self.base_url = self.url.rstrip("/")
        self.user_agent = "CertFetcher certificate client"

        self.token = None
        self.session_id = None
        self.cookies = httpx.Cookies()
        self.headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
            "cache-control": "max-age=0",
            "content-type": "application/x-www-form-urlencoded",
            "origin": self.base_url,
            "priority": "u=0, i",
            "referer": f"{self.base_url}/login/",
            "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Linux"',
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": self.user_agent
            or "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
        }
        self.client = httpx.Client(
            base_url=self.base_url,
            cookies=self.cookies,
            headers=self.headers,
            follow_redirects=True,
            verify=False,
        )

    def _display_namespace_vars(self):
        """
        Logs all non-private instance variables of the class at the debug level.
        This method iterates over the instance's namespace (i.e., its __dict__),
        and logs the name and value of each variable that does not start with an underscore.
        Private or protected variables (those starting with '_') are skipped.
        """
        self.logger = logging.getLogger("CertFetcher")
        self.logger.debug("Namespace variables:")
        for k, v in vars(self).items():
            if k.startswith("_"):
                continue
            else:
                self.logger.debug(f"{k}: {v}")

    def set_args(self):
        """
        Sets instance attributes based on the attributes of self.args.
        Iterates over all attributes of the self.args object and sets them as attributes
        of the current instance with the same names and values.
        This allows for convenient propagation of argument values to the instance.
        Example:
            If self.args has an attribute 'foo' with value 42, after calling this method,
            self.foo will also be set to 42.
        """

        for k, v in vars(self.args).items():
            setattr(self, k, v)

    def setup_logging(self):
        """
        Configures logging for the application based on the debug mode.
        In debug mode:
            - Sets up logging with DEBUG level for all loggers, including 'httpx' and 'httpcore'.
            - Uses a rich handler for enhanced log output formatting.
            - Displays namespace variables for debugging purposes.
            - Assigns a logger named 'CertFetcher' to self.logger.
        In non-debug mode:
            - Sets up logging with INFO level for the main script only.
            - Restricts 'httpx' and 'httpcore' loggers to WARNING level to reduce verbosity.
            - Uses a rich handler for log output formatting.
            - Assigns a logger named 'CertFetcher' to self.logger.
        """

        if self.debug:
            # Enable full debug for everything, including httpx
            logging.basicConfig(
                format="[ %(name)s ]: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
                level=logging.DEBUG,
                handlers=[RichHandler()],
            )
            # Set httpx loggers to DEBUG
            for logger_name in ["httpx", "httpcore"]:
                logging.getLogger(logger_name).setLevel(logging.DEBUG)
            self._display_namespace_vars()
            self.logger = logging.getLogger("CertFetcher")
        else:
            # Only log info from this script, do not touch httpx loggers
            logging.basicConfig(
                format="[ %(name)s ]: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
                level=logging.INFO,
                handlers=[RichHandler()],
            )
            for logger_name in ["httpx", "httpcore"]:
                logging.getLogger(logger_name).setLevel(logging.WARNING)
            self.logger = logging.getLogger("CertFetcher")

    def _update_cookies_and_headers(self, response):
        """
        Updates the client's cookies and headers based on the given HTTP response.
        This method performs the following actions:
            - Iterates through all cookies in the response and updates the client's cookie jar.
            - If the 'HESTIASID' cookie is present, updates the session ID accordingly.
            - Sets the 'referer' header to the URL of the response for use in subsequent requests.
            - Updates the client's headers with the modified headers.
        Args:
            response: The HTTP response object containing cookies and URL information.
        """

        for k, v in response.headers.items():
            if k == "Set-Cookie" or k == "Cookie" and k == "HESTIASID":

                self.logger.debug(f"Setting cookie from header: {v}")

                self.cookies.set_cookie(v)
        for x in self.client.cookies.items():
            self.logger.debug(f"Client Cookie {x[0]}: {x[1]}")
        for x in self.client.headers.items():
            self.logger.debug(f"Client Header {x[0]}: {x[1]}")

    def _extract_token(self, html):
        """
        Extracts a token value from an HTML input field.
        This method searches the provided HTML string for an <input> element with the name attribute set to "token"
        and extracts the value of its value attribute.
        Args:
            html (str): The HTML content as a string.
        Returns:
            str or None: The extracted token if found, otherwise None.
        """

        # Extract token from HTML input field
        match = re.search(
            r'<input[^>]+name=["\']token["\'][^>]+value=["\']([^"\']+)["\']', html
        )
        if match:
            self.token = match.group(1)
            self.logger.debug(self.token)
            return self.token
        return None

    def get_login_page(self):
        self.logger.debug("Fetching login page...")
        """
        Sends a GET request to the login page, updates cookies and headers, extracts the authentication token, and returns the response.
        Returns:
            requests.Response: The response object from the GET request to the login page.
        """

        resp = self.client.get("/login/")
        for x in self.client.__dict__.items():
            self.logger.debug(
                f"{self.get_login_page.__name__} Client attribute {x[0]}: {x[1]}"
            )
        self.logger.debug(
            f"Fetching {self.post_username.__name__}: {self.base_url}/login/\n"
            f"Response status code: {resp.status_code}"
        )

        self._update_cookies_and_headers(resp)
        self._extract_token(resp.text)
        return resp

    def post_username(self):
        """
        Sends a POST request to the '/login/' endpoint with the current username and token.
        The method constructs a data payload containing the authentication token and username,
        sends it to the login endpoint, updates the client's cookies and headers based on the response,
        and extracts a new token from the response text.
        Returns:
            Response: The response object returned by the POST request.
        """
        self.logger.debug("sending username...")
        data = {"token": self.token, "user": self.username}
        resp = self.client.post("/login/", data=data, cookies=self.cookies)
        for x in self.client.__dict__.items():
            self.logger.debug(
                f"{self.post_username.__name__} Client attribute {x[0]}: {x[1]}"
            )
        self.logger.debug(
            f"Fetching {self.post_username.__name__}: {self.base_url}/list/web/\n"
            f"Response status code: {resp.status_code}"
        )
        self._update_cookies_and_headers(resp)
        self._extract_token(resp.text)

        return resp

    def post_password(self):
        """
        Sends a POST request to the '/login/' endpoint with the user's token and password.
        This method constructs a payload containing the current token and password,
        sends it to the login endpoint, updates the client's cookies and headers based
        on the response, and returns the response object.
        Returns:
            Response: The response object returned by the POST request.
        """
        self.logger.debug("sending password...")
        data = {"token": self.token, "password": self.password}
        resp = self.client.post("/login/", data=data, cookies=self.cookies)
        if resp.status_code != 200 or "login" in str(resp.url).lower():
            self.logger.error("Login failed. Check your credentials.")
            self.logger.debug(resp.status_code)
            self.logger.debug(resp.url)
            raise Exception("Login failed")

        self.logger.info("Login successful.")
        for x in self.client.__dict__.items():
            self.logger.debug(
                f"{self.post_password.__name__} Client attribute {x[0]}: {x[1]}"
            )
        self.logger.debug(
            f"Fetching post_pwd: {self.base_url}/list/web/\n"
            f"Response status code: {resp.status_code}"
        )
        domain_edit_urls = re.findall(r'href="/edit/web/([^"]+)"', resp.text)
        domain_edit_urls = list(set(domain_edit_urls))  # Remove duplicates
        uri_data = []
        for x in domain_edit_urls:
            parsed_uri = urlparse(self.base_url + x)
            domain = parse_qs(parsed_uri.query)["domain"][0]
            token = parse_qs(parsed_uri.query)["token"][0]
            d = {
                "uri": x,
                "domain": domain,
                "token": token,
            }
            uri_data.append(d)
            self.logger.debug(f"Extracted domain: {d['domain']}, token: {d['token']}")
        self._extract_token(resp.text)
        self._update_cookies_and_headers(resp)
        prep_return = {"response": resp, "uri_data": uri_data}
        return prep_return

    def fetch_domain_certificate_page(self, domain_edit_url, domain_name):
        """
        Fetches the SSL certificate information for a given domain by accessing its edit page.

        Args:
            domain_edit_url (str): The URL segment or identifier used to access the domain's edit page.
            domain_name (str): The name of the domain for which the SSL certificate is being fetched.

        Returns:
            dict: Parsed SSL certificate data for the specified domain.

        Logs:
            Debug information about the fetching process.
        """
        # self.logger.info(f"Fetching SSL certificate for domain: {domain_name}")
        self.logger.debug(f"Domain edit URL: {domain_edit_url}")
        self.logger.debug(f"Fetching SSL certificate for domain: {domain_edit_url}")
        resp = self.client.get(
            f"/edit/web/{domain_edit_url}",
            cookies=self.cookies,
        )

        for x in self.client.__dict__.items():
            self.logger.debug(
                f"{self.fetch_domain_certificate_page.__name__} Client attribute {x[0]}: {x[1]}"
            )

        cert_data = self.parse_certificate_page(resp.text, domain_name)
        self.logger.debug(cert_data)
        self._extract_token(resp.text)
        self._update_cookies_and_headers(resp)
        return cert_data

    def parse_certificate_page(self, html, domain_name):
        """Parses the HTML content of an SSL certificate edit page to extract certificate, key, and CA values.

        Args:
            html (str): The HTML content of the edit page containing SSL certificate fields.
            domain_name (str): The domain name associated with the SSL certificate.

        Returns:
            dict: A dictionary containing:
                - 'domain' (str): The provided domain name.
                - 'ssl_crt_value' (str or None): The extracted SSL certificate value, or None if not found.
                - 'ssl_key_value' (str or None): The extracted SSL key value, or None if not found.
                - 'ssl_ca_value' (str or None): The extracted SSL CA value, or None if not found.

        Logs:
            Debug information about the extraction process and the values found.
        """

        data = {"domain": domain_name}
        # Parse the page for the textarea with name="v_ssl_crt" and extract its value
        match = re.search(
            r'<textarea[^>]+name=["\']v_ssl_crt["\'][^>]*>(.*?)</textarea>',
            html,
            re.DOTALL,
        )
        ssl_crt_value = match.group(1).strip() if match else None
        data["ssl_crt_value"] = ssl_crt_value
        logging.debug(
            f"Extracted SSL certificate value: {ssl_crt_value[:40]}..."
            if ssl_crt_value
            else "SSL certificate not found."
        )
        logging.debug(f"{domain_name} SSL certificate value: {ssl_crt_value}")
        # Parse the page for the textarea with name="v_ssl_key" and extract its value
        match_key = re.search(
            r'<textarea[^>]+name=["\']v_ssl_key["\'][^>]*>(.*?)</textarea>',
            html,
            re.DOTALL,
        )
        ssl_key_value = match_key.group(1).strip() if match_key else None
        logging.debug(
            f"Extracted SSL key value: {ssl_key_value[:40]}..."
            if ssl_key_value
            else "SSL key not found."
        )
        logging.debug(f"{domain_name} SSL key value: {ssl_key_value}")
        data["ssl_key_value"] = ssl_key_value
        # Parse the page for the textarea with name="v_ssl_ca" and extract its value
        match_ca = re.search(
            r'<textarea[^>]+name=["\']v_ssl_ca["\'][^>]*>(.*?)</textarea>',
            html,
            re.DOTALL,
        )
        ssl_ca_value = match_ca.group(1).strip() if match_ca else None
        logging.debug(
            f"Extracted SSL CA value: {ssl_ca_value[:40]}..."
            if ssl_ca_value
            else "SSL CA not found."
        )
        logging.debug(f"{domain_name} SSL CA value: {ssl_ca_value}")
        data["ssl_ca_value"] = ssl_ca_value
        logging.debug(data)
        return data

    def set_domain_name(self, domain_url):
        """
        Extracts and returns the domain name from a given domain URL string.
        The function expects the input string to contain a key-value pair separated by '='
        and possibly additional parameters separated by '&'. It extracts the value after the first '='
        and before any '&' character.
        Args:
            domain_url (str): The URL string containing the domain information, typically in the format 'key=domain.com&other=params'.
        Returns:
            str: The extracted domain name.
        Raises:
            IndexError: If the input string does not contain the expected '=' character.
        """

        logging.debug(domain_url)
        domain_name = domain_url.split("&")[0].split("=")[1]
        logging.debug(f"Set domain name: {domain_name}")
        return domain_name

    def full_login_flow(self):
        """
        Executes the full login flow and retrieves certificate data for all available domains.
        Steps performed:
            1. Loads the login page.
            2. Submits the username.
            3. Submits the password and checks for successful authentication.
            4. Retrieves the list of domain paths from the front page.
            5. Iterates over each domain path, sets the domain name, and fetches certificate data.
            6. Logs relevant information and debugging details.
        Returns:
            list: A list containing certificate data for each domain.
        Raises:
            Exception: If login fails due to incorrect credentials or unsuccessful authentication.
        """

        # Step 1: GET /login/
        login_resp = self.get_login_page()

        # Step 2: POST username
        user_resp = self.post_username()

        # Step 3: POST password
        resp_pass = self.post_password()
        uri_data = resp_pass.get("uri_data", [])
        resp_pass = resp_pass.get("response", None)
        list_of_domain_path = [x.get("uri", []) for x in uri_data]
        self.logger.info(f"Found {len(list_of_domain_path)} domains.")
        for x in uri_data:
            self.logger.info(f"Domain: {x['domain']}")

        all_certificate_data = []

        for x in list_of_domain_path:
            domain_name = self.set_domain_name(x)
            cert_data = self.fetch_domain_certificate_page(x, domain_name)
            self.logger.debug(cert_data)
            all_certificate_data.append(cert_data)

        # self.loop_over_domain_urls(list_of_domain_path)
        debug_dict = {
            "login_page": login_resp,
            "username_post": user_resp,
            "password_post": resp_pass,
            "uri_data": uri_data,
            "HESTIASID": self.session_id,
            "token": self.token,
        }
        for k, v in debug_dict.items():
            if k == "uri_data":
                for x in v:
                    for k, v in x.items():
                        self.logger.debug(f"{k}: {v}")
            else:
                self.logger.debug(f"{k}: {v}")

        return all_certificate_data

    def run(self):
        """
        Executes the full login flow, processes the results, and optionally writes certificates to files.
        Returns:
            list: A list containing the results of writing certificates to files, if applicable.
        Raises:
            httpx.HTTPStatusError: If an HTTP error occurs during the login flow.
            Exception: For any other exceptions, logs the error with traceback information.
        Behavior:
            - Calls `self.full_login_flow()` to perform the login process.
            - If `self.domain` is set, only processes results matching the domain.
            - If `self.write_to_file` is True, writes the certificate to a file and appends the result to the response list.
            - Handles and logs HTTP and general exceptions.
        """
        self.logger.debug(self.write_to_file)
        try:
            result = self.full_login_flow()
            final_response = []
            for x in result:
                if self.domain:
                    if x["domain"] == self.domain:
                        if self.write_to_file:
                            final_response.append(self.write_certificate_to_file(x))
                            break
                else:
                    if self.write_to_file:
                        final_response.append(self.write_certificate_to_file(x))

            # self.logger.info("Login flow completed successfully.")
            return final_response
        except httpx.HTTPStatusError as e:
            logging.error(
                f"HTTP error occurred: {e.response.status_code} - {e.response.text}"
            )
        except Exception as e:
            tb = traceback.extract_tb(e.__traceback__)
            if tb:
                filename, lineno, func, text = tb[-1]
                logging.error(
                    f"An error occurred at {filename}, line {lineno}: {str(e)}"
                )
            else:
                logging.error(f"An error occurred: {str(e)}")

    def write_certificate_to_file(self, domain_data):
        """
        Writes SSL certificate, key, and CA values from the provided domain data to files in the specified output directory.
        Args:
            domain_data (dict): A dictionary containing SSL data for a domain. Expected keys are:
                - 'domain' (str): The domain name.
                - 'ssl_crt_value' (str, optional): The SSL certificate content.
                - 'ssl_key_value' (str, optional): The SSL private key content.
                - 'ssl_ca_value' (str, optional): The SSL certificate authority content.
        Returns:
            dict: A dictionary containing the domain and the file paths for the written certificate, key, CA, and fullchain files (if applicable).
        Logs:
            - Information about the writing process and file paths.
            - Warnings if any of the certificate, key, or CA values are missing.
            - Debug messages for each file written.
        Notes:
            - If both certificate and CA are present, a fullchain PEM file is also created.
            - If the output directory does not exist, it will be created.
            - If none of the certificate, key, or CA values are present, a warning is logged and only the domain is returned.
        """

        result = {"domain": domain_data["domain"]}
        # self.logger.info(f"Writing certificates to {self.output_dir}")
        domain = domain_data["domain"]
        ssl_crt_value = domain_data.get("ssl_crt_value")
        ssl_key_value = domain_data.get("ssl_key_value")
        ssl_ca_value = domain_data.get("ssl_ca_value")
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

        if ssl_crt_value:
            if self.write_to_file is True:
                cert_file_path = f"{self.output_dir}/{domain}.crt"
                with open(cert_file_path, "w") as cert_file:
                    cert_file.write(ssl_crt_value)
                logging.debug(f"Wrote certificate to {cert_file_path}")
                result["ssl_crt_value"] = cert_file_path
                self.logger.info(f"Wrote crt to {cert_file_path}")
            if self.write_to_file is False:
                self.logger.info(ssl_crt_value)

        if ssl_key_value:
            if self.write_to_file is True:
                key_file_path = f"{self.output_dir}/{domain}.key"
                with open(key_file_path, "w") as key_file:
                    key_file.write(ssl_key_value)
                logging.debug(f"Wrote key to {key_file_path}")
                result["ssl_key_value"] = key_file_path
                self.logger.info(f"Wrote key to {key_file_path}")
            if self.write_to_file is False:
                self.logger.info(ssl_key_value)
        if self.write_to_file is True:
            if ssl_ca_value:
                ca_file_path = f"{self.output_dir}/{domain}.ca"
                with open(ca_file_path, "w") as ca_file:
                    ca_file.write(ssl_ca_value)
                logging.debug(f"Wrote CA to {ca_file_path}")
                result["ssl_ca_value"] = ca_file_path
                self.logger.info(f"Wrote ca to {ca_file_path}")
            if self.write_to_file is False:
                self.logger.info(ssl_ca_value)

        if not ssl_crt_value and not ssl_key_value and not ssl_ca_value:
            self.logger.warning(
                f"No SSL certificate, key, or CA found for domain: {domain}"
            )
            return result

        if not ssl_crt_value:
            self.logger.warning(
                f"No SSL certificate found for domain: {domain}. Skipping fullchain creation."
            )
            return result

        if not ssl_ca_value:
            self.logger.warning(
                f"No SSL CA found for domain: {domain}. Skipping fullchain creation."
            )
            return result

        # Write fullchain file if both crt and ca are present
        if self.write_to_file is True:
            if ssl_crt_value and ssl_ca_value:
                fullchain_file_path = f"{self.output_dir}/fullchain_{domain}.pem"
                with open(fullchain_file_path, "w") as fullchain_file:
                    fullchain_file.write(ssl_crt_value + "\n" + ssl_ca_value)
                logging.debug(f"Wrote fullchain to {fullchain_file_path}")
                result["ssl_fullchain_value"] = fullchain_file_path
                self.logger.info(f"Wrote fullchain to {fullchain_file_path}")
            if self.write_to_file is False:
                self.logger.info(ssl_crt_value + "\n" + ssl_ca_value)
        return result


if __name__ == "__main__":
    console = Console()
    console.print(
        r"""
 .--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--. 
/ .. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \
\ \/\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ \/ /
 \/ /`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'\/ / 
 / /\   ____                   __        ____        __           __                         / /\ 
/ /\ \ /\  _`\                /\ \__    /\  _`\     /\ \__       /\ \                       / /\ \
\ \/ / \ \ \/\_\     __   _ __\ \ ,_\   \ \ \L\_\ __\ \ ,_\   ___\ \ \___      __   _ __    \ \/ /
 \/ /   \ \ \/_/_  /'__`\/\`'__\ \ \/    \ \  _\/'__`\ \ \/  /'___\ \  _ `\  /'__`\/\`'__\   \/ / 
 / /\    \ \ \L\ \/\  __/\ \ \/ \ \ \_    \ \ \/\  __/\ \ \_/\ \__/\ \ \ \ \/\  __/\ \ \/    / /\ 
/ /\ \    \ \____/\ \____\\ \_\  \ \__\    \ \_\ \____\\ \__\ \____\\ \_\ \_\ \____\\ \_\   / /\ \
\ \/ /     \/___/  \/____/ \/_/   \/__/     \/_/\/____/ \/__/\/____/ \/_/\/_/\/____/ \/_/   \ \/ /
 \/ /                                                                                        \/ / 
 / /\.--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--./ /\ 
/ /\ \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \/\ \
\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `' /
 `--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'
    """,
        style="bold cyan",
        justify="center",
    )
    parser = argparse.ArgumentParser(
        description="CertFetcher: Automate SSL Certificate Retrieval",
        formatter_class=RichHelpFormatter,
        epilog="This script automates the login and SSL certificate retrieval process for Hestia Control Panel.",
        add_help=True,
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="%(prog)s 1.0.0\nThis script automates the login and SSL certificate retrieval process for Hestia Control Panel.",
        help="Show the version of the script and exit.",
    )
    parser.add_argument(
        "-U",
        "--url",
        type=str,
        required=True,
        help="Base URL of the certificate management web interface (e.g., HestiaCP). "
        "This is where the login and certificate retrieval will be performed. ",
    )
    parser.add_argument(
        "-u",
        "--username",
        type=str,
        required=True,
        help="Username for login to the certificate management interface. "
        "This value is required for authentication.",
    )
    parser.add_argument(
        "-p",
        "--password",
        type=str,
        required=True,
        help="Password for login to the certificate management interface. "
        "This value is required for authentication.",
    )
    parser.add_argument(
        "-w",
        "--write-to-file",
        action="store_true",
        help="If set, writes fetched SSL certificates, keys, and CA bundles to files in the output directory. "
        "Otherwise, certificates are only retrieved and not saved to disk.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=str,
        required=False,
        default="./certificates",
        help="Output directory for writing SSL certificate, key, CA, and fullchain files. "
        "If the directory does not exist, it will be created. "
        "Default: ./certificates",
    )
    parser.add_argument(
        "-d",
        "--domain",
        type=str,
        required=False,
        help="Specific domain to fetch certificates for. "
        "If provided, only this domain will be processed; otherwise, all domains will be fetched.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging for detailed output, including HTTP requests and internal state.",
    )

    args = parser.parse_args()

    CertFetcher(args).run()
