```
.d8888b.   .d8888b.  8888888b.  8888888b.         d8888 Y88b   d88P 8888888888 8888888b.
d88P  Y88b d88P  Y88b 888   Y88b 888   Y88b       d88888  Y88b d88P  888        888   Y88b
888    888 Y88b.      888    888 888    888      d88P888   Y88o88P   888        888    888
888         "Y888b.   888   d88P 888   d88P     d88P 888    Y888P    8888888    888   d88P
888  88888     "Y88b. 8888888P"  8888888P"     d88P  888     888     888        8888888P"
888    888       "888 888        888 T88b     d88P   888     888     888        888 T88b
Y88b  d88P Y88b  d88P 888        888  T88b   d8888888888     888     888        888  T88b
 "Y8888P88  "Y8888P"  888        888   T88b d88P     888     888     8888888888 888   T88b
```

A DOM-based G-Suite password sprayer and user enumerator

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.


### Installing

First, clone the repository

```
git clone https://github.com/yok4i/gsprayer.git
```

Once inside it, run `poetry` to install the dependencies

```
poetry install
```

Alternatively, you can install them with `pip`

```
pip install -r requirements.txt
```

### Help

Use `-h` to show the help menu

```
poetry run ./gsprayer.py -h

usage: gsprayer.py [-h] [-t TARGET] (-u USERNAME | -U FILE) [-o OUTPUT] [-r N] [--headless] [--proxy PROXY] [--wait WAIT] [-v]
                   {enum,spray} ...

G-Suite Password Sprayer.

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target URL (default: https://accounts.google.com/)
  -u USERNAME, --username USERNAME
                        Single username
  -U FILE, --usernames FILE
                        File containing usernames
  -o OUTPUT, --output OUTPUT
                        Output file (default depends on subcommand)
  -r N, --reset-after N
                        Reset browser after N attempts (default: 1)
  --headless            Run in headless mode
  --proxy PROXY         Proxy to pass traffic through: <ip:port>
  --wait WAIT           Time to wait (in seconds) when looking for DOM elements (default: 3)
  --jitter JITTER       Max jitter (in seconds) to be added to wait time (default: 0)
  -v, --verbose         Verbose output

subcommands:
  valid subcommands

  {enum,spray}          additional help
    enum                Perform user enumeration
    spray               Perform password spraying

```

There is also help menu for each subcommand:

```
poetry run ./gsprayer.py <subcommand> -h
```


## Examples

Enumerate valid accounts from a company using G-Suite, in headless mode

```
poetry run ./gsprayer.py -r 50 -U emails.txt --headless enum
```

Perform password spraying using a proxy and waiting 30 minutes between each password iteration

```
poetry run ./gsprayer.py -r 1 -U emails.txt -P passwords.txt --proxy 127.0.0.1:9050 spray --lockout 30
```

### Note

If you are using a proxy with a protocol other than HTTP, you should specify the schema like `socks5://127.0.0.1:9050`.


## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/yok4i/gsprayer/tags). 


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details


## Acknowledgments

* This project was heavily inspired by [0xZDH/msspray](https://github.com/0xZDH/msspray)


## Disclaimer

This tool is intended for educational purpose or for use in environments where you have been given explicit/legal authorization to do so.
