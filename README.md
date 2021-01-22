![dirsearch](https://user-images.githubusercontent.com/59408894/103289759-87a0ce80-4a1a-11eb-89c9-2feb7e6db25f.png) - *Hacking is not a crime*

dirsearch - Web path scanner
=========

![Build](https://img.shields.io/badge/Built%20with-Python-Blue)
![License](https://img.shields.io/badge/license-GNU_General_Public_License-_red.svg)
![Release](https://img.shields.io/github/release/maurosoria/dirsearch.svg)
![Stars](https://img.shields.io/github/stars/maurosoria/dirsearch.svg)
<a href="https://twitter.com/intent/tweet?text=Dirsearch%20-%20Web%20path%20scanner%20by%20@_maurosoria%0A%0Ahttps://github.com/maurosoria/dirsearch">
    ![Tweet](https://img.shields.io/twitter/url?url=https%3A%2F%2Fgithub.com%2Fmaurosoria%2Fdirsearch)
</a>

**Current Release: v0.4.1 (2020.12.8)**


Overview
--------
- Dirsearch is a mature command-line tool designed to brute force directories and files in webservers. 

- With 6 years of growth, dirsearch now has become the top web content scanner.

- As a feature-rich tool, dirsearch gives users the opportunity to perform a complex web content discovering, with many vectors for the wordlist, high accuracy, impressive performance, advanced connection/request settings, modern brute-force techniques and nice output.

- Dirsearch is being actively developed by [@maurosoria](https://twitter.com/_maurosoria) and [@shelld3v](https://github.com/shelld3v)


Installation & Usage
------------

```python
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
python3 dirsearch.py -u <URL> -e <EXTENSIONS>
```

- To can use SOCKS proxy or work with `../` in the wordlist, you need to install pips with `requirements.txt`: `pip3 install -r requirements.txt`

- If you are using Windows and don't have git, you can install the ZIP file [here](https://github.com/maurosoria/dirsearch/archive/master.zip). Dirsearch also supports [Docker](https://github.com/maurosoria/dirsearch#support-docker)

*Dirsearch requires python 3 or greater*


Features
--------
- Fast
- Easy and simple to use
- Multithreading
- Wildcard responses filtering (invalid webpages)
- Keep alive connections
- Support for multiple extensions
- Support for every HTTP method
- Support for HTTP request data
- Support for raw request
- Extensions excluding
- Reporting (Plain text, JSON, XML, Markdown, CSV)
- Recursive brute forcing
- Target enumeration from an IP range
- Sub-directories brute forcing
- Force extensions
- HTTP and SOCKS proxy support
- HTTP cookies and headers support
- HTTP headers from file
- User agent randomization
- Proxy host randomization
- Batch processing
- Request delaying
- 429 response code detecting
- Multiple wordlist formats (lowercase, uppercase, capitalization)
- Default configuration from file
- Option to force requests by hostname
- Option to add custom suffixes and prefixes
- Option to whitelist response codes, support ranges (-i 200,300-399)
- Option to blacklist response codes, support ranges (-x 404,500-599)
- Option to exclude responses by sizes
- Option to exclude responses by texts
- Option to exclude responses by regexp(s)
- Option to exclude responses by redirects
- Options to display only items with response length from range
- Option to remove all extensions from every wordlist entry
- Quiet mode
- Debug mode


About wordlists
---------------
**Summary**: Wordlist must be a text file, each line will be an endpoint. About extensions, unlike other tools, dirsearch won't append extensions to every word, if you don't use the `-f` flag. By default, only the `%EXT%` keyword in the wordlist will be replaced with extensions (`-e <extensions>`).

**Details**:
- Each line in the wordlist will be processed as such, except when the special keyword *%EXT%* is used, it will generate one entry for each extension (-e | --extensions) passed as an argument.

Example:

```
root/
index.%EXT%
```

Passing the extensions "asp" and "aspx" (`-e asp,aspx`) will generate the following dictionary:

```
root/
index
index.asp
index.aspx
```

- For wordlists without *%EXT%* (like [SecLists](https://github.com/danielmiessler/SecLists)), you need to use the **-f | --force-extensions** switch to append extensions to every word in the wordlists, as well as the "/". And for entries in the wordlist that you do not want to force, you can add *%NOFORCE%* at the end of them so dirsearch won't append any extension.

Example:

```
admin
home.%EXT%
api%NOFORCE%
```

Passing extensions "php" and "html" with the **-f**/**--force-extensions** flag (`-f -e php,html`) will generate the following dictionary:

```
admin
admin.php
admin.html
admin/
home
home.php
home.html
api
```

*To use multiple wordlists, you can seperate your wordlists with commas. Example: -w wordlist1.txt,wordlist2.txt*


Options
-------


```
Usage: dirsearch.py [-u|--url] target [-e|--extensions] extensions [options]

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit

  Mandatory:
    -u URL, --url=URL   Target URL
    -l FILE, --url-list=FILE
                        URL list file
    --stdin             URL list from STDIN
    --cidr=CIDR         Target CIDR
    --raw=FILE          File contains the raw request (use `--scheme` flag to
                        set the scheme)
    -e EXTENSIONS, --extensions=EXTENSIONS
                        Extension list separated by commas (Example: php,asp)
    -X EXTENSIONS, --exclude-extensions=EXTENSIONS
                        Exclude extension list separated by commas (Example:
                        asp,jsp)
    -f, --force-extensions
                        Add extensions to the end of every wordlist entry. By
                        default dirsearch only replaces the %EXT% keyword with
                        extensions

  Dictionary Settings:
    -w WORDLIST, --wordlists=WORDLIST
                        Customize wordlists (separated by commas)
    --prefixes=PREFIXES
                        Add custom prefixes to all entries (separated by
                        commas)
    --suffixes=SUFFIXES
                        Add custom suffixes to all entries, ignore directories
                        (separated by commas)
    --only-selected     Only entries with selected extensions or no extension
                        + directories
    --remove-extensions
                        Remove extensions in all wordlist entries (Example:
                        admin.php -> admin)
    -U, --uppercase     Uppercase wordlist
    -L, --lowercase     Lowercase wordlist
    -C, --capital       Capital wordlist

  General Settings:
    -r, --recursive     Bruteforce recursively
    -R DEPTH, --recursion-depth=DEPTH
                        Maximum recursion depth
    -t THREADS, --threads=THREADS
                        Number of threads
    --subdirs=SUBDIRS   Scan sub-directories of the given URL[s] (separated by
                        commas)
    --exclude-subdirs=SUBDIRS
                        Exclude the following subdirectories during recursive
                        scan (separated by commas)
    -i STATUS, --include-status=STATUS
                        Include status codes, separated by commas, support
                        ranges (Example: 200,300-399)
    -x STATUS, --exclude-status=STATUS
                        Exclude status codes, separated by commas, support
                        ranges (Example: 301,500-599)
    --exclude-sizes=SIZES
                        Exclude responses by sizes, separated by commas
                        (Example: 123B,4KB)
    --exclude-texts=TEXTS
                        Exclude responses by texts, separated by commas
                        (Example: 'Not found', 'Error')
    --exclude-regexps=REGEXPS
                        Exclude responses by regexps, separated by commas
                        (Example: 'Not foun[a-z]{1}', '^Error$')
    --exclude-redirects=REGEXPS
                        Exclude responses by redirect regexps or texts,
                        separated by commas (Example: 'https://okta.com/*')
    --calibration=PATH  Path to test for calibration
    --random-agent      Choose a random User-Agent for each request
    --minimal=LENGTH    Minimal response length
    --maximal=LENGTH    Maximal response length
    -q, --quiet-mode    Quiet mode
    --full-url          Print full URLs in the output
    --no-color          No colored output

  Request Settings:
    -m METHOD, --http-method=METHOD
                        HTTP method (default: GET)
    -d DATA, --data=DATA
                        HTTP request data
    -H HEADERS, --header=HEADERS
                        HTTP request header, support multiple flags (Example:
                        -H 'Referer: example.com' -H 'Accept: */*')
    --header-list=FILE  File contains HTTP request headers
    -F, --follow-redirects
                        Follow HTTP redirects
    --user-agent=USERAGENT
    --cookie=COOKIE

  Connection Settings:
    --timeout=TIMEOUT   Connection timeout
    --ip=IP             Server IP address
    -s DELAY, --delay=DELAY
                        Delay between requests
    --proxy=PROXY       Proxy URL, support HTTP and SOCKS proxies (Example:
                        localhost:8080, socks5://localhost:8088)
    --proxy-list=FILE   File contains proxy servers
    --matches-proxy=PROXY
                        Proxy to replay with found paths
    --scheme=SCHEME     Default scheme (for raw request or if there is no
                        scheme in the URL)
    --max-retries=RETRIES
    -b, --request-by-hostname
                        By default dirsearch requests by IP for speed. This
                        will force requests by hostname
    --exit-on-error     Exit whenever an error occurs
    --debug             Debug mode

  Reports:
    --simple-report=OUTPUTFILE
    --plain-text-report=OUTPUTFILE
    --json-report=OUTPUTFILE
    --xml-report=OUTPUTFILE
    --markdown-report=OUTPUTFILE
    --csv-report=OUTPUTFILE
```

 **NOTE**: 
 You can change the dirsearch default configurations (default extensions, timeout, wordlist location, ...) by editing the **default.conf** file.


How to use
---------------

[![Dirsearch demo](https://asciinema.org/a/380112.svg)](https://asciinema.org/a/380112)

Some examples for how to use dirsearch - those are the most common arguments. If you need all, just use the **-h** argument.

### Simple usage
```
python3 dirsearch.py -u https://target
```

```
python3 dirsearch.py -e php,html,js -u https://target
```

```
python3 dirsearch.py -e php,html,js -u https://target -w /path/to/wordlist
```

### Recursive scan
By using the **-r | --recursive** argument, dirsearch will automatically brute-force the after of directories that it found.

```
python3 dirsearch.py -e php,html,js -u https://target -r
```
You can set the max recursion depth with **-R** or **--recursion-depth**

```
python3 dirsearch.py -e php,html,js -u https://target -r -R 3
```

### Threads
The threads number (-t | --threads) reflects the number of separate brute force processes, that each process will perform path brute-forcing against the target. And so the bigger the threads number is, the more fast dirsearch runs. By default, the number of threads is 20, but you can increase it if you want to speed up the progress.

In spite of that, the speed is actually still uncontrollable since it depends a lot on the response time of the server. And as a warning, we advise you to keep the threads number not too big because of the impact from too much automation requests, this should be adjusted to fit the power of the system that you're scanning against.

```
python3 dirsearch.py -e php,htm,js,bak,zip,tgz,txt -u https://target -t 30
```

### Prefixes / Suffixes
- **--prefixes**: Adding custom prefixes to all entries

```
python3 dirsearch.py -e php -u https://target --prefixes .,admin,_,~
```
Base wordlist:

```
tools
```
Generated with prefixes:

```
.tools
admintools
_tools
~tools
```

- **--suffixes**: Adding custom suffixes to all entries

```
python3 dirsearch.py -e php -u https://target --suffixes ~,/
```
Base wordlist:

```
index.php
internal
```
Generated with suffixes:

```
index.php~
index.php/
internal~
internal/
```

### Exclude extensions
Use **-X | --exclude-extensions** with your exclude-extension list to remove all entries in the wordlist that have the given extensions

```
python3 dirsearch.py -e asp,aspx,htm,js -u https://target -X php,jsp,jspx
```

Base wordlist:

```
admin
admin.%EXT%
index.html
home.php
test.jsp
```

After:

```
admin
admin.asp
admin.aspx
admin.htm
admin.js
index.html
```

### Wordlist formats
Supported wordlist formats: uppercase, lowercase, capitalization

#### Lowercase:

```
admin
index.html
test
```

#### Uppercase:

```
ADMIN
INDEX.HTML
TEST
```

#### Capital:

```
Admin
Index.html
Test
```

### Filters
Use **-i | --include-status** and **-x | --exclude-status** to select allowed and not allowed response status codes

```
python3 dirsearch.py -e php,html,js -u https://target -i 200,204,400,403 -x 500,502,429
```

**--exclude-sizes**, **--exclude-texts**, **--exclude-regexps** and **--exclude-redirects** are also supported for a more advanced filter

```
python3 dirsearch.py -e php,html,js -u https://target --exclude-sizes 1B,243KB
```

```
python3 dirsearch.py -e php,html,js -u https://target --exclude-texts "403 Forbidden"
```

```
python3 dirsearch.py -e php,html,js -u https://target --exclude-regexps "^Error$"
```

### Raw requests
dirsearch allows you to import the raw request from a file. The raw file content will be looked something like this:

```
GET /admin HTTP/1.1
Host: admin.example.com
Cache-Control: max-age=0
Accept: */*
```

Since there is no way for dirsearch to know what the URI scheme is (`http` or `https`), you need to set it using the `--scheme` flag. By default, the scheme is `http`, which is not popular in modern web servers now. That means, without setting up the scheme, you may brute-force with the wrong protocol, and will end up with false negatives.

### Scan sub-directories
From an URL, you can scan sub-dirsearctories with **--subdirs**.

```
python3 dirsearch.py -e php,html,js -u https://target --subdirs admin/,folder/,/
```

A reverse version of this feature is **--exclude-subdirs**, which to prevent dirsearch from brute-forcing directories that should not be brute-forced when doing a recursive scan.

```
python3 dirsearch.py -e php,html,js -u https://target --recursive -R 2 --exclude-subdirs "server-status/,%3f/"
```

### Proxies
Dirsearch supports SOCKS and HTTP proxy, with two options: a proxy server or a list of proxy servers.

```
python3 dirsearch.py -e php,html,js -u https://target --proxy 127.0.0.1:8080
```

```
python3 dirsearch.py -e php,html,js -u https://target --proxy socks5://10.10.0.1:8080
```

```
python3 dirsearch.py -e php,html,js -u https://target --proxylist proxyservers.txt
```

### Reports
Dirsearch allows the user to save the output into a file. It supports several output formats like text or json, and we are keep updating for new formats

```
python3 dirsearch.py -e php -l URLs.txt --plain-text-report report.txt
```

```
python3 dirsearch.py -e php -u https://target --json-report target.json
```

```
python3 dirsearch.py -e php -u https://target --simple-report target.txt
```

### Some others commands
```
python3 dirsearch.py -e php,txt,zip -u https://target -w db/dicc.txt -H "X-Forwarded-Host: 127.0.0.1" -f
```

```
python3 dirsearch.py -e php,txt,zip -u https://target -w db/dicc.txt -t 100 -m POST --data "username=admin"
```

```
python3 dirsearch.py -e php,txt,zip -u https://target -w db/dicc.txt --random-agent --cookie "isAdmin=1"
```

```
python3 dirsearch.py -e php,txt,zip -u https://target -w db/dicc.txt --json-report=target.json
```

```
python3 dirsearch.py -e php,txt,zip -u https://target -w db/dicc.txt --minimal 1
```

```
python3 dirsearch.py -e php,txt,zip -u https://target -w db/dicc.txt --header-list rate-limit-bypasses.txt
```

```
python3 dirsearch.py -e php,txt,zip -u https://target -w db/dicc.txt -q --stop-on-error
```

```
python3 dirsearch.py -e php,txt,zip -u https://target -w db/dicc.txt --full-url
```

```
python3 dirsearch.py -u https://target -w db/dicc.txt --no-extension
```

**There are more features and you will need to discover it by your self**


Tips
---------------
- To run dirsearch with a rate of requests per second, try `-t <rate> -s 1`
- Want to findout config files or backups? Try out `--suffixes ~` and `--prefixes .`
- For some endpoints that you do not want to force extensions, add `%NOFORCE%` at the end of them
- Want to find only folders/directories? Combine `--no-extension` and `--suffixes /`!
- The combination of `--cidr`, `-F` and `-q` will reduce most of the noise + false negatives when brute-forcing with a CIDR


Support Docker
---------------
### Install Docker Linux
Install Docker

```sh
curl -fsSL https://get.docker.com | bash
```

> To use docker you need superuser power

### Build Image dirsearch
To create image

```sh
docker build -t "dirsearch:v0.4.1" .
```

> **dirsearch** is the name of the image and **v0.4.1** is the version

### Using dirsearch
For using
```sh
docker run -it --rm "dirsearch:v0.4.1" -u target -e php,html,js,zip
```


License
---------------
Copyright (C) Mauro Soria (maurosoria@gmail.com)

License: GNU General Public License, version 2


Contributors
---------------
This tool is currently under development by @maurosoria and @shelld3v. We received a lot of help from many people around the world to improve this tool. Thanks so much to everyone who helped us!!

See [CONTRIBUTORS.md](https://github.com/maurosoria/dirsearch/blob/master/CONTRIBUTORS.md) for more information about who they are!

#### Want to join the team? Feel free to submit any pull request that you can. If you don't know how to code, you can support us by updating the wordlist or the documentation. Giving feedback or [a new feature suggestion](https://github.com/maurosoria/dirsearch/issues/new?labels=enhancement&template=feature_request.md) is also a good way to help us improve this tool
