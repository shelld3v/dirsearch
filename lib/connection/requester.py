# -*- coding: utf-8 -*-
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#  Author: Mauro Soria

import http.client
import random
import socket
import urllib.parse

import thirdparty.requests as requests
from .request_exception import *
from .response import *


class Requester(object):
    def __init__(
        self,
        url,
        cookie=None,
        useragent=None,
        maxPool=1,
        maxRetries=5,
        timeout=20,
        ip=None,
        proxy=None,
        proxylist=None,
        redirect=False,
        requestByHostname=False,
        httpmethod="get",
        data=None,
        scheme=None,
    ):
        self.httpmethod = httpmethod
        self.data = data
        self.headers = {}

        # If no backslash, append one
        if not url.endswith("/"):
            url += "/"

        parsed = urllib.parse.urlparse(url)

        # If no protocol specified, set http by default
        if "://" not in url:
            parsed = urllib.parse.urlparse("{0}://{1}".format(scheme, url))

        # If protocol is not supported
        elif parsed.scheme not in ["https", "http"]:
            raise RequestException({"message": "Unsupported URL scheme: {0}".format(parsed.scheme)})

        if parsed.path.startswith("/"):
            self.basePath = parsed.path[1:]
        else:
            self.basePath = parsed.path

        # Safe quote all special characters in basePath to prevent from being encoded when performing requests
        self.basePath = urllib.parse.quote(self.basePath, safe="!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
        self.protocol = parsed.scheme
        self.host = parsed.netloc.split(":")[0]

        # Resolve DNS to decrease overhead
        if ip:
            self.ip = ip
        else:
            try:
                self.ip = socket.gethostbyname(self.host)
            except socket.gaierror:
                raise RequestException({"message": "Couldn't resolve DNS"})

        # If no port specified, set default (80, 443)
        try:
            self.port = int(parsed.netloc.split(":")[1])
        except IndexError:
            self.port = 443 if self.protocol == "https" else 80
        except ValueError:
            raise RequestException(
                {"message": "Invalid port number: {0}".format(parsed.netloc.split(":")[1])}
            )

        # Set the Host header, this will be overwritten if the user has already set the header
        self.headers["Host"] = self.host

        # Include port in Host header if it's non-standard
        if (self.protocol == "https" and self.port != 443) or (
            self.protocol == "http" and self.port != 80
        ):
            self.headers["Host"] += ":{0}".format(self.port)

        # Set cookie and user-agent headers
        if cookie:
            self.setHeader("Cookie", cookie)

        if useragent:
            self.setHeader("User-agent", useragent)

        self.maxRetries = maxRetries
        self.maxPool = maxPool
        self.timeout = timeout
        self.pool = None
        self.proxy = proxy
        self.proxylist = proxylist
        self.redirect = redirect
        self.randomAgents = None
        self.requestByHostname = requestByHostname
        self.session = requests.Session()
        self.url = "{0}://{1}:{2}/".format(
            self.protocol,
            self.host if self.requestByHostname else self.ip,
            self.port,
        )

    def setHeader(self, key, value):
        self.headers[key.strip()] = value.strip()

    def setRandomAgents(self, agents):
        self.randomAgents = list(agents)

    def unsetRandomAgents(self):
        self.randomAgents = None

    def request(self, path, proxy=None):
        i = 0
        result = None

        while i <= self.maxRetries:

            try:
                if not proxy:
                    if self.proxylist:
                        proxy = random.choice(self.proxylist)
                    elif self.proxy:
                        proxy = self.proxy

                if proxy:
                    if not proxy.startswith(
                        ("http://", "https://", "socks5://", "socks5h://", "socks4://", "socks4a://")
                    ):
                        proxy = "http://" + proxy

                    if proxy.startswith("http:"):
                        proxies = {"http": proxy}
                    elif proxy.startswith("https:"):
                        proxies = {"https": proxy}
                    else:
                        proxies = {"https": proxy, "http": proxy}
                else:
                    proxies = None

                url = self.url + self.basePath + path

                if self.randomAgents:
                    self.headers["User-agent"] = random.choice(self.randomAgents)

                response = self.session.request(
                    self.httpmethod,
                    url,
                    data=self.data,
                    proxies=proxies,
                    allow_redirects=self.redirect,
                    headers=dict(self.headers),
                    timeout=self.timeout,
                    verify=False,
                )

                result = Response(
                    response.status_code,
                    response.reason,
                    response.headers,
                    response.content,
                )

                break

            except requests.exceptions.SSLError:
                self.url = "{0}://{1}:{2}/".format(self.protocol, self.host, self.port)
                continue

            except requests.exceptions.TooManyRedirects:
                raise RequestException(
                    {"message": "Too many redirects"}
                )

            except requests.exceptions.ProxyError as e:
                raise RequestException(
                    {"message": "Error with the proxy: {0}".format(e)}
                )

            except requests.exceptions.ConnectionError:
                raise RequestException(
                    {"message": "Cannot connect to: {0}:{1}".format(self.host, self.port)}
                )

            except requests.exceptions.InvalidURL:
                raise RequestException(
                    {"message": "Invalid URL: {0}".format(url)}
                )

            except requests.exceptions.InvalidProxyURL:
                raise RequestException(
                    {"message": "Invalid proxy URL: {0}".format(proxy)}
                )

            except (
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout,
                requests.exceptions.Timeout,
                http.client.IncompleteRead,
                socket.timeout,
            ):
                continue

            finally:
                i += 1

        if i > self.maxRetries:
            raise RequestException(
                {
                    "message": "There was a problem in the request to: {0}".format(
                        url
                    )
                }
            )

        return result
