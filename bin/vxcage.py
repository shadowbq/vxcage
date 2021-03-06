#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import getpass
import argparse
import readline
import json


import rlcompleter
import atexit
import glob

# tab completion
def complete(text, state):
    return (glob.glob(text+'*')+[None])[state]
readline.set_completer_delims(' \t\n;')
readline.parse_and_bind("tab: complete")
readline.set_completer(complete)

# history file
histfile = os.path.join(os.environ['HOME'], '.vxcage_history')
try:
    readline.read_history_file(histfile)
except IOError:
    pass
atexit.register(readline.write_history_file, histfile)
del histfile, readline, rlcompleter




try:
    import requests
    from progressbar import *
    from prettytable import PrettyTable
except ImportError as e:
    sys.exit("ERROR: Missing dependency: %s" % e)



def color(text, color_code):
    return '\x1b[%dm%s\x1b[0m' % (color_code, text)

def cyan(text):
    return color(text, 36)

def bold(text):
    return color(text, 1)

def logo():
    print("")
    print(cyan("  `o   O o   O .oOo  .oOoO' .oOoO .oOo. "))
    print(cyan("   O   o  OoO  O     O   o  o   O OooO' "))
    print(cyan("   o  O   o o  o     o   O  O   o O     "))
    print(cyan("   `o'   O   O `OoO' `OoO'o `OoOo `OoO' "))
    print(cyan("                                O       "))
    print(cyan("                             OoO' ") + " by nex")
    print("")

def help():
    print("Available commands:")
    print("  " + bold("tags") + "         Retrieve list of tags")
    print("  " + bold("find") + "         Query a file by md5, sha256, ssdeep, imphash, tag or date")
    print("  " + bold("get") + "          Download a file by sha256")
    print("  " + bold("dump") + "         Dump a list of md5, sha256, ssdeep hashes")
    print("  " + bold("add") + "          Upload a file to the server")
    print("  " + bold("last") + "         Retrieve a list of the last x files uploaded")
    print("  " + bold("total") + "        Total number of samples")
    print("  " + bold("stats") + "        File type stats")
    print("  " )
    print("  " + bold("version") + "      Version of remote vxcage server")
    print("  " + bold("license") + "      Print the software license")
    print("  " )
    print("  " + bold("help | ?") + "         Show this help")
    print("  " + bold("exit | quit") + "  Exit cli application")


class VxCage(object):
    def __init__(self, host, port, xmock, ssl=False, auth=False):
        self.host = host
        self.port = port
        self.ssl = ssl
        self.auth = auth
        self.xmock = xmock
        self.username = None
        self.password = None

    def authenticate(self):
        if self.auth:
            self.username = raw_input("Username: ")
            self.password = getpass.getpass("Password: ")

    def build_url(self, route):
        if self.ssl:
            url = "https://"
            if self.port is None:
                self.port = 443
        else:
            if self.port is None:
                self.port = 8080
            url = "http://"

        url += "%s:%s%s%s" % (self.host, self.port, self.xmock, route)

        return url

    def check_errors(self, code):
        if code == 400:
            print("ERROR: Invalid request format")
            return True
        elif code == 500:
            print("ERROR: Unexpected error, check your server logs")
            return True
        else:
            return False

    def tags_list(self):
        req = requests.get(self.build_url("/tags/list"),
                           auth=(self.username, self.password),
                           verify=False)
        try:
            res = req.json()
        except:
            try:
                res = req.json
            except Exception as e:
                print("ERROR: Unable to parse results: {0}".format(e))
                return

        if self.check_errors(req.status_code):
            return

        table = PrettyTable(["tag"])
        table.align = "l"
        table.padding_width = 1

        for tag in res:
            table.add_row([tag])

        print(table)
        print("Total: %s" % len(res))

    def dump_list(self, hType):
        req = requests.get(self.build_url("/malware/dump/"+hType),
                           auth=(self.username, self.password),
                           verify=False)
        try:
            res = req.json()
        except:
            try:
                res = req.json
            except Exception as e:
                print("ERROR: Unable to parse results: {0}".format(e))
                return

        if self.check_errors(req.status_code):
            return

        table = PrettyTable([hType])
        table.align = "l"
        table.padding_width = 1

        for hType in res:
            table.add_row(hType)

        print(table)
        print("Total: %s" % len(res))

    def malware_total(self):
        req = requests.get(self.build_url("/malware/total"),
                           auth=(self.username, self.password),
                           verify=False)
        try:
            res = req.json()
        except:
            try:
                res = req.json
            except Exception as e:
                print("ERROR: Unable to parse results: {0}".format(e))
                return

        if self.check_errors(req.status_code):
            return

        print("Total: %s" % res)

    def malware_stats_total(self):
        req = requests.get(self.build_url("/malware/total/stats"),
                           auth=(self.username, self.password),
                           verify=False)
        try:
            res = req.json()
        except:
            try:
                res = req.json
            except Exception as e:
                print("ERROR: Unable to parse results: {0}".format(e))
                return

        if self.check_errors(req.status_code):
            return

        self._print_list(res, ["File_type", "Count"])

    def server_version(self):
        req = requests.get(self.build_url("/about"),
                           auth=(self.username, self.password),
                           verify=False)
        try:
            res = req.json()
        except:
            try:
                res = req.json
            except Exception as e:
                print("ERROR: Unable to parse results: {0}".format(e))
                return

        if self.check_errors(req.status_code):
            return

        self._print_kv(res)

    def license(self):
        req = requests.get(self.build_url("/about/license"),
                           auth=(self.username, self.password),
                           verify=False)

        if self.check_errors(req.status_code):
            return
        print req.text

    def find_malware(self, term, value):
        term = term.lower()
        terms = ["md5", "sha256", "ssdeep", "imphash", "tag", "date"]

        if not term in terms:
            print("ERROR: Invalid search term [%s]" % (", ".join(terms)))
            return

        payload = {term : value}
        req = requests.post(self.build_url("/malware/find"),
                            data=payload,
                            auth=(self.username, self.password),
                            verify=False)
        try:
            res = req.json()
        except:
            try:
                res = req.json
            except Exception as e:
                print("ERROR: Unable to parse results: {0}".format(e))
                return

        if req.status_code == 404:
            print("No file found matching your search")
            return
        if self.check_errors(req.status_code):
            return
        self._print_malware_info(res)

    def last_x(self, x):
        req = requests.get(self.build_url("/malware/last/"+x),
                           auth=(self.username, self.password),
                           verify=False)
        try:
            res = req.json()
        except:
            try:
                res = req.json
            except Exception as e:
                print("ERROR: Unable to parse results: {0}".format(e))
                return

        if req.status_code == 404:
            print("No data found matching your search")
            return
        if self.check_errors(req.status_code):
            return
        self._print_malware_info(res)

    def get_malware(self, sha256, path):
        if not os.path.exists(path):
            print("ERROR: Folder does not exist at path %s" % path)
            return

        if not os.path.isdir(path):
            print("ERROR: The path specified is not a directory.")
            return

        req = requests.get(self.build_url("/malware/get/%s" % sha256),
                           auth=(self.username, self.password),
                           verify=False)

        if req.status_code == 404:
            print("File not found")
            return
        if self.check_errors(req.status_code):
            return

        size = int(req.headers["Content-Length"].strip())
        bytes = 0

        widgets = [
            "Download: ",
            Percentage(),
            " ",
            Bar(marker=":"),
            " ",
            ETA(),
            " ",
            FileTransferSpeed()
        ]
        progress = ProgressBar(widgets=widgets, maxval=size).start()

        destination = os.path.join(path, sha256)
        binary = open(destination, "wb")

        for buf in req.iter_content(1024):
            if buf:
                binary.write(buf)
                bytes += len(buf)
                progress.update(bytes)

        progress.finish()
        binary.close()

        print("File downloaded at path: %s" % destination)

    def add_malware(self, path, tags=None):
        if not os.path.exists(path):
            print("ERROR: File does not exist at path %s" % path)
            return

        files = {"file": (os.path.basename(path), open(path, "rb"))}
        payload = {"tags" : tags}

        req = requests.post(self.build_url("/malware/add"),
                            auth=(self.username, self.password),
                            verify=False,
                            files=files,
                            data=payload)

        if not self.check_errors(req.status_code):
            print("File uploaded successfully")

    def _is_number(self, s):
        try:
            float(s)
            return True
        except ValueError:
            return False

    def _print_kv(self, res):
        table = PrettyTable(["Key","Value"])
        table.align = "l"
        table.padding_width = 1

        for k,v in res.items():
                table.add_row([k, v])

        print(table)

    def _print_list(self, res, title = ["Key", "Value"]):
        table = PrettyTable(title)
        table.align = "l"
        table.padding_width = 1

        for v in res:
                table.add_row([v[0],v[1]])

        print(table)

    def _print_malware_info(self, res):
        if isinstance(res, dict):
            for key, value in res.items():
                if key == "tags":
                    print("%s: %s" % (bold(key), ",".join(value)))
                elif key == "virustotal":
                    vt = res["virustotal"]
                    try:
                        print('\033[1m' + "virustotal" + '\033[0m' + ": " + str(vt["positives"]) + "/" + str(vt["total"]) + " matches")
                    except:
                        print('\033[1m' + "virustotal" + '\033[0m' + ": -/- matches")

                elif key == "exif":
                    exif = res["exif"]
                    #print('\033[1m' + "timestamp" + '\033[0m' + ": " + exif["EXE:TimeStamp"])
                    #print('\033[1m' + "character set" + '\033[0m' + ": " + exif["EXE:CharacterSet"])
                else:
                    print("%s: %s" % (bold(key), value))
        else:
            table = PrettyTable(["md5",
                                 "sha256",
                                 "file_name",
                                 "file_type",
                                 "file_size",
                                 "virustotal",
                                 "created_at",
                                 "tags"])
            table.align = "l"
            table.padding_width = 1

            for entry in res:
                table.add_row([entry["md5"],
                               entry["sha256"],
                               entry["file_name"],
                               entry["file_type"],
                               entry["file_size"],
                               entry["virustotal"]["virustotal"],
                               entry["created_at"],
                               ", ".join(entry["tags"])])

            print(table)
            print("Total: %d" % len(res))

    def run(self):
        self.authenticate()

        while True:
            try:
                raw = raw_input(cyan("vxcage> "))
            except KeyboardInterrupt:
                print("")
                continue
            except EOFError:
                print("")
                break

            command = raw.strip().split(" ")

            if (command[0] == "help" or command[0] == "?"):
                help()
            elif (command[0] == "version" or command[0] == "about"):
                self.server_version()
            elif (command[0] == "license"):
                self.license()
            elif command[0] == "total":
                self.malware_total()
            elif command[0] == "stats":
                self.malware_stats_total()
            elif command[0] == "tags":
                self.tags_list()
            elif command[0] == "last":
                if len(command) == 2 and self._is_number(command[1]):
                    self.last_x(command[1])
                else:
                    print("ERROR: Missing arguments (e.g. \"last <x>\")")
            elif command[0] == "dump":
                if len(command) == 2 and command[1] in ['md5', 'sha256', 'ssdeep']:
                    self.dump_list(command[1])
                else:
                    print("ERROR: Missing arguments (e.g. \"dump <type>\")")
                    print("     Available types: md5, sha256, ssdeep")
            elif command[0] == "find":
                if len(command) == 3 and command[1] in ['md5', 'sha256', 'ssdeep', 'imphash', 'tag', 'date']:
                    self.find_malware(command[1], command[2])
                else:
                    print("ERROR: Missing arguments (e.g. \"find <key> <value>\")")
                    print("     Available keys: md5, sha256, ssdeep, imphash, tag or date")
            elif command[0] == "get":
                if len(command) == 3:
                    self.get_malware(command[1], command[2])
                else:
                    print("ERROR: Missing arguments (e.g. \"get <sha256> <path>\")")
            elif command[0] == "add":
                if len(command) == 2:
                    self.add_malware(command[1])
                elif len(command) == 3:
                    self.add_malware(command[1], command[2])
                else:
                    print("ERROR: Missing arguments (e.g. \"add <path> <comma separated tags>\")")
            elif (command[0] == "quit" or command[0] == "exit"):
                break

if __name__ == "__main__":
    logo()

    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host of VxCage server", default="localhost", action="store", required=False)
    parser.add_argument("-p", "--port", help="Port of VxCage server", action="store", required=False)
    parser.add_argument("-s", "--ssl", help="Enable if the server is running over SSL", default=False, action="store_true", required=False)
    parser.add_argument("-a", "--auth", help="Enable if the server is prompting an HTTP authentication", default=False, action="store_true", required=False)
    parser.add_argument("-x", "--xmock", help="(api testing) URL of VxCage server mock service", default="", action="store", required=False)
    args = parser.parse_args()

    vx = VxCage(host=args.host, port=args.port, ssl=args.ssl, auth=args.auth, xmock=args.xmock)
    vx.run()
