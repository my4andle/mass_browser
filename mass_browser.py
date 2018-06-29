#!/usr/bin/python3
"""
Usage:
  webbrowser.py    -h | --help
  webbrowser.py    (--proto=<proto> --subnet=<subnet> --rport=<rpot> --browser=<browser> --iface=<iface>)

Options:
  --subnet=<subnet>     subnet
  --rport=<rport>       optional destination port
  --proto=<proto>       http or https
  --browser=<browser>   firefox, chrome, etc
  --iface=<iface>       outbound interface for masscan
"""

# TODO: clean up docstrings
# run through test cases

import os
import webbrowser
import masscan
from docopt import docopt
from netifaces import ifaddresses, AF_INET


def masscan_subnet(subnet: str, iface, rport: str="80"):
    """
    Run masscan against a subnet to quickly return a list of IPs with open port 445.

    Args:
        subnet: A subnet to scan

    Returns:
        A list of IPv4 addresses that report TCP port open by masscan

    Note:
        Masscan command: masscan -oX - <subnet> -p <port> --adapter-ip <source interface ip>
    """
    print("Running masscan")
    rhosts_open = []
    iface_ip = ifaddresses(iface)[AF_INET][0]['addr']
    try:
        my_scanner = masscan.PortScanner()
    except masscan.PortScannerError as ex:
        print("MASSCAN not installed to OS path: {}".format(str(ex)))
        os._exit(1)

    print("Begin masscan against subnet: {}".format(subnet))
    try:
        my_scanner.scan(subnet, ports=rport, arguments="--adapter-ip {}".format(iface_ip))
        scan_results = my_scanner.scan_result['scan']
    except masscan.PortScannerError as ex:
        print("The masscan requires root privleges, run with sudo")
        os._exit(1)
    except KeyError as ex:
        print("Masscan results do not contain scan data: {}".format(str(ex)))
        os._exit(1)

    for host in my_scanner.all_hosts:
        try:
            if scan_results[host]['tcp'][rport]['state'] == 'open':
                rhosts_open.append(host)
        except KeyError as ex:
            print("Port {} closed on: {}".format(rport, host))
            pass

    print("Hosts with open port {}: {}".format(rport, rhosts_open))
    return rhosts_open

def open_your_tabs(rhosts_open, browser="firefox", proto="http", rport=80):
    for ip in rhosts_open:
        if rport:
            webbrowser.get(browser).open_new_tab('{}://{}:{}'.format(proto, ip, rport))
        else:
            webbrowser.get(browser).open_new_tab('{}://{}'.format(proto, ip))

def main():
    opts = docopt(__doc__)
    rhosts_open = masscan_subnet(
        subnet=opts['--subnet'],
        rport=opts['--rport'],
        iface=opts['--iface']
    )
    open_your_tabs(
        rhosts_open=rhosts_open,
        browser=opts['--browser'],
        proto=opts['--proto'],
        rport=opts['--rport']
    )

if __name__ == '__main__':
    main()
