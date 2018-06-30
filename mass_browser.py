#!/usr/bin/python3
"""
Usage:
  webbrowser.py    -h | --help
  webbrowser.py    (--proto=<proto> --subnet=<subnet> --rport=<rport> --browser=<browser> --iface=<iface>)

Options:
  --subnet=<subnet>     subnet
  --rport=<rport>       optional destination port
  --proto=<proto>       http or https
  --browser=<browser>   firefox, chrome, etc
  --iface=<iface>       outbound interface for masscan
"""

import os
import webbrowser
import concurrent.futures
from ipaddress import IPv4Network
from socket import socket, AF_INET, SOCK_STREAM
from docopt import docopt
from netifaces import ifaddresses, AF_INET

def create_ip_list(subnet):
    """
    Create a list of ip addresses from a give subnet.

    Arguments:
        subnet:         a subnet in cidr form ex: 196.168.0.0/24 
    """
    print("generating an ip list from subnet: {}".format(subnet))
    ip_list = []
    for ip in IPv4Network(subnet):
        ip_list.append(ip)
    print("ip list: {}".format(ip_list))
    return ip_list

def scan_port(ip, rport, iface):
    """
    Scan a single host for an open port.

    Arguments:
        ip:         an ip to scan
        rport:      remote port
        iface       source interface for outbound traffic  
    """
    print("scanning: {}".format(ip))
    iface_ip = ifaddresses(iface)[AF_INET][0]['addr']
    my_soc = socket(AF_INET, SOCK_STREAM)
    my_soc.bind((iface_ip, 0))
    my_soc.settimeout(3)
    result = my_soc.connect_ex((ip, int(rport)))
    if result == 0:
        return ip
    else:
        pass

def scan_port_concurrent(ip_list, rport, iface):
    """
    Scan for open port concurrently.
    
    Arguments:
        ip_list:    list of ipv4 targets
        rport:      remote port
        iface       source interface for outbound traffic        
    """
    print("entering concurrent port scan")
    results_list = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=50) as pool:
        results = {pool.submit(scan_port, str(ip), rport, iface): ip for ip in ip_list}
        for future in concurrent.futures.as_completed(results):
            if future.result():
                results_list.append(future.result())
    print(results_list)
    return results_list

def open_your_tabs(rhosts_open, browser="firefox", proto="http", rport=80):
    """
    Open a web browser tab for all open ports.

    Arguments:
        rhosts_open:    list of hosts with the desired port open
        browser:        browser to open tabs for
        proto:          http or https
        rport:          remote port to check
    """
    print("time to open browser tabs")
    print("just because the port is open, doesn't mean there is a web server")
    print("checking http/s requests could lead to false positives")
    print("closing browser windws is easier than opening them")
    print("happy web surfing")
    for ip in rhosts_open:
        print("opening tab for: {}".format(ip))
        if (rport != "80" and rport != "443" ):
            webbrowser.get(browser).open_new_tab('{}://{}:{}'.format(proto, ip, rport))
        else:
            webbrowser.get(browser).open_new_tab('{}://{}'.format(proto, ip))


def main():
    opts = docopt(__doc__)
    ip_list = create_ip_list(subnet=opts['--subnet'])
    rhosts_open = scan_port_concurrent(
        ip_list=ip_list,
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
