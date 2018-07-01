# mass_browser
This tool will help you quickly scan for and open browser tabs to all servers listening on a desired port, in a desired subnet, for a desired protocol.

I wrote this for the OSCP because I am lazy, but still feel it is important to hit the default web page for all web servers.

# Example
sudo python3 massbrowser.py  --proto http --subnet 196.168.0.0/24 --rport 80 --browser firefox --iface eth0
