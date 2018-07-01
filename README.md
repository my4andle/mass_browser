# mass_browser
This tool will help you quickly scan for and open browser tabs to all servers listening on a desired port, in a desired subnet, for a desired protocol.

# Example
sudo python3 massbrowser.py  --proto http --subnet 196.168.0.0/24 --rport 80 --browser firefox --iface eth0
