# IT567Scanner
A simple port scanner for simple people

The port scanner can be used from the command line or from a GUI.
In order to launch the GUI simply supply the -g option.
The GUI has an input for IP addresses that are comma separated with dashes for a range without whitespace.
e.g. 127.0.0.0,127.0.0.1-24,127.0.0.80
It also has an option to choose a file with IP addresses formatted the same way.
It has an input for ports which are formatted in a similar fashion.
e.g 80-1000,8080,9000
It has checkboxes that allow the user to include a UDP, TCP, and ICMP scan.
The results will be outputted as a report.html file in the same directory as scanner, which the program will attempt to open automatically.

The command line inputs are similar to the GUI's.
*All IP addresses and ports must be separated with commas and without whitespace. See examples above.*
Use the -f option to specify a file with IP addresses.
Use the -d option to specify target-ip addresses.
Use the -p option to specify ports.
Use the -g option to launch the GUI.
Use the -t option to run a TCP scan.
Use the -u option to run a UDP scan.
Use the -i option to run a ICMP scan.
