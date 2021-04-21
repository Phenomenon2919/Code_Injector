# Code Injector

This application can be used to add script/code into the HTTP response when the victim requests a URL from the server.
The injection code is in html format (between \<script> tags). The code can be be modified in the *process_packets()* function in the file *code_injector.py*.

Note: This program only works if you already have launched an ARP Spoofing or some other kind MiTM attack on the Target machine. Make sure that port forwarding is enabled on your Host machine.

This code uses *scapy* package

##### Usage
> pip install -r Requirements.txt

> python3 src/code_injector.py