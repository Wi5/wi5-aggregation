# wi5-aggregation
This repository contains different software tools for implementing and testing 802.11 frame aggregation (A-MPDU and perhaps A-MSDU). For further information about frame aggregation, see [this Wikipedia article](https://en.wikipedia.org/wiki/Frame_aggregation) and its [References](https://en.wikipedia.org/wiki/Frame_aggregation#References) and [External links](https://en.wikipedia.org/wiki/Frame_aggregation#External_links).

We have started our work with Evan Jones' work "Fake Access Points using Atheros wireless cards in Linux," taken from the following website:
http://www.evanjones.ca/software/fakeaps.c

And we extended it to implement the 802.11 authentication and association process.

Our final purpose is to implement frame aggregation (A-MPDU) between a "fake AP" and a normal terminal running 802.11n or 802.11ac.

Note: TO USE THIS SOFTWARE YOU NEED A NETWORK DRIVER THAT SUPPORTS [RADIOTAP](http://www.radiotap.org/), OTHERWISE IT MAY CONSIDER THE HEADERS AS PRISM, SO IT WON'T WORK AS EXPECTED.

These changes are being made by Cristian Hernandez in [University of Zaragoza](http://www.unizar.es), as a part of the H2020 [Wi-5 project](http://www.wi5.eu).

What does this software do?
---------------------------

The main purpose of this software is to send a number of Wi-Fi A-MPDUs, with the aim of measuring the savings they provide.

It creates a "fake AP" called `ap0` and starts sending beacons.

When the association of the STA to this "fake AP" is completed, the software runs all the mechanisms required for sending a number of A-MPDUs to it, and ends.

Therefore, it runs all this process:

```
fakeaps.c            STA that connects
|                      |
|------- Beacon ------>|            The announced SSID is "ap0"
|------- Beacon ------>|
|------- Beacon ------>|
|                      |
|<--- Probe request ---| 
|                      |----------- The association process starts now
|--- Probe response -->|
|<------- ACK ---------|
|                      |
|<--- Auth request ----|
|-------- ACK -------->|
|                      |
|--- Auth response --->|
|<------- ACK ---------|
|                      |
|<--- Assoc request ---|
|-------- ACK -------->|
|                      |
|-- Assoc response --->|
|<------- ACK ---------|
|                      | ------------- The association is completed
|                      |
|                      | ------------- Now the process of sending A-MPDUs can start
|                      |
|--- ADDBA Request --->|               AddBaRequest is an Action frame 
|                      |
|<------- ACK ---------|
|                      |
|<-- ADDBA Response ---|            
|                      |
|-------- ACK -------->|  
|                      |
|-------- A-MPDU ----->|            First A-MPDU
|-------- A-MPDU ----->|
|         ...          |
|-------- A-MPDU ----->|            Last A-MPDU
|                      |
|------ BA Request --->|            Block ACK request
|                      |
|<------- BA  ---------|            Block ACK
```

How to use the software (with an example)
-----------------------------------------

PC running fakeaps (AP):      `wlan0` IP address `192.168.7.1`; MAC address: `60:e3:27:1d:32:b7`.

PC acting as the STA:         `wlan2` IP address `192.168.7.2`; MAC address: `f4:f2:6d:0c:9d:aa`.


Download the files:

      $ git clone https://github.com/Wi5/wi5-aggregation.git

Compile the software:

      $ gcc --std=gnu99 -Wall -o fakeaps fakeaps.c

Prepare the PC acting as the AP:

	iwconfig wlan0 mode monitor
	ifconfig wlan0 up
	ifconfig wlan0 192.168.7.1
	iwconfig wlan0 channel 5

Run the software:

      ./fakeaps wlan0 5 2 10 192.168.7.2 f4:f2:6d:0c:9d:aa

This is the meaning of the parameters:

  - `wlan0`: name of the interface where you are creating the "fake AP". It has to be in monitor mode.
  - `5`: number of the Wi-Fi channel where you are creating the "fake AP".
  - `2`: number of packets that are going to travel in an A-MPDU.
  - `10`: number of A-MPDUs that will be sent.
  - `192.168.7.2`: IP address of the STA that is going to connect. It will be the destination of the A-MPDUs to be sent.
  - `f4:f2:6d:0c:9d:aa`: MAC address of the STA that is going to connect. The MAC is used as a filter. Only this MAC is allowed to connect to the "fake AP".

Prepare the PC acting as the STA:

	iwconfig wlan2 mode managed
	ifconfig wlan2 up
	ifconfig wlan2 192.168.7.2
	iwconfig wlan2 channel 5
      
Connect the STA to the AP:

      iwconfig wlan2 essid ap0
      
After the association of the STA, the software runs all the mechanisms required for sending 10 A-MPDUs (each of them containing 2 packets) to it, and ends.

How to capture the traffic
--------------------------

Prepare another interface (in another computer) in monitor mode:

	iw phy phy0 interface add mon0 type monitor
	ifconfig mon0 up
	iwconfig mon0 channel 5
      
And capture the traffic:

      tcpdump -e -i mon0 -w /home/proyecto/Aggregation/fakeapscap.pcap

You can see it in Wireshark using this filter:

      wlan.sa == f4:f2:6d:0c:9d:aa || wlan.da == f4:f2:6d:0c:9d:aa || wlan.ra == f4:f2:6d:0c:9d:aa || wlan.ta == f4:f2:6d:0c:9d:aa || wlan.da == 60:e3:27:1d:32:b7 || wlan.sa == 60:e3:27:1d:32:b7 || wlan.ra == 60:e3:27:1d:32:b7 || wlan.ta == 60:e3:27:1d:32:b7 
