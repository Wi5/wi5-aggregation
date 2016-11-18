# wi5-aggregation
This repository contains different software tools for implementing and testing 802.11 frame aggregation (A-MPDU and perhaps A-MSDU). For further information about frame aggregation, see [this Wikipedia article](https://en.wikipedia.org/wiki/Frame_aggregation) and its [References](https://en.wikipedia.org/wiki/Frame_aggregation#References) and [External links](https://en.wikipedia.org/wiki/Frame_aggregation#External_links).

We have started our work with Evan Jones' work "Fake Access Points using Atheros wireless cards in Linux," taken from the following website:
http://www.evanjones.ca/software/fakeaps.c

And we extended it to implement the 802.11 authentication and association process.

Our final purpose is to implement frame aggregation (A-MPDU) between a "fake AP" and a normal terminal running 802.11n or 802.11ac.

Note: TO USE THIS SOFTWARE YOU NEED A NETWORK DRIVER THAT SUPPORTS [RADIOTAP](http://www.radiotap.org/), OTHERWISE IT MAY CONSIDER THE HEADERS AS PRISM, SO IT WON'T WORK AS EXPECTED

These changes are being made by Cristian Hernandez in [University of Zaragoza](http://www.unizar.es), as a part of the H2020 [Wi-5 project](http://www.wi5.eu).

What does this software do?
---------------------------

The main purpose of this software is to send Wi-Fi A-MPDUs, with the aim of measuring the savings they provide.

Therefore, it runs all this process:

```
fakeaps.c            STA that connects
|                      |
|------- Beacon ------>|            The SSID is "ap0"
|------- Beacon ------>|
|------- Beacon ------>|
|                      |
|<--- Probe request ---| 
|                      |            The association process starts now
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
|--- ADDBA Request --->|            AddBaRequest is an Action frame 
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

It creates a "fake AP" called `ap0` and starts sending beacons.

When the association of the STA to this "fake AP" is completed, the software runs all the mechanisms required for sending a number of A-MPDUs to it, and ends.

How to use the software
-----------------------

Download the files:

      $ git clone https://github.com/Wi5/wi5-aggregation.git

Compile the software:

      $ gcc --std=gnu99 -Wall -o fakeaps fakeaps.c

Run the software:

      ./fakeaps wlan0 5 2 10 192.168.7.2 f4:f2:6d:0c:9d:aa

This is the meaning of the parameters:

  - `wlan0`: name of the interface where you are creating the "fake AP". It has to be in monitor mode.
  - `5`: number of the Wi-Fi channel where you are creating the "fake AP".
  - `2`: number of packets that are going to travel in an A-MPDU.
  - `10`: number of A-MPDUs that will be sent.
  - `192.168.7.2`: IP address of the STA that is going to connect. It will be the destination of the A-MPDUs to be sent.
  - `f4:f2:6d:0c:9d:aa`: MAC address of the STA that is going to connect. It is used as a filter. Only this MAC is allowed to connect to the "fake AP".
