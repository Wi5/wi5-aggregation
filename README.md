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

The main purpose of this software is to implement and measure the use of Wi-Fi A-MPDUs. Therefore, it runs all this process:

``
            |                      |
            |--- ADDBA Request --->|
            |                      |
            |<------- ACK ---------|
            |                      |
            |<-- ADDBA Response ---|            
            |                      |
            |-------- ACK -------->|  
            |                      |
            |-------- A-MPDU ----->|
            |-------- A-MPDU ----->|
            |         ...          |
            |-------- A-MPDU ----->|
            |                      |
            |------ BA Request --->|
            |                      |
            |<------- BA  ---------|            
``


It creates a "fake AP" called `ap0` and starts sending beacons.

When a STA is associated to this "fake AP," the software runs all the 

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
