# wi5-aggregation
This repository contains different software tools for implementing and testing 802.11 frame aggregation (A-MPDU and perhaps A-MSDU). For further information about frame aggregation, see [this Wikipedia article](https://en.wikipedia.org/wiki/Frame_aggregation) and its [References](https://en.wikipedia.org/wiki/Frame_aggregation#References) and [External links](https://en.wikipedia.org/wiki/Frame_aggregation#External_links).

We have started our work with Evan Jones' work "Fake Access Points using Atheros wireless cards in Linux," taken from the following website:
http://www.evanjones.ca/software/fakeaps.c

And we extended it to implement the 802.11 authentication and association process.

Our final purpose is to implement frame aggregation (A-MPDU) between a "fake AP" and a normal terminal running 802.11n or 802.11ac.

Note: TO USE THIS SOFTWARE YOU NEED A NETWORK DRIVER THAT SUPPORTS [RADIOTAP](http://www.radiotap.org/), OTHERWISE IT MAY CONSIDER THE HEADERS AS PRISM, SO IT WON'T WORK AS EXPECTED

These changes are being made by Cristian Hernandez in [University of Zaragoza](http://www.unizar.es), as a part of the H2020 [Wi-5 project](http://www.wi5.eu).
