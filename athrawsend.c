/*-
 * Copyright (c) 2005 Sebastian Weitzel <togg@togg.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 *
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include <netpacket/packet.h>

#include <stdio.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <math.h>

//Compilar usando gcc -lm 
//Para ejecutar se necesitan permisos de usuario

#include  "net80211/ieee80211.h"
#include  "net80211/ieee80211_radiotap.h"

#define P_BUF_SIZE 3000
#define RTAP_HLEN 8
#define MAC_LEN IEEE80211_ADDR_LEN
#define DATA_LEN 2000
#define SCAN_BUF_SIZE 100

static int sock;
static char packet_buffer[P_BUF_SIZE];

int open_socket(char *device){
	struct ifreq ifr;
	struct sockaddr_ll ll;
	int protocol = ETH_P_802_3;

	sock = socket(PF_PACKET, SOCK_RAW, htons(protocol));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl[SIOCGIFINDEX]");
		close(sock);
		return 0;
	}

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(protocol);
	if (bind(sock, (struct sockaddr *) &ll, sizeof(ll)) < 0) {
		perror("bind[PF_PACKET]");
		close(sock);
		return 0;
	}


	if(sock < 0){
		return 0;
	} else{
		return 1;
	}
}

void close_socket(){
	close(sock);
}

void packet_hexdump(char* data, size_t size){
	size_t i;

	printf("%02x", data[0]);
	for(i=1; i<size; i++){
		printf(":%02x", data[i]);
	}
	printf("\n\n");
}

void printhelp(){
	printf("athrawsend\n");
	printf("  send raw data to device\n");
	printf("usage: \n");
	printf("  -i  --interface <network interface name>\n");
	printf("  -r  bit rate (e.g. 5.5 for 5.5MBit)\n");
	printf("  -b  bitpattern in decimal (1byte)\n");
	printf("  -s  data size \n");
	printf("  -h  help\n");
}

int
main(int argc, char *argv[])
{
	struct ieee80211_radiotap_header *rtap_h;
	u_int8_t *rtap_d;
	struct ieee80211_htframe_addr4 *ieee80211_h;
	u_int8_t *data;
	int num_rtapdata;
	int i;
	int c;

	// parameter variables
	int rate;
	int txpow;
	u_int8_t mac_bssid[MAC_LEN] = { 0x41, 0x54, 0x48, 0x54, 0x53, 0x54 };
	u_int8_t mac_src[MAC_LEN];
	u_int8_t mac_dst[MAC_LEN];
	int data_size;
	char device[IFNAMSIZ];
	u_int8_t pattern;

	// setting default values
	strncpy(device, "wlan0", IFNAMSIZ);
	pattern = 0xff;
	txpow = 60;
	rate = 108; // 54 MBit/s
	data_size = DATA_LEN;

	// parsing command line parameters
	while(1){
        int option_index = 0;

        static struct option long_options[] = {
            {"interface", 1, 0, 'i'},
            {"rate", 1, 0, 'r'},
            {"txpower", 1, 0, 'p'},
            {"bitpattern", 1, 0, 'b'},
            {"size", 1, 0, 's'},
            {"help", 0, 0, 'h'},
            {0, 0, 0, 0}
        };
		
		c = getopt_long(argc, argv, "i:r:p:b:s:h", long_options, &option_index);
		if(c==-1){
			printhelp();
			break;
		}

		switch(c){
			case 0:
                printf ("option %s", long_options[option_index].name);
                if (optarg)
                    printf (" with arg %s", optarg);
                printf ("\n");
                break;

			case 'i':
				strncpy(device, optarg, IFNAMSIZ);
				break;
			case 'r': {
					int r1, r2;
					sscanf(optarg, "%i.%i", &r1, &r2);
					rate = 2 * r1 + (r2 / 5);
				}
				break;
			case 'p':  {
					int p_val;
					char p_unit[SCAN_BUF_SIZE];
					int ret;

					ret=sscanf(optarg, "%i%s", &p_val, &p_unit);
					printf("power: %i, unit: %s, ret: %i\n", p_val, p_unit, ret);

					switch(ret){
						default:
						case 0:	// no valid value
							printf("wrong power value\n");
							printhelp();
							exit(-EINVAL);
							break;
						case 1:	// valid value, no unit
							break;
						case 2:	// valid value with unit
							if((strcasecmp(p_unit, "dBm")==0)){
								double v;
								double w;

								w = p_val;

								v = exp(log(10) * (w / 10));
								txpow = (int) (v + 0.5) ;
								//printf("power in mW: %f (%i)\n", v, p_val);
							} else if((strcasecmp(p_unit, "mW")==0)){
								printf("assuming, power unit is mW\n");
								txpow = p_val;
							} else{
								printf("wrong power unit\n");
								printhelp();
								exit(-EINVAL);
							}
							break;
					}

				}
				break;
			case 'b': {
					u_int8_t bp;
					int ival;

					sscanf(optarg, "%i", &ival);
					bp = (u_int8_t) ival;

					pattern = bp;
				}
				break;
			case 's': {
					int s;

					sscanf(optarg, "%i", &s);
					data_size = s;
				}
				break;
			case 'h':
				printhelp();
				break;
			default:
				break;
		}
	}


	// constructing radiotap header
	num_rtapdata = 2;

	rtap_h = (struct ieee80211_radiotap_header*) &packet_buffer;

	rtap_h->it_version = 0;
	rtap_h->it_pad = 0;
	//rtap_h->it_len = 0; //TODO: length
	rtap_h->it_len = RTAP_HLEN + num_rtapdata;
	rtap_h->it_present = 
		(1 << IEEE80211_RADIOTAP_RATE) | 
		(1 << IEEE80211_RADIOTAP_DBM_TX_POWER); 

	rtap_d = ((u_int8_t*) rtap_h) + RTAP_HLEN;
	rtap_d[0] = rate;
	rtap_d[1] = txpow;

	// constructing 802.11 header
	//ieee80211_h = (struct ieee80211_htframe_addr4*) rtap_d + num_rtapdata;
	ieee80211_h = (struct ieee80211_htframe_addr4*) &(packet_buffer[RTAP_HLEN + num_rtapdata]);

	ieee80211_h->i_fc[0] = IEEE80211_FC0_SUBTYPE_DATA;
	ieee80211_h->i_fc[1] = 0; // TODO: ???
	
	ieee80211_h->i_dur[0] = 0;
	ieee80211_h->i_dur[1] = 0;

	memcpy(ieee80211_h->i_addr1, mac_bssid, MAC_LEN);
	memcpy(ieee80211_h->i_addr2, mac_src, MAC_LEN);
	memcpy(ieee80211_h->i_addr3, mac_dst, MAC_LEN);

	ieee80211_h->i_seq[0] = 0;
	ieee80211_h->i_seq[1] = 0;
	
	// generating packet data
	//data = ((u_int8_t*) ieee80211_h) + sizeof(ieee80211_h);
	data = &(packet_buffer[RTAP_HLEN + num_rtapdata + sizeof(struct ieee80211_htframe_addr4)]);

	for(i=0; i<data_size; i++){
		//data[i] = (u_int8_t) random();
		data[i] = pattern;
	}

	printf("opening socket...\n");
	if(open_socket(device)){
		int ret;
		
		// sendinf packet
	
		//printf("sending packet...\n");
		packet_hexdump(packet_buffer, data_size + sizeof(ieee80211_h) + RTAP_HLEN + num_rtapdata);
		while(1){
			ret = send(sock, packet_buffer, data_size + sizeof(ieee80211_h) + RTAP_HLEN + num_rtapdata, 0);
			//printf("sending packet, ret=%i\n", ret);

			if(ret < 0){
				printf("error: errno=%i\n", errno);
				break;
			}
		}

		close_socket();
	}

	
}
