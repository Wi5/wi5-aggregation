/**
UNDER CONSTRUCTION

Code taken from the following website:

http://www.evanjones.ca/software/fakeaps.c

Thanks to Evan Jones for his work.

And used to implement the authentication, association. And finally our purpose is to implement frame aggregation (A-MPDU).
This changes will be made by Cristian Hernandez.

TO USE IT YOU NEED A NETWORK DRIVER THAT SUPPORT RADIOTAP, OTHERWISE IT WON'T WORK AS EXPECTED

Fake Access Points using Atheros wireless cards in Linux
Written by Evan Jones <ejones@uwaterloo.ca>
Released under a BSD Licence
How to Use:
1. Customize the array of access points below, if you want.
2. Bring up your Atheros interface on the desired channel.
3. Enable the raw device (echo "1" > /proc/sys/dev/ath0/rawdev)
4. Configure the raw device to use radiotap headers (echo "2" > /proc/sys/dev/ath0/rawdev_type)
5. Bring up the raw device (ifconfig ath0raw up)
6. Start this program (./fakeaps ath0raw [channel number for ath0])
How to Compile:
1. Get the "ieee80211.h" and "ieee80211_radiotap.h" headers from the MadWiFi
distribution:
http://cvs.sourceforge.net/viewcvs.py/madwifi/madwifi/net80211/
2. gcc --std=gnu99 -Wall -o fakeaps fakeaps.c
Thanks go out to John Bicket for his help in getting the raw device to work
correctly, and getting it included in the MadWiFi driver.
http://pdos.csail.mit.edu/~jbicket/
Thanks also to Sebastian Weitzel for his athrawsend program:
http://www.togg.de/stuff/athrawsend.c
Thanks also to Silver Moon for his implementation of sending an UDP frame
http://www.binarytides.com/raw-udp-sockets-c-linux/
*/

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

#include <unistd.h>

#include <netinet/in.h>
#include <netinet/udp.h>	//Provides declarations for udp header
#include <netinet/ip.h>		//Provides declarations for ip header
#include <arpa/inet.h>

#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <sys/time.h>
#include <time.h>

#define __packed __attribute__((__packed__))
#include  "ieee80211.h"
#include  "ieee80211_radiotap.h"

#include <endian.h>



#define WLAN_TAG_PARAM_SIZE 512

uint8_t seqnumber[2] = {0, 0};
uint8_t firstSequence[2] = {0, 0};

/* Definition of an authentication request/response */
struct ieee80211_authentication {
  uint16_t alg;
  uint16_t seq;
  uint16_t status;
  /* We do not support shared key auth */
} __attribute__ ((packed));


/* Definition of an association response */
struct ieee80211_association_response {
  uint16_t capab_info;
  uint16_t status;
  uint16_t aid;
} __attribute__ ((packed));

struct ieee80211_addba_request
{
	uint8_t category;
	uint8_t actionCode;
	uint8_t dialogToken;
	uint16_t BA_params;
	uint16_t BA_timeout;
	uint16_t seq;
} __attribute__ ((packed));

struct ieee80211_addba_response
{
	uint8_t category;
	uint8_t actionCode;
	uint8_t dialogToken;
	uint16_t status;
	uint16_t BA_params;
	uint16_t BA_timeout;
} __attribute__ ((packed));

struct ieee80211_ba_request
{
	uint16_t BA_control;
	uint16_t BA_seq;
}  __attribute__ ((packed));

struct pseudo_header //For doing the udp checksum
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
} __attribute__ ((packed));

struct mpdu_delimiter
{
	u_int16_t reservedAndLength;
	u_int8_t crc;
	u_int8_t delimiterSignature;
} __attribute__ ((packed));

int openSocket( const char device[IFNAMSIZ] )
{
	struct ifreq ifr;
	struct sockaddr_ll ll;
	const int protocol = ETH_P_ALL;
	int sock = -1;
	
	assert( sizeof( ifr.ifr_name ) == IFNAMSIZ );

	sock = socket( PF_PACKET, SOCK_RAW, htons(protocol) );
	if ( sock < 0 )
	{
		perror( "socket failed (do you have root priviledges?)" );
		return -1;
	}
	
	memset( &ifr, 0, sizeof( ifr ) );
	strncpy( ifr.ifr_name, device, sizeof(ifr.ifr_name) );
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
	{
		perror("ioctl[SIOCGIFINDEX]");
		close(sock);
		return -1;
	}

	memset( &ll, 0, sizeof(ll) );
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(protocol);
	if ( bind( sock, (struct sockaddr *) &ll, sizeof(ll) ) < 0 ) {
		perror( "bind[AF_PACKET]" );
		close( sock );
		return -1;
	}
		
	// Enable promiscuous mode
	//~ struct packet_mreq mr;
	//~ memset( &mr, 0, sizeof( mr ) );
	
	//~ mr.mr_ifindex = ll.sll_ifindex;
	//~ mr.mr_type    = PACKET_MR_PROMISC;

	//~ if( setsockopt( sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof( mr ) ) < 0 )
	//~ {
		//~ perror( "setsockopt[PACKET_MR_PROMISC]" );
		//~ close( sock );
		//~ return -1;
	//~ }
	
	return sock;
}

void parseMACAddresses(char* data, u_int8_t* address)
{
	int cont = 1;
	char *token = strtok(data, ":");
	*address = strtol(token, NULL, 16);

	while (token != NULL)
	{
		token = strtok (NULL, ":");
		if(token != NULL)
		{
			*(address+cont) = strtol(token, NULL, 16);
			cont++;
		}
	}
}

void parseIPAddresses(char* data, u_int8_t* address)
{
	int cont = 1;
	char *primeraPalabra = strtok(data, ".");
	char *token = primeraPalabra;
	*address = atoi(token);
	while (token != NULL)
	{
		token = strtok (NULL, ".");
		if(token != NULL)
		{
			*(address+cont) = atoi(token);
			cont++;
		}
	}
}

unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}

void packet_hexdump(const uint8_t* data, size_t size)
{
	size_t i;

	printf("%02x:", data[0]);
	for(i=1; i<size; i++){
		printf("%02x:", data[i]);
		if ( (i & 0xf)  == 0xf )
		{
			// Add a carrage return every 16 bytes
			printf( "\n" );
		}
	}
	printf("\n\n");
}


/** Get the current 802.11 64-bit timestamp from the system time. */
uint64_t getCurrentTimestamp()
{
	struct timeval t;
	
	int code = gettimeofday( &t, NULL );
	assert( code == 0 );
	if ( code != 0 )
	{
		perror( "error calling gettimeofday" );
		assert( 0 );
	}
	
	// Convert seconds to microseconds
	// For the purposes of 802.11 timestamps, we don't care about what happens
	// when this value wraps. As long as the value wraps consistently, we are
	// happy
	uint64_t timestamp = t.tv_sec * 1000000LL;
	timestamp += t.tv_usec;
	
	return timestamp;
}

/** Add increment microseconds to time, computing the overflow correctly. */
void incrementTimeval( struct timeval* time, suseconds_t increment )
{
	assert( time != NULL );
	assert( 0 <= time->tv_usec && time->tv_usec < 1000000 );
	
	if ( increment >= 1000000 )
	{
		// Add the seconds to the seconds field, and keep the remainder
		time->tv_sec += (increment/1000000);
		increment = increment % 1000000;
	}
	
	assert( increment < 1000000 );
	
	time->tv_usec += increment;
	if ( time->tv_usec >= 1000000 )
	{
		time->tv_sec += 1;
		time->tv_usec -= 1000000;
		
		assert( 0 <= time->tv_usec && time->tv_usec < 1000000 );
	}
}

/** Computes "second = first - second" including the underflow "borrow." */ 
void differenceTimeval( const struct timeval* first, struct timeval* second )
{
	assert( first != NULL );
	assert( second != NULL );
	
	second->tv_sec = first->tv_sec - second->tv_sec;
	second->tv_usec = first->tv_usec - second->tv_usec;
	
	// If underflow occured, borrow a second from the higher field
	if ( second->tv_usec < 0 )
	{
		second->tv_sec -= 1;
		second->tv_usec += 1000000;
		
		// If this assertion fails, the initial timevals had invalid values
		assert( 0 <= second->tv_usec && second->tv_usec < 1000000 );
	}
}

/** Returns a negative integer if first < second, zero if first == second, and a positive integer if first > second. */
int compareTimeval( const struct timeval* first, const struct timeval* second )
{
	int difference = first->tv_sec - second->tv_sec;
	if ( difference == 0 )
	{
		// If the seconds fields are equal, compare based on the microseconds
		difference = first->tv_usec - second->tv_usec;
	}
	
	return difference;
}

struct AccessPointDescriptor
{
	uint8_t macAddress[IEEE80211_ADDR_LEN];
	const uint8_t* ssid;
	size_t ssidLength;
	const uint8_t* dataRates;
	size_t dataRatesLength;
};

static const uint8_t IEEE80211_BROADCAST_ADDR[IEEE80211_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const uint8_t IEEE80211B_DEFAULT_RATES[] = { 
	IEEE80211_RATE_BASIC | 2,
	IEEE80211_RATE_BASIC | 4,
	11,
	22,
};
//~ static const size_t IEEE80211B_DEFAULT_RATES_LENGTH = sizeof(IEEE80211B_DEFAULT_RATES);
#define IEEE80211B_DEFAULT_RATES_LENGTH sizeof(IEEE80211B_DEFAULT_RATES)

struct ieee80211_beacon {
	u_int64_t beacon_timestamp;
	u_int16_t beacon_interval;
	u_int16_t beacon_capabilities;
} __attribute__((__packed__));

struct ieee80211_info_element {
	u_int8_t info_elemid;
	u_int8_t info_length;
	u_int8_t* info[0];
} __attribute__((__packed__));

/** Converts a 16-bit integer from host byte order to little-endian byte order. Not implement yet. */
//inline uint16_t htole16( uint16_t src ) { return src; }

#define BEACON_INTERVAL 102400

/** Returns a beacon packet for the specified descriptor. The packet will be allocated using malloc. */
uint8_t* constructBeaconPacket( uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* beaconLength )
{
	// Validate parameters
	assert( apDescription != NULL );
	assert( beaconLength != NULL );
	
	assert( 0 <= apDescription->ssidLength && apDescription->ssidLength <= 32 );
	assert( 1 <= apDescription->dataRatesLength && apDescription->dataRatesLength <= 8 );
	
	uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 ); 
	
	// Packet size: radiotap header + 1 byte for rate + ieee80211_frame header + beacon info + tags
	*beaconLength = sizeof(struct ieee80211_radiotap_header) + sizeof(dataRate) +
		sizeof(struct ieee80211_frame) + sizeof(struct ieee80211_beacon) +
	// SSID, rates, channel
		sizeof(struct ieee80211_info_element)*3 + apDescription->ssidLength +
		apDescription->dataRatesLength + sizeof(channel);

	uint8_t* packet = (uint8_t*) malloc( *beaconLength );
	assert( packet != NULL );
	if ( packet == NULL )
	{
		return NULL;
	}
	
	size_t remainingBytes = *beaconLength;
	
	// Add the radiotap header
	assert( remainingBytes >= sizeof(struct ieee80211_radiotap_header) );
	struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) packet;
	uint8_t* packetIterator = packet + sizeof(*radiotap);
	remainingBytes -= sizeof(*radiotap);
	
	radiotap->it_version = 0;
	radiotap->it_len = sizeof(*radiotap) + sizeof(dataRate);
	radiotap->it_present = (1 << IEEE80211_RADIOTAP_RATE);

	// Add the data rate for the radiotap header
	assert( remainingBytes >= sizeof(dataRate) );
	*packetIterator = (dataRate & IEEE80211_RATE_VAL);
	packetIterator ++;
	remainingBytes -= sizeof(dataRate);
	
	// Build the 802.11 header
	assert( remainingBytes >= sizeof(struct ieee80211_frame) );
	struct ieee80211_frame* dot80211 = (struct ieee80211_frame*) packetIterator;
	packetIterator += sizeof(*dot80211);
	remainingBytes -= sizeof(*dot80211);
	
	// Beacon packet flags
	dot80211->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON;
	//printf("%i\n", *dot80211->i_fc);
	dot80211->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	//printf("%i\n", *dot80211->i_fc);
	//Add by CHdezFdez, using other beacon as example
	dot80211->i_dur[0] = 0x3A;
	dot80211->i_dur[1] = 0x01;
	// Destination = broadcast (no retries)
	memcpy( dot80211->i_addr1, IEEE80211_BROADCAST_ADDR, IEEE80211_ADDR_LEN );
	// Source = our own mac address
	memcpy( dot80211->i_addr2, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// BSS = our mac address
	memcpy( dot80211->i_addr3, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// Sequence control
	dot80211->i_seq[0] = seqnumber[0]&0xf0;
	dot80211->i_seq[1] = seqnumber[1];

	if(seqnumber[0]<0xf0)
	{
		seqnumber[0] += (1<<4);
	}else{
		seqnumber[0]=0;
		seqnumber[1]++;
	}
	
	// Add the beacon frame
	assert( remainingBytes >= sizeof(struct ieee80211_beacon) );
	struct ieee80211_beacon* beacon = (struct ieee80211_beacon*) packetIterator;
	packetIterator += sizeof(*beacon);
	remainingBytes -= sizeof(*beacon);
	
	beacon->beacon_timestamp = getCurrentTimestamp();
	// interval = 100 "time units" = 102.4 ms
	// Each time unit is equal to 1024 us
	beacon->beacon_interval = htole16( BEACON_INTERVAL/1024 );
	// capabilities = sent by ESS
	beacon->beacon_capabilities = IEEE80211_CAPINFO_ESS | IEEE80211_CAPINFO_IMMEDIATE_B_ACK;
	
	// Add the SSID
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + apDescription->ssidLength );
	struct ieee80211_info_element* info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + apDescription->ssidLength;
	remainingBytes -= sizeof(struct ieee80211_info_element) + apDescription->ssidLength;
	
	info->info_elemid = IEEE80211_ELEMID_SSID;
	info->info_length = apDescription->ssidLength;
	memcpy( info->info, apDescription->ssid, apDescription->ssidLength );
	
	// Add the data rates
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + apDescription->dataRatesLength );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + apDescription->dataRatesLength;
	remainingBytes -= sizeof(struct ieee80211_info_element) + apDescription->dataRatesLength;
	
	info->info_elemid = IEEE80211_ELEMID_RATES;
	info->info_length = apDescription->dataRatesLength;
	memcpy( info->info, apDescription->dataRates, apDescription->dataRatesLength );
	
	// Add the channel
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + sizeof(channel) );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + sizeof(channel);
	remainingBytes -= sizeof(struct ieee80211_info_element) + sizeof(channel);
	
	info->info_elemid = IEEE80211_ELEMID_DSPARMS;
	info->info_length = sizeof(channel);
	memcpy( info->info, &channel, sizeof(channel) );

	assert( remainingBytes == 0 );
	//packet_hexdump( (const uint8_t*) packet, *beaconLength );
	return packet;
}

void transmitProbeResponse( int rawSocket, uint8_t* beaconPacket, size_t beaconLength, const uint8_t* destinationMAC )
{
	// Probe responses are identical to beacon packets, except that
	// they are directed and not broadcast, and they are
	// set to be the probe response type
	
	// Find the 802.11 frame
	struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) beaconPacket;
	struct ieee80211_frame* dot80211 = (struct ieee80211_frame*) (beaconPacket + radiotap->it_len);

	dot80211->i_fc[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_RESP;
	memcpy( dot80211->i_addr1, destinationMAC, IEEE80211_ADDR_LEN );

	dot80211->i_seq[0] = seqnumber[0]&0xf0;
	dot80211->i_seq[1] = seqnumber[1];

	if(seqnumber[0]<0xf0)
	{
		seqnumber[0] += (1<<4);
	}else{
		seqnumber[0]=0;
		seqnumber[1]++;
	}
		
	// Send the packet
	ssize_t bytes = write( rawSocket, beaconPacket, beaconLength );
	assert( bytes == (ssize_t) beaconLength );
	//printf("Probe Response Sent\n");
	
	// Set the values back to what they should be for broadcast packets
	dot80211->i_fc[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON;
	memcpy( dot80211->i_addr1, IEEE80211_BROADCAST_ADDR, IEEE80211_ADDR_LEN );
}

uint8_t* constructACKPacket( uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* ACKLength, const uint8_t* destinationMAC )
{
	uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 ); 

	// Packet size: radiotap header + 1 byte for rate + ieee80211_frame_ack header
	*ACKLength = sizeof(struct ieee80211_radiotap_header) + sizeof(dataRate) + sizeof(struct ieee80211_frame_ack);

	uint8_t* packet = (uint8_t*) malloc( *ACKLength );
	assert( packet != NULL );
	if ( packet == NULL )
	{
		return NULL;
	}
	
	size_t remainingBytes = *ACKLength;

	// Add the radiotap header
	assert( remainingBytes >= sizeof(struct ieee80211_radiotap_header) );
	struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) packet;
	uint8_t* packetIterator = packet + sizeof(*radiotap);
	remainingBytes -= sizeof(*radiotap);
	
	radiotap->it_version = 0;
	radiotap->it_len = sizeof(*radiotap) + sizeof(dataRate);
	radiotap->it_present = (1 << IEEE80211_RADIOTAP_RATE);
	
	// Add the data rate for the radiotap header
	assert( remainingBytes >= sizeof(dataRate) );
	*packetIterator = (dataRate & IEEE80211_RATE_VAL);
	packetIterator ++;
	remainingBytes -= sizeof(dataRate);

	// Build the 802.11 header for ACK
	assert( remainingBytes >= sizeof(struct ieee80211_frame_ack) );
	struct ieee80211_frame_ack* dot80211 = (struct ieee80211_frame_ack*) packetIterator;
	packetIterator += sizeof(*dot80211);
	remainingBytes -= sizeof(*dot80211);
	
	// ACK packet flags
	dot80211->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_ACK;
	//printf("%i\n", *dot80211->i_fc);
	dot80211->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	//printf("%i\n", *dot80211->i_fc);
	//Added as an example
	dot80211->i_dur[0] = 0x3A;
	dot80211->i_dur[1] = 0x01;
	// Destination 
	memcpy( dot80211->i_ra, destinationMAC, IEEE80211_ADDR_LEN );

	assert( remainingBytes == 0 );
	//packet_hexdump( (const uint8_t*) packet, *beaconLength );
	return packet;
}

uint8_t* constructAuthResponse ( uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* authLength, const uint8_t* destinationMAC)
{

	uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 );

	*authLength = sizeof(struct ieee80211_radiotap_header) + sizeof(dataRate) +
	sizeof(struct ieee80211_frame) + sizeof(struct ieee80211_authentication);

	uint8_t* packet = (uint8_t*) malloc( *authLength );
	assert( packet != NULL );
	if ( packet == NULL )
	{
		return NULL;
	}
	
	size_t remainingBytes = *authLength;
	
	// Add the radiotap header
	assert( remainingBytes >= sizeof(struct ieee80211_radiotap_header) );
	struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) packet;
	uint8_t* packetIterator = packet + sizeof(*radiotap);
	remainingBytes -= sizeof(*radiotap);
	
	radiotap->it_version = 0;
	radiotap->it_len = sizeof(*radiotap) + sizeof(dataRate);
	radiotap->it_present = (1 << IEEE80211_RADIOTAP_RATE);
	
	// Add the data rate for the radiotap header
	assert( remainingBytes >= sizeof(dataRate) );
	*packetIterator = (dataRate & IEEE80211_RATE_VAL);
	packetIterator ++;
	remainingBytes -= sizeof(dataRate);
	
	// Build the 802.11 header
	assert( remainingBytes >= sizeof(struct ieee80211_frame) );
	struct ieee80211_frame* dot80211 = (struct ieee80211_frame*) packetIterator;
	packetIterator += sizeof(*dot80211);
	remainingBytes -= sizeof(*dot80211);
	
	// Auth packet flags
	dot80211->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_AUTH;
	//printf("%i\n", *dot80211->i_fc);
	dot80211->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	//printf("%i\n", *dot80211->i_fc);
	//Add by CHdezFdez as an example
	dot80211->i_dur[0] = 0x3A;
	dot80211->i_dur[1] = 0x01;
	// Destination 
	memcpy( dot80211->i_addr1, destinationMAC, IEEE80211_ADDR_LEN );
	// Source = our own mac address
	memcpy( dot80211->i_addr2, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// BSS = our mac address
	memcpy( dot80211->i_addr3, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// Sequence control
	dot80211->i_seq[0] = seqnumber[0]&0xf0;
	dot80211->i_seq[1] = seqnumber[1];

	if(seqnumber[0]<0xf0)
	{
		seqnumber[0] += (1<<4);
	}else{
		seqnumber[0]=0;
		seqnumber[1]++;
	}
	
	// Add the authentication frame
	assert( remainingBytes >= sizeof(struct ieee80211_authentication) );
	struct ieee80211_authentication* auth = (struct ieee80211_authentication*) packetIterator;
	packetIterator += sizeof(*auth);
	remainingBytes -= sizeof(*auth);
	
	auth->alg = IEEE80211_AUTH_ALG_OPEN;
	auth->seq = IEEE80211_AUTH_OPEN_RESPONSE;
	auth->status = IEEE80211_STATUS_SUCCESS;
	
	assert( remainingBytes == 0 );
	//packet_hexdump( (const uint8_t*) packet, *beaconLength );
	return packet;

}

uint8_t* constructAssoResponse ( uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* assoLength, const uint8_t* destinationMAC)
{

	static uint8_t cont_AID = 1;
	uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 );

	*assoLength = sizeof(struct ieee80211_radiotap_header) + sizeof(dataRate) +
	sizeof(struct ieee80211_frame) + sizeof(struct ieee80211_association_response) +
	// SSID, rates, channel
	sizeof(struct ieee80211_info_element)*3 + apDescription->ssidLength +
	apDescription->dataRatesLength + sizeof(channel);

	uint8_t* packet = (uint8_t*) malloc( *assoLength );
	assert( packet != NULL );
	if ( packet == NULL )
	{
		return NULL;
	}
	
	size_t remainingBytes = *assoLength;
	
	// Add the radiotap header
	assert( remainingBytes >= sizeof(struct ieee80211_radiotap_header) );
	struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) packet;
	uint8_t* packetIterator = packet + sizeof(*radiotap);
	remainingBytes -= sizeof(*radiotap);
	
	radiotap->it_version = 0;
	radiotap->it_len = sizeof(*radiotap) + sizeof(dataRate);
	radiotap->it_present = (1 << IEEE80211_RADIOTAP_RATE);
	
	// Add the data rate for the radiotap header
	assert( remainingBytes >= sizeof(dataRate) );
	*packetIterator = (dataRate & IEEE80211_RATE_VAL);
	packetIterator ++;
	remainingBytes -= sizeof(dataRate);
	
	// Build the 802.11 header
	assert( remainingBytes >= sizeof(struct ieee80211_frame) );
	struct ieee80211_frame* dot80211 = (struct ieee80211_frame*) packetIterator;
	packetIterator += sizeof(*dot80211);
	remainingBytes -= sizeof(*dot80211);
	
	// Assc packet flags
	dot80211->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ASSOC_RESP;
	//printf("%i\n", *dot80211->i_fc);
	dot80211->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	//printf("%i\n", *dot80211->i_fc);
	//Add by CHdezFdez as an example
	dot80211->i_dur[0] = 0x3A;
	dot80211->i_dur[1] = 0x01;
	// Destination 
	memcpy( dot80211->i_addr1, destinationMAC, IEEE80211_ADDR_LEN );
	// Source = our own mac address
	memcpy( dot80211->i_addr2, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// BSS = our mac address
	memcpy( dot80211->i_addr3, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// Sequence control
	dot80211->i_seq[0] = seqnumber[0]&0xf0;
	dot80211->i_seq[1] = seqnumber[1];

	if(seqnumber[0]<0xf0)
	{
		seqnumber[0] += (1<<4);
	}else{
		seqnumber[0]=0;
		seqnumber[1]++;
	}
	
	// Add the association frame
	assert( remainingBytes >= sizeof(struct ieee80211_association_response) );
	struct ieee80211_association_response* asso = (struct ieee80211_association_response*) packetIterator;
	packetIterator += sizeof(*asso);
	remainingBytes -= sizeof(*asso);
	
	asso->capab_info = IEEE80211_CAPINFO_ESS | IEEE80211_CAPINFO_IMMEDIATE_B_ACK ;
	asso->status = IEEE80211_STATUS_SUCCESS;
	asso->aid = cont_AID;
	cont_AID = cont_AID+1;

	// Add the SSID
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + apDescription->ssidLength );
	struct ieee80211_info_element* info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + apDescription->ssidLength;
	remainingBytes -= sizeof(struct ieee80211_info_element) + apDescription->ssidLength;
	
	info->info_elemid = IEEE80211_ELEMID_SSID;
	info->info_length = apDescription->ssidLength;
	memcpy( info->info, apDescription->ssid, apDescription->ssidLength );
	
	// Add the data rates
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + apDescription->dataRatesLength );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + apDescription->dataRatesLength;
	remainingBytes -= sizeof(struct ieee80211_info_element) + apDescription->dataRatesLength;
	
	info->info_elemid = IEEE80211_ELEMID_RATES;
	info->info_length = apDescription->dataRatesLength;
	memcpy( info->info, apDescription->dataRates, apDescription->dataRatesLength );
	
	// Add the channel
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + sizeof(channel) );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + sizeof(channel);
	remainingBytes -= sizeof(struct ieee80211_info_element) + sizeof(channel);
	
	info->info_elemid = IEEE80211_ELEMID_DSPARMS;
	info->info_length = sizeof(channel);
	memcpy( info->info, &channel, sizeof(channel) );

	assert( remainingBytes == 0 );
	//packet_hexdump( (const uint8_t*) packet, *beaconLength );
	return packet;

}

uint8_t* constructADDBARequest ( uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* addBALength, const uint8_t* destinationMAC)
{
	static uint8_t token = 1;
	uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 );

	*addBALength = sizeof(struct ieee80211_radiotap_header) + sizeof(dataRate) +
	sizeof(struct ieee80211_frame) + sizeof(struct ieee80211_addba_request) +
	// SSID
	sizeof(struct ieee80211_info_element) + apDescription->ssidLength;

	uint8_t* packet = (uint8_t*) malloc( *addBALength );
	assert( packet != NULL );
	if ( packet == NULL )
	{
		return NULL;
	}
	
	size_t remainingBytes = *addBALength;
	
	// Add the radiotap header
	assert( remainingBytes >= sizeof(struct ieee80211_radiotap_header) );
	struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) packet;
	uint8_t* packetIterator = packet + sizeof(*radiotap);
	remainingBytes -= sizeof(*radiotap);
	
	radiotap->it_version = 0;
	radiotap->it_len = sizeof(*radiotap) + sizeof(dataRate);
	radiotap->it_present = (1 << IEEE80211_RADIOTAP_RATE);
	
	// Add the data rate for the radiotap header
	assert( remainingBytes >= sizeof(dataRate) );
	*packetIterator = (dataRate & IEEE80211_RATE_VAL);
	packetIterator ++;
	remainingBytes -= sizeof(dataRate);
	
	// Build the 802.11 header
	assert( remainingBytes >= sizeof(struct ieee80211_frame) );
	struct ieee80211_frame* dot80211 = (struct ieee80211_frame*) packetIterator;
	packetIterator += sizeof(*dot80211);
	remainingBytes -= sizeof(*dot80211);
	
	// ADDBA packet flags
	dot80211->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_ACTION;
	//printf("%i\n", *dot80211->i_fc);
	dot80211->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	//printf("%i\n", *dot80211->i_fc);
	//Add by CHdezFdez as an example
	dot80211->i_dur[0] = 0x3A;
	dot80211->i_dur[1] = 0x01;
	// Destination 
	memcpy( dot80211->i_addr1, destinationMAC, IEEE80211_ADDR_LEN );
	// Source = our own mac address
	memcpy( dot80211->i_addr2, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// BSS = our mac address
	memcpy( dot80211->i_addr3, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// Sequence control
	dot80211->i_seq[0] = seqnumber[0]&0xf0;
	dot80211->i_seq[1] = seqnumber[1];

	if(seqnumber[0]<0xf0)
	{
		seqnumber[0] += (1<<4);
	}else{
		seqnumber[0]=0;
		seqnumber[1]++;
	}
	
	// Add the addba frame
	assert( remainingBytes >= sizeof(struct ieee80211_addba_request) );
	struct ieee80211_addba_request* addBA = (struct ieee80211_addba_request*) packetIterator;
	packetIterator += sizeof(*addBA);
	remainingBytes -= sizeof(*addBA);
	
	addBA->category = IEEE80211_CATEG_BA;
	addBA->actionCode = IEEE80211_ACTION_ADDBA_REQ;
	addBA->dialogToken = token;
	token = token+1;
	addBA->BA_params = htole16(0x1002);
	addBA->BA_timeout = 0;
	addBA->seq = 0;

	// Add the SSID
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + apDescription->ssidLength );
	struct ieee80211_info_element* info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + apDescription->ssidLength;
	remainingBytes -= sizeof(struct ieee80211_info_element) + apDescription->ssidLength;
	
	info->info_elemid = IEEE80211_ELEMID_SSID;
	info->info_length = apDescription->ssidLength;
	memcpy( info->info, apDescription->ssid, apDescription->ssidLength );
	
	assert( remainingBytes == 0 );
	//packet_hexdump( (const uint8_t*) packet, *beaconLength );
	return packet;

}

uint8_t* constructDataPacket ( uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* DataLength, uint8_t* sourceIP, 
	uint8_t* dstIP ,const uint8_t* destinationMAC)
{
	static uint32_t cont = 1502;

	int numCharDatagram = 1400; // It should be lower than 1439 otherwise you will have a problem with the write.

	uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 );

	*DataLength = sizeof(struct ieee80211_radiotap_header) + sizeof(dataRate) +
	sizeof(struct ieee80211_frame) + //sizeof(struct mpdu_delimiter) +
	 sizeof(struct iphdr) + sizeof(struct udphdr) + numCharDatagram*sizeof(char);

	uint8_t* packet = (uint8_t*) malloc( *DataLength );
	assert( packet != NULL );
	if ( packet == NULL )
	{
		return NULL;
	}
	
	size_t remainingBytes = *DataLength;
	
	// Add the radiotap header
	assert( remainingBytes >= sizeof(struct ieee80211_radiotap_header) );
	struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) packet;
	uint8_t* packetIterator = packet + sizeof(*radiotap);
	remainingBytes -= sizeof(*radiotap);
	
	radiotap->it_version = 0;
	radiotap->it_len = sizeof(*radiotap) + sizeof(dataRate);
	radiotap->it_present = (1 << IEEE80211_RADIOTAP_RATE);
	
	// Add the data rate for the radiotap header
	assert( remainingBytes >= sizeof(dataRate) );
	*packetIterator = (dataRate & IEEE80211_RATE_VAL);
	packetIterator ++;
	remainingBytes -= sizeof(dataRate);
	
	// Build the 802.11 header
	assert( remainingBytes >= sizeof(struct ieee80211_frame) );
	struct ieee80211_frame* dot80211 = (struct ieee80211_frame*) packetIterator;
	packetIterator += sizeof(*dot80211);
	remainingBytes -= sizeof(*dot80211);
	
	// ADDBA packet flags
	dot80211->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_DATA;
	//printf("%i\n", *dot80211->i_fc);
	dot80211->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	//printf("%i\n", *dot80211->i_fc);
	//Add by CHdezFdez as an example
	dot80211->i_dur[0] = 0x3A;
	dot80211->i_dur[1] = 0x01;
	// Destination 
	memcpy( dot80211->i_addr1, destinationMAC, IEEE80211_ADDR_LEN );
	// Source = our own mac address
	memcpy( dot80211->i_addr2, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// BSS = our mac address
	memcpy( dot80211->i_addr3, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// Sequence control
	dot80211->i_seq[0] = seqnumber[0]&0xf0;
	dot80211->i_seq[1] = seqnumber[1];

	if(seqnumber[0]<0xf0)
	{
		seqnumber[0] += (1<<4);
	}else{
		seqnumber[0]=0;
		seqnumber[1]++;
	}
	

	/*assert( remainingBytes >= sizeof(struct mpdu_delimiter));
	struct mpdu_delimiter* delim = (struct mpdu_delimiter*) packetIterator;
	packetIterator += sizeof(*delim);
	remainingBytes -= sizeof(*delim);

	delim->reservedAndLength = htole16()*/

    char *pseudogram;

	// Add the IP header
	assert( remainingBytes >= sizeof(struct iphdr) );
	struct iphdr* iph = (struct iphdr*) packetIterator;
	packetIterator += sizeof(*iph);
	remainingBytes -= sizeof(*iph);
     
    //UDP header
    assert( remainingBytes >= sizeof(struct udphdr) );
    struct udphdr *udph = (struct udphdr *) packetIterator;
	packetIterator += sizeof(*udph);
	remainingBytes -= sizeof(*udph);

	assert( remainingBytes >= numCharDatagram*sizeof(char) );
    char *data = (char *) packetIterator;
    //zero out the packet buffer
    memset (data, '0', numCharDatagram);
    //Data part
    strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	packetIterator += numCharDatagram*sizeof(char);
	remainingBytes -= numCharDatagram*sizeof(char);
     
    struct sockaddr_in sin;
    struct pseudo_header psh;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(8080);
    u_int32_t source_address = ((((0x00000000 | *sourceIP<<24) | *(sourceIP+1)<<16) | *(sourceIP+2)<<8) | *(sourceIP));
    u_int32_t destination_address = ((((0x00000000 | *dstIP<<24) | *(dstIP+1)<<16) | *(dstIP+2)<<8) | *(dstIP));
    sin.sin_addr.s_addr = destination_address;
     
    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
    iph->id = htonl (cont); //Id of this packet
    cont++;
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = source_address;    //Spoof the source ip address
    iph->daddr = destination_address;
     
    //Ip checksum
    iph->check = csum ((unsigned short *) iph, iph->tot_len);
     
    //UDP header
    udph->source = htons (6666);
    udph->dest = htons (8622);
    udph->len = htons(sizeof(struct udphdr) + strlen(data)); //tcp header size
    udph->check = 0; //leave checksum 0 now, filled later by pseudo header
     
    //Now the UDP checksum using the pseudo header
    psh.source_address = source_address;
    psh.dest_address = destination_address;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );
     
    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    pseudogram = malloc(psize);
     
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));
     
    udph->check = csum( (unsigned short*) pseudogram , psize);

	assert( remainingBytes == 0 );
	//packet_hexdump( (const uint8_t*) packet, *beaconLength );
	return packet;

}

uint8_t* constructBARequest ( uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* BALength, const uint8_t* destinationMAC)
{

	uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 );

	*BALength = sizeof(struct ieee80211_radiotap_header) + sizeof(dataRate) +
	sizeof(struct ieee80211_frame) + sizeof(struct ieee80211_ba_request);

	uint8_t* packet = (uint8_t*) malloc( *BALength );
	assert( packet != NULL );
	if ( packet == NULL )
	{
		return NULL;
	}
	
	size_t remainingBytes = *BALength;
	
	// Add the radiotap header
	assert( remainingBytes >= sizeof(struct ieee80211_radiotap_header) );
	struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) packet;
	uint8_t* packetIterator = packet + sizeof(*radiotap);
	remainingBytes -= sizeof(*radiotap);
	
	radiotap->it_version = 0;
	radiotap->it_len = sizeof(*radiotap) + sizeof(dataRate);
	radiotap->it_present = (1 << IEEE80211_RADIOTAP_RATE);
	
	// Add the data rate for the radiotap header
	assert( remainingBytes >= sizeof(dataRate) );
	*packetIterator = (dataRate & IEEE80211_RATE_VAL);
	packetIterator ++;
	remainingBytes -= sizeof(dataRate);
	
	// Build the 802.11 header
	assert( remainingBytes >= sizeof(struct ieee80211_frame) );
	struct ieee80211_frame* dot80211 = (struct ieee80211_frame*) packetIterator;
	packetIterator += sizeof(*dot80211);
	remainingBytes -= sizeof(*dot80211);
	
	// ADDBA packet flags
	dot80211->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_BAR;
	//printf("%i\n", *dot80211->i_fc);
	dot80211->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	//printf("%i\n", *dot80211->i_fc);
	//Add by CHdezFdez as an example
	dot80211->i_dur[0] = 0x3A;
	dot80211->i_dur[1] = 0x01;
	// Destination 
	memcpy( dot80211->i_addr1, destinationMAC, IEEE80211_ADDR_LEN );
	// Source = our own mac address
	memcpy( dot80211->i_addr2, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// BSS = our mac address
	memcpy( dot80211->i_addr3, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// Sequence control
	dot80211->i_seq[0] = seqnumber[0]&0xf0;
	dot80211->i_seq[1] = seqnumber[1];

	if(seqnumber[0]<0xf0)
	{
		seqnumber[0] += (1<<4);
	}else{
		seqnumber[0]=0;
		seqnumber[1]++;
	}
	
	// Add the addba frame
	assert( remainingBytes >= sizeof(struct ieee80211_ba_request) );
	struct ieee80211_ba_request* BAR = (struct ieee80211_ba_request*) packetIterator;
	packetIterator += sizeof(*BAR);
	remainingBytes -= sizeof(*BAR);
	
	BAR->BA_control = htole16(0x0001);
	BAR->BA_seq = htole16(((0x0000|(firstSequence[0]<<8))|firstSequence[1])&0x0FFF);

	// Add the SSID
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + apDescription->ssidLength );
	struct ieee80211_info_element* info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + apDescription->ssidLength;
	remainingBytes -= sizeof(struct ieee80211_info_element) + apDescription->ssidLength;
	
	info->info_elemid = IEEE80211_ELEMID_SSID;
	info->info_length = apDescription->ssidLength;
	memcpy( info->info, apDescription->ssid, apDescription->ssidLength );
	
	assert( remainingBytes == 0 );
	//packet_hexdump( (const uint8_t*) packet, *beaconLength );
	return packet;

}


// ADD MORE ACCESS POINTS HERE, IF YOU WANT
static struct AccessPointDescriptor ap0 = {
	{ 0x1c, 0x4b, 0xd6, 0xdc, 0x90, 0xb4 },
	(const uint8_t*) "ap0", 3,
	IEEE80211B_DEFAULT_RATES, IEEE80211B_DEFAULT_RATES_LENGTH,
};

static const struct AccessPointDescriptor* accessPoints[] = {
	&ap0, //&ap1, &ap2, &ap3,
};
static const size_t numAccessPoints = sizeof(accessPoints) / sizeof(*accessPoints);

/** These offsets start from the beginning of the 802.11 frame. */
static const size_t PROBE_SSID_OFFSET = sizeof( struct ieee80211_frame );
static const size_t BEACON_TIMESTAMP_OFFSET = sizeof( struct ieee80211_frame );

void help()
{
	printf( "fakeaps [raw device] [channel it is tuned to] [destination IP address using (.)] [destination MAC address using (:)]\n" );
}

int main(int argc, char *argv[])
{
	if ( argc != 5 )
	{
		help();
		return 1;
	}

	int fd;
 	struct ifreq ifr;
 	fd = socket(AF_INET, SOCK_DGRAM, 0);
 	/* I want to get an IPv4 IP address */
 	ifr.ifr_addr.sa_family = AF_INET;
 	/* I want IP address attached to the selected interface */
 	strncpy(ifr.ifr_name, argv[1], IFNAMSIZ-1);
 	ioctl(fd, SIOCGIFADDR, &ifr);
 	close(fd);

 	u_int8_t sourceIP[4];
 	parseIPAddresses(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), &sourceIP[0]);
	u_int8_t dstIP[4];
	parseIPAddresses(argv[3], &dstIP[0]);
	u_int8_t dstMAC[6];
	parseMACAddresses(argv[4], &dstMAC[0]);

	size_t ACKLength = (size_t) sizeof(size_t);
	uint8_t* ACKPacket = (uint8_t*) (sizeof(uint8_t*));
	size_t authLength = (size_t) sizeof(size_t);
	uint8_t* authPacket = (uint8_t*) (sizeof(uint8_t*));
	size_t assoLength = (size_t) sizeof(size_t);
	uint8_t* assoPacket = (uint8_t*) (sizeof(uint8_t*));
	size_t addBALength = (size_t) sizeof(size_t);
	uint8_t* ADDBAPacket = (uint8_t*) (sizeof(uint8_t*));
	size_t dataPacketLength = (size_t) sizeof(size_t);
	uint8_t* dataPacket = (uint8_t*) (sizeof(uint8_t*));
	size_t BARLength = (size_t) sizeof(size_t);
	uint8_t* BARPacket = (uint8_t*) (sizeof(uint8_t*));
	
	long int channel = strtol( argv[2], NULL, 10 );
	if ( channel <= 0 || 255 <= channel )
	{
		printf( "The channel must be between 1 and 255.\n" );
		help();
		return 1;
	}

		// The 802.11b base broadcast rate
	const uint8_t dataRate = 0x2;
	const char* device = argv[1];
		
	// Construct the beacon packets
	size_t* beaconLengths = (size_t*) malloc( sizeof(size_t) * numAccessPoints );
	assert( beaconLengths != NULL );
	uint8_t** beaconPackets = (uint8_t**) malloc( sizeof(uint8_t*) * numAccessPoints );
	assert( beaconLengths != NULL );
	

	// Open the raw device
	int rawSocket = openSocket( device );
	if ( rawSocket < 0 )
	{
		fprintf( stderr, "error opening socket\n" );
		return 1;
	}

		for ( size_t i = 0; i < numAccessPoints; ++ i )
	{
		beaconPackets[i] = constructBeaconPacket( dataRate, channel, accessPoints[i], &beaconLengths[i] );
		assert( beaconPackets[i] != NULL );
		assert( beaconLengths[i] > 0 );

		ssize_t bytes = write( rawSocket, beaconPackets[i], beaconLengths[i]);
				//printf("Beacon sent\n");
				//packet_hexdump( (const uint8_t*) beaconPackets[i], beaconLengths[i] );
				assert( bytes == (ssize_t) beaconLengths[i] );
				if ( bytes < (ssize_t) beaconLengths[i] )
				{
					perror( "error sending packet" );
					return 1;
				}
	}

	
	// Configure the initial timeout
	struct timeval now;
	int code = gettimeofday( &now, NULL );
	assert( code == 0 );
	
	struct timeval beaconTime = now;
	incrementTimeval( &beaconTime, BEACON_INTERVAL );
	
	// This is used to change the sequence of the probe response messages
	// In order to help clients find more of our fake access points
	size_t lastProbeStartIndex = 0;
	
	while ( 1 )
	{
		// We need to wait until one of two conditions:
		// 1. The "sockin" socket has data for us
		// 2. The beacon interval (102400 microseconds) has expired
		fd_set readfds;
		FD_ZERO( &readfds );
		FD_SET( rawSocket, &readfds );
		
		struct timeval timeout = now;
		differenceTimeval( &beaconTime, &timeout );
		int numFds = select( rawSocket+1, &readfds, NULL, NULL, &timeout );
		assert( numFds >= 0 );
		if ( numFds < 0 )
		{
			perror( "select failed" );
			return 1;
		}
		
		if ( numFds == 1 )
		{
			// We have a packet waiting: Read it
			uint8_t packetBuffer[4096];
			ssize_t bytes = read( rawSocket, packetBuffer, sizeof(packetBuffer) );
			if ( bytes < 0 )
			{
				perror( "read failed" );
				return 1;
			}
			
			// Move past the radiotap header
			assert( bytes >= (ssize_t) sizeof( struct ieee80211_radiotap_header ) );
			struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) packetBuffer;
			assert( radiotap->it_version == 0 );
			assert( bytes >= radiotap->it_len );
			uint8_t* packetIterator = packetBuffer + radiotap->it_len;
			size_t remainingBytes = bytes - radiotap->it_len;
			
			// Get the 802.11 frame:
			// NOTE: This frame structure is larger than some packet types, so only read the initial bytes
			struct ieee80211_frame* frame = (struct ieee80211_frame*)( packetIterator );


			
			if(*frame->i_addr2 == dstMAC[0] && *(frame->i_addr2+1) == dstMAC[1] && *(frame->i_addr2+2) == dstMAC[2] && *(frame->i_addr2+3) == dstMAC[3] &&
				*(frame->i_addr2+4) == dstMAC[4] && *(frame->i_addr2+5) == dstMAC[5])
			{

				// Check to see if this is a PROBE_REQUEST
				//assert( (frame->i_fc[0] & IEEE80211_FC0_VERSION_MASK) == IEEE80211_FC0_VERSION_0 ); //Delete to receive other kinds of packets.
				if ( (frame->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_MGT &&
				(frame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_PROBE_REQ )
				{
					// To get sure that it receive a probe request
					printf("Probe Request received\n");
					packet_hexdump( (const uint8_t*) frame, remainingBytes );
					
					// Locate the SSID
					assert( remainingBytes >= PROBE_SSID_OFFSET );
					packetIterator += PROBE_SSID_OFFSET;
					remainingBytes -= PROBE_SSID_OFFSET;
					struct ieee80211_info_element* info = (struct ieee80211_info_element*) packetIterator;
					assert( remainingBytes >= sizeof(*info) );
					packetIterator += sizeof(*info);
					remainingBytes -= sizeof(*info);
					//assert( remainingBytes >= info->info_length );
					
					// See if it is a broadcast ssid (zero length SSID)
					if ( info->info_length == 0 )
					{
						//printf( "broadcast probe request!\n");
					
						// Start with the next index for the next broadcast probe
						size_t index = lastProbeStartIndex;
						lastProbeStartIndex += 1;
						if ( lastProbeStartIndex >= numAccessPoints )
						{
							lastProbeStartIndex = 0;
						}
					
						// Transmit responses for all access points
						for ( size_t i = 0; i < numAccessPoints; ++ i )
						{
							if ( index >= numAccessPoints )
							{
								index = 0;
							}
							transmitProbeResponse( rawSocket, beaconPackets[index], beaconLengths[index], frame->i_addr2 );
							index += 1;
						}
					}
					else
					{
						// Check if the SSID matches any of ours
						for ( size_t i = 0; i < numAccessPoints; ++ i )
						{
							if ( info->info_length == accessPoints[i]->ssidLength && memcmp( info->info, accessPoints[i]->ssid, info->info_length ) == 0 )
							{
								// It does!
								//printf( "probe for SSID '%.*s'\n", info->info_length, (char*) info->info );
								transmitProbeResponse( rawSocket, beaconPackets[i], beaconLengths[i], frame->i_addr2 );
								break;
							}
						}
					}	
					
				}
				else if( (frame->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_MGT &&
					(frame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_AUTH ) // We received an Authentication Request
				{
					packetIterator += sizeof(struct ieee80211_frame);
					struct ieee80211_authentication* authFrame = (struct ieee80211_authentication*)( packetIterator );

					if(authFrame->seq == IEEE80211_AUTH_OPEN_REQUEST)
					{
						ACKPacket=constructACKPacket(dataRate, channel, accessPoints[0], &ACKLength, frame->i_addr2);
						ssize_t bytes = write( rawSocket, ACKPacket, ACKLength );
						assert( bytes == (ssize_t) ACKLength );
						//printf("ACK sent\n");
						//packet_hexdump( (const uint8_t*) ACKPacket, ACKLength );

						authPacket = constructAuthResponse(dataRate, channel, accessPoints[0], &authLength, frame->i_addr2 );
						bytes = write( rawSocket, authPacket, authLength);
						assert(bytes == (ssize_t) authLength);
						//printf("Authentication response sent\n");
						//packet_hexdump((const uint8_t*) authPacket, authLength);
					}
				

				}
				else if( (frame->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_MGT &&
					(frame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_ASSOC_REQ ) // We received an Association Request
				{
					ACKPacket = constructACKPacket(dataRate, channel, accessPoints[0], &ACKLength, frame->i_addr2);
					ssize_t bytes = write(rawSocket,ACKPacket,ACKLength);
					assert(bytes == (ssize_t) ACKLength);
					//printf("ACK sent\n");
					//packet_hexdump( (const uint8_t*) ACKPacket, ACKLength);

					assoPacket = constructAssoResponse(dataRate, channel, accessPoints[0], &assoLength, frame->i_addr2);
					bytes = write(rawSocket, assoPacket, assoLength);
					assert(bytes== (ssize_t) assoLength);
					//printf("Association Response\n");
					//packet_hexdump( (const uint8_t*) assoPacket, assoLength);

					dataPacket = constructDataPacket(dataRate, channel, accessPoints[0], &dataPacketLength, sourceIP, dstIP ,frame->i_addr2);
					bytes = write(rawSocket, dataPacket, dataPacketLength);
					assert(bytes== (ssize_t) dataPacketLength);
					//printf("Paquete de datos enviado\n");
					//packet_hexdump( (const uint8_t*) dataPacket, dataPacketLength);

					/*ADDBAPacket = constructADDBARequest(dataRate, channel, accessPoints[0], &addBALength, frame->i_addr2);
					bytes = write(rawSocket, ADDBAPacket, addBALength);
					assert(bytes == (ssize_t) addBALength);
					//printf("ADDBA Request\n");
					//packet_hexdump( (const uint8_t*) ADDBAPacket, addBALength);*/
				}
				else if ( (frame->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_MGT &&
					(frame->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_SUBTYPE_ACTION)
				{
					packetIterator += sizeof(struct ieee80211_frame);
					struct ieee80211_addba_response* addbaResponseFrame = (struct ieee80211_addba_response*)( packetIterator );

					if(addbaResponseFrame->category == IEEE80211_CATEG_BA && addbaResponseFrame->actionCode == IEEE80211_ACTION_ADDBA_RESP) //I check if the received frame is an ADDBA Response
					{
						if(addbaResponseFrame->status == 0) // I check the status to know if the receiver can send Block Ack
						{ 
							//Here I must implement the A-MPDU sent
							BARPacket = constructBARequest(dataRate, channel, accessPoints[0], &BARLength, frame->i_addr2);		
						}else
						{
							perror("Device unable to do frame aggregation");
						}
					}

				}
			}
			
		}else{

			// We should only have 1 or 0 fds ready
			assert( numFds == 0 );
		}
			
		// Get the current time to calculate how much longer we need to wait
		// or if we need to send a beacon now
		int code = gettimeofday( &now, NULL );
		assert( code == 0 );
		
		if ( compareTimeval( &beaconTime, &now ) <= 0 )
		{
			//~ printf( "beacon\n" );
			// The timeout has expired. Send out the beacons
			// TODO: Update the timestamp in the beacon packets
			for ( size_t i = 0; i < numAccessPoints; ++ i )
			{
				//Rebuild the beacon to update the timestamp
				beaconPackets[i] = constructBeaconPacket( dataRate, channel, accessPoints[i], &beaconLengths[i] );

				assert( beaconPackets[i] != NULL );
				assert( beaconLengths[i] > 0 );

				//printf("Prueba: %zu\n",beaconLengths[i]);
				ssize_t bytes = write( rawSocket, beaconPackets[i], beaconLengths[i]);
				//printf("Beacon sent\n");
				//packet_hexdump( (const uint8_t*) beaconPackets[i], beaconLengths[i] );
				assert( bytes == (ssize_t) beaconLengths[i] );
				if ( bytes < (ssize_t) beaconLengths[i] )
				{
					perror( "error sending packet" );
					return 1;
				}
			}
			
			// Increment the next beacon time until it is in the future
			do {
				incrementTimeval( &beaconTime, BEACON_INTERVAL );
			} while( compareTimeval( &beaconTime, &now ) <= 0 );
		}
		
		
		
	}
	
	close( rawSocket );
	free( beaconPackets );
	free( beaconLengths );
}