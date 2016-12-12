/**
Code taken from the following website:

http://www.evanjones.ca/software/fakeaps.c

Thanks to Evan Jones for his work.

And used to implement the authentication, association. And finally our purpose is to implement frame aggregation (A-MPDU).
This changes will be made by Cristian Hernandez.

TO USE IT YOU NEED A NETWORK DRIVER THAT SUPPORTS RADIOTAP, OTHERWISE IT WILL NOT WORK AS EXPECTED

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

#define DUMP_PACKETS 1	// if you set this to 0, you will see no packets dump
			//                    1, only the A-MPDUs or the MPDUs (data packets) will be dump
                        //                    2, all the generated packets will be dump by the screen

#define DEBUG_LEVEL 2	// if you set this to 0, you will not see anything by the screen
			//                    1, you will see a message when a data frame or a block ACK is sent
			//                    2, you will see a message every time a frame is sent

uint8_t seqnumber[2] = {0, 0};
uint8_t firstSequence[2] = {0, 0};
uint32_t mpduseq = 0;

//This from https://stackoverflow.com/questions/11523844/802-11-fcs-crc32

const uint32_t crctable[] = {
   0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L, 0x706af48fL, 0xe963a535L, 0x9e6495a3L,
   0x0edb8832L, 0x79dcb8a4L, 0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L, 0x90bf1d91L,
   0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL, 0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L,
   0x136c9856L, 0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L, 0xfa0f3d63L, 0x8d080df5L,
   0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L, 0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
   0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L, 0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L,
   0x26d930acL, 0x51de003aL, 0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L, 0xb8bda50fL,
   0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L, 0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL,
   0x76dc4190L, 0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL, 0x9fbfe4a5L, 0xe8b8d433L,
   0x7807c9a2L, 0x0f00f934L, 0x9609a88eL, 0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
   0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL, 0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L,
   0x65b0d9c6L, 0x12b7e950L, 0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L, 0xfbd44c65L,
   0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L, 0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL,
   0x4369e96aL, 0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L, 0xaa0a4c5fL, 0xdd0d7cc9L,
   0x5005713cL, 0x270241aaL, 0xbe0b1010L, 0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
   0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L, 0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL,
   0xedb88320L, 0x9abfb3b6L, 0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L, 0x73dc1683L,
   0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L, 0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L,
   0xf00f9344L, 0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL, 0x196c3671L, 0x6e6b06e7L,
   0xfed41b76L, 0x89d32be0L, 0x10da7a5aL, 0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
   0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L, 0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL,
   0xd80d2bdaL, 0xaf0a1b4cL, 0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL, 0x4669be79L,
   0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L, 0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL,
   0xc5ba3bbeL, 0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L, 0x2cd99e8bL, 0x5bdeae1dL,
   0x9b64c2b0L, 0xec63f226L, 0x756aa39cL, 0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
   0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL, 0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L,
   0x86d3d2d4L, 0xf1d4e242L, 0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L, 0x18b74777L,
   0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL, 0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L,
   0xa00ae278L, 0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L, 0x4969474dL, 0x3e6e77dbL,
   0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L, 0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
   0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L, 0xcdd70693L, 0x54de5729L, 0x23d967bfL,
   0xb3667a2eL, 0xc4614ab8L, 0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL, 0x2d02ef8dL
};

uint32_t crc32(uint32_t bytes_sz, const uint8_t *bytes)
{
   uint32_t crc = ~0;
   uint32_t i;
   for(i = 0; i < bytes_sz; ++i) {
      crc = crctable[(crc ^ bytes[i]) & 0xff] ^ (crc >> 8);
   }
   return ~crc;
}

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

struct ieee80211_baframe {
	u_int8_t	i_fc[2];
	u_int8_t	i_dur[2];
	u_int8_t	i_addr1[IEEE80211_ADDR_LEN];
	u_int8_t	i_addr2[IEEE80211_ADDR_LEN];
} __attribute__ ((packed));

struct ieee80211_ba_request
{
	uint16_t BA_control;
	uint16_t BA_seq;
}  __attribute__ ((packed));

struct llc
{
	uint8_t DSAP;
	uint8_t SSAP;
	uint8_t control;
} __attribute__ ((packed));

struct snap
{
	uint16_t OID1;
	uint8_t OID2;
	uint16_t protocolID;
} __attribute__ ((packed));

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

struct ampdu_status
{
	uint32_t reference;
	uint16_t flags;
} __attribute__ ((packed));

struct HTCapabilities
{
	uint16_t info;
	uint8_t ampduParams;
	uint32_t rxModulation1;
	uint32_t rxModulation2;
	uint16_t rxModulation3;
	uint16_t highestDataRate;
	uint8_t txParams;
	uint16_t empty1;
	uint8_t empty2;
	uint16_t extendedCap;
	uint32_t beanFormingCap;
	uint8_t antennaSelectionCap;
} __attribute__ ((packed));

struct HTInfo
{
	uint8_t channel;
	uint8_t subset1;
	uint16_t subset2;
	uint16_t subset3;
	uint64_t rxModulation1;
	uint64_t rxModulation2;
} __attribute__ ((packed));

struct vendor
{
	uint16_t oid1;
	uint8_t oid2;
	uint8_t type;
	uint8_t subtype;
	uint8_t version;
	uint8_t qosInfo;
	uint8_t reserved;
	uint8_t ACI0;
	uint8_t ECW0;
	uint16_t TxLim0;
	uint8_t ACI1;
	uint8_t ECW1;
	uint16_t TxLim1;
	uint8_t ACI2;
	uint8_t ECW2;
	uint16_t TxLim2;
	uint8_t ACI3;
	uint8_t ECW3;
	uint16_t TxLim3;
} __attribute__ ((packed));
struct FCS
{
	uint32_t FCSvalue;
};

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
	//~ mr.mr_type = PACKET_MR_PROMISC;

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

uint8_t checksum (uint8_t *buffer, int cantidad) {
	register uint32_t suma = 0;
	while (cantidad--) {
		suma += *buffer++;
	if (suma & 0xFFFF0000) {
		/* hubo acarreo, se debe incrementar el resultado */
		suma &= 0xFFFF;
		suma++;
		}
	}
	return ~(suma & 0xFFFF);
} 

/*uint8_t CRC8(uint8_t* bytes, int length)
{
	const uint8_t generator = 0x07;
	uint8_t crc = 0; // start with 0 so first byte can be 'xored' in 

	for (int i = 0; i < length; i++)
	{
		crc ^= *(bytes+i); // XOR-in the next input byte 

		for (int j = 0; j < 8; j++)
		{
			if ((crc & 0x80) != 0)
			{
				crc = (uint8_t)((crc << 1) ^ generator);
			}
			else
			{
				crc <<= 1;
			}
		}
	}

	return crc;
}*/

#define GP  0x107   /* x^8 + x^2 + x + 1 */
#define DI  0x07


static uint8_t crc8_table[256];	/* 8-bit table */
static int made_table=0;

static void init_crc8()
	/*
	* Should be called before any other crc function.  
	*/
{
	int i,j;
	uint8_t crc;

	if (!made_table) {
		for (i=0; i<256; i++) {
			crc = i;
			for (j=0; j<8; j++)
				crc = (crc << 1) ^ ((crc & 0x80) ? DI : 0);
				crc8_table[i] = crc & 0xFF;
				/* printf("table[%d] = %d (0x%X)\n", i, crc, crc); */
			}
		made_table=1;
	}
}


void crc8(uint8_t *crc, uint8_t m)
	/*
	* For a byte array whose accumulated crc value is stored in *crc, computes
	* resultant crc obtained by appending m to the byte array
	*/
{
	if (!made_table)
		init_crc8();

	*crc = crc8_table[(*crc) ^ m];
	*crc &= 0xFF;
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
/*uint64_t getCurrentTimestamp()
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
}*/

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
static const uint8_t IEEE80211_DEFAULT_RATES[] = { 
	0x82,
	0x84,
	0x8b,
	0x0c,
	0x12,
	0x96,
	0x18,
	0x24
};
//~ static const size_t IEEE80211_DEFAULT_RATES_LENGTH = sizeof(IEEE80211_DEFAULT_RATES);
#define IEEE80211_DEFAULT_RATES_LENGTH sizeof(IEEE80211_DEFAULT_RATES)

static const uint8_t IEEE80211_EXTENDED_RATES[] = {
	0x30,
	0x48,
	0x60,
	0x6c
};
#define IEEE80211_EXTENDED_RATES_LENGTH sizeof(IEEE80211_EXTENDED_RATES)

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
void constructBeaconPacket(uint8_t* packet, uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* beaconLength )
{
	// Validate parameters
	assert( apDescription != NULL );
	assert( beaconLength != NULL );
	
	assert( 0 <= apDescription->ssidLength && apDescription->ssidLength <= 32 );
	assert( 1 <= apDescription->dataRatesLength && apDescription->dataRatesLength <= 8 );
	
	////uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	//assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 ); 
	
	assert( packet != NULL );
	
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
	dot80211->i_dur[0] = 0x00;
	dot80211->i_dur[1] = 0x00;
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
	
	beacon->beacon_timestamp = 0x000000000000000000;//getCurrentTimestamp();
	// interval = 100 "time units" = 102.4 ms
	// Each time unit is equal to 1024 us
	beacon->beacon_interval = htole16( BEACON_INTERVAL/1024 );
	// capabilities = sent by ESS
	beacon->beacon_capabilities = IEEE80211_CAPINFO_ESS | IEEE80211_CAPINFO_IMMEDIATE_B_ACK | IEEE80211_CAPINFO_QOS;
	
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

	// Add the HT-Capabilities
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + sizeof(struct HTCapabilities) );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + sizeof(struct HTCapabilities);
	remainingBytes -= sizeof(struct ieee80211_info_element) + sizeof(struct HTCapabilities);
	
	info->info_elemid = IEEE80211_ELEMID_HTCAPS;
	info->info_length = sizeof(struct HTCapabilities);
	struct HTCapabilities htcap;
	htcap.info = htons(0xee19);
	htcap.ampduParams = 0x1b;
	htcap.rxModulation1 = htonl(0xffffff00);
	htcap.rxModulation2 = 0x00000000;
	htcap.rxModulation3 = 0x0000;
	htcap.highestDataRate = 0x0000;
	htcap.txParams = 0x00;
	htcap.empty1 = 0x0000;
	htcap.empty2 = 0x00;
	htcap.extendedCap = 0x0000;
	htcap.beanFormingCap = 0x00000000;
	htcap.antennaSelectionCap = 0x00;
	memcpy( info->info, &htcap, sizeof(htcap) );

	// Add the extended data rates
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + IEEE80211_EXTENDED_RATES_LENGTH );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + IEEE80211_EXTENDED_RATES_LENGTH;
	remainingBytes -= sizeof(struct ieee80211_info_element) + IEEE80211_EXTENDED_RATES_LENGTH;
	
	info->info_elemid = IEEE80211_ELEMID_XRATES;
	info->info_length = IEEE80211_EXTENDED_RATES_LENGTH;
	memcpy( info->info, IEEE80211_EXTENDED_RATES, IEEE80211_EXTENDED_RATES_LENGTH );

	// Add the HT-Capabilities
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + sizeof(struct HTInfo) );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + sizeof(struct HTInfo);
	remainingBytes -= sizeof(struct ieee80211_info_element) + sizeof(struct HTInfo);
	
	info->info_elemid = IEEE80211_ELEMID_HTOP;
	info->info_length = sizeof(struct HTInfo);
	struct HTInfo htinf;
	htinf.channel = 0x05;
	htinf.subset1 = 0x00;
	htinf.subset2 = htons(0x0700);
	htinf.subset3 = 0x0000;
	htinf.rxModulation1 = 0x000000000000000000;
	htinf.rxModulation2 = 0x000000000000000000;
	memcpy( info->info, &htinf, sizeof(htinf) );

	// Add the Microsoft: WMM/WME
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + sizeof(struct vendor) );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + sizeof(struct vendor);
	remainingBytes -= sizeof(struct ieee80211_info_element) + sizeof(struct vendor);

	info->info_elemid = IEEE80211_ELEMID_VENDOR;
	info->info_length = sizeof(struct vendor);
	struct vendor WMM;
	WMM.oid1 = htons(0x0050);
	WMM.oid2 = 0xf2;
	WMM.type = 0x02;
	WMM.subtype = 0x01;
	WMM.version = 0x01;
	WMM.qosInfo = 0x80;
	WMM.reserved = 0x00;
	WMM.ACI0 = 0x03;
	WMM.ECW0 = 0xa4;
	WMM.TxLim0 = 0x0000;
	WMM.ACI1 = 0x27;
	WMM.ECW1 = 0xa4;
	WMM.TxLim1 = 0x0000;
	WMM.ACI2 = 0x42;
	WMM.ECW2 = 0x43;
	WMM.TxLim2 = htons(0x005e);
	WMM.ACI3 = 0x62;
	WMM.ECW3 = 0x32;
	WMM.TxLim3 = htons(0x002f);
	memcpy( info->info, &WMM, sizeof(WMM) ); 

	assert( remainingBytes == 0 );
	//packet_hexdump( (const uint8_t*) packet, *beaconLength );

}

void constructProbeResponse(uint8_t* packet, uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* probeResponseLength, const uint8_t* destinationMAC )
{
	// Validate parameters
	assert( apDescription != NULL );
	assert( probeResponseLength != NULL );
	
	assert( 0 <= apDescription->ssidLength && apDescription->ssidLength <= 32 );
	assert( 1 <= apDescription->dataRatesLength && apDescription->dataRatesLength <= 8 );
	
	////uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	//assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 ); 
	
	// Packet size: radiotap header + 1 byte for rate + ieee80211_frame header + beacon info + tags

	assert( packet != NULL );
	
	size_t remainingBytes = *probeResponseLength;
	
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
	dot80211->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_RESP;
	//printf("%i\n", *dot80211->i_fc);
	dot80211->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	//printf("%i\n", *dot80211->i_fc);
	//Add by CHdezFdez, using other beacon as example
	dot80211->i_dur[0] = 0x00;
	dot80211->i_dur[1] = 0x00;
	// Destination = broadcast (no retries)
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
	
	// Add the beacon frame
	assert( remainingBytes >= sizeof(struct ieee80211_beacon) );
	struct ieee80211_beacon* beacon = (struct ieee80211_beacon*) packetIterator;
	packetIterator += sizeof(*beacon);
	remainingBytes -= sizeof(*beacon);
	
	beacon->beacon_timestamp = 0x000000000000000000;//getCurrentTimestamp();
	// interval = 100 "time units" = 102.4 ms
	// Each time unit is equal to 1024 us
	beacon->beacon_interval = htole16( BEACON_INTERVAL/1024 );
	// capabilities = sent by ESS
	beacon->beacon_capabilities = IEEE80211_CAPINFO_ESS | IEEE80211_CAPINFO_IMMEDIATE_B_ACK | IEEE80211_CAPINFO_QOS;
	
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

	// Add the HT-Capabilities
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + sizeof(struct HTCapabilities) );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + sizeof(struct HTCapabilities);
	remainingBytes -= sizeof(struct ieee80211_info_element) + sizeof(struct HTCapabilities);
	
	info->info_elemid = IEEE80211_ELEMID_HTCAPS;
	info->info_length = sizeof(struct HTCapabilities);
	struct HTCapabilities htcap;
	htcap.info = htons(0xac19);
	htcap.ampduParams = 0x1b;
	htcap.rxModulation1 = htonl(0xffffff00);
	htcap.rxModulation2 = 0x00000000;
	htcap.rxModulation3 = 0x0000;
	htcap.highestDataRate = 0x0000;
	htcap.txParams = 0x00;
	htcap.empty1 = 0x0000;
	htcap.empty2 = 0x00;
	htcap.extendedCap = 0x0000;
	htcap.beanFormingCap = 0x00000000;
	htcap.antennaSelectionCap = 0x00;
	memcpy( info->info, &htcap, sizeof(htcap) );

	// Add the extended data rates
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + IEEE80211_EXTENDED_RATES_LENGTH );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + IEEE80211_EXTENDED_RATES_LENGTH;
	remainingBytes -= sizeof(struct ieee80211_info_element) + IEEE80211_EXTENDED_RATES_LENGTH;
	
	info->info_elemid = IEEE80211_ELEMID_XRATES;
	info->info_length = IEEE80211_EXTENDED_RATES_LENGTH;
	memcpy( info->info, IEEE80211_EXTENDED_RATES, IEEE80211_EXTENDED_RATES_LENGTH );

	// Add the HT-Capabilities
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + sizeof(struct HTInfo) );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + sizeof(struct HTInfo);
	remainingBytes -= sizeof(struct ieee80211_info_element) + sizeof(struct HTInfo);
	
	info->info_elemid = IEEE80211_ELEMID_HTOP;
	info->info_length = sizeof(struct HTInfo);
	struct HTInfo htinf;
	htinf.channel = 0x05;
	htinf.subset1 = 0x00;
	htinf.subset2 = htons(0x0700);
	htinf.subset3 = 0x0000;
	htinf.rxModulation1 = 0x000000000000000000;
	htinf.rxModulation2 = 0x000000000000000000;
	memcpy( info->info, &htinf, sizeof(htinf) );

	// Add the Microsoft: WMM/WME
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + sizeof(struct vendor) );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + sizeof(struct vendor);
	remainingBytes -= sizeof(struct ieee80211_info_element) + sizeof(struct vendor);
	struct vendor WMM;
	WMM.oid1 = htons(0x0050);
	WMM.oid2 = 0xf2;
	WMM.type = 0x02;
	WMM.subtype = 0x01;
	WMM.version = 0x01;
	WMM.qosInfo = 0x80;
	WMM.reserved = 0x00;
	WMM.ACI0 = 0x03;
	WMM.ECW0 = 0xa4;
	WMM.TxLim0 = 0x0000;
	WMM.ACI1 = 0x27;
	WMM.ECW1 = 0xa4;
	WMM.TxLim1 = 0x0000;
	WMM.ACI2 = 0x42;
	WMM.ECW2 = 0x43;
	WMM.TxLim2 = htons(0x005e);
	WMM.ACI3 = 0x62;
	WMM.ECW3 = 0x32;
	WMM.TxLim3 = htons(0x002f);
	memcpy( info->info, &WMM, sizeof(WMM) ); 
	assert( remainingBytes == 0 );
	//packet_hexdump( (const uint8_t*) packet, *beaconLength );
}

/*void constructACKPacket(uint8_t packet, uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* ACKLength, const uint8_t* destinationMAC )
{
	//uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	//assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 ); 

	// Packet size: radiotap header + 1 byte for rate + ieee80211_frame_ack header
	
	assert( packet != NULL );
	
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
	dot80211->i_dur[0] = 0x00;
	dot80211->i_dur[1] = 0x00;
	// Destination 
	memcpy( dot80211->i_ra, destinationMAC, IEEE80211_ADDR_LEN );

	assert( remainingBytes == 0 );
	//packet_hexdump( (const uint8_t*) packet, *beaconLength );
}*/

void constructAuthResponse (uint8_t* packet, uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* authLength, const uint8_t* destinationMAC)
{

	//uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	//assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 );


	assert( packet != NULL );
	
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
	dot80211->i_dur[0] = 0x00;
	dot80211->i_dur[1] = 0x00;
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
}

void constructAssoResponse (uint8_t* packet, uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* assoLength, const uint8_t* destinationMAC)
{
	static uint8_t cont_AID = 1;
	//uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	//assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 );

	assert( packet != NULL );
	
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
	dot80211->i_dur[0] = 0x00;
	dot80211->i_dur[1] = 0x00;
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
	} else {
		seqnumber[0]=0;
		seqnumber[1]++;
	}
	
	// Add the association frame
	assert( remainingBytes >= sizeof(struct ieee80211_association_response) );
	struct ieee80211_association_response* asso = (struct ieee80211_association_response*) packetIterator;
	packetIterator += sizeof(*asso);
	remainingBytes -= sizeof(*asso);
	
	asso->capab_info = IEEE80211_CAPINFO_ESS | IEEE80211_CAPINFO_IMMEDIATE_B_ACK | IEEE80211_CAPINFO_QOS;
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

	// Add the HT-Capabilities
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + sizeof(struct HTCapabilities) );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + sizeof(struct HTCapabilities);
	remainingBytes -= sizeof(struct ieee80211_info_element) + sizeof(struct HTCapabilities);
	
	info->info_elemid = IEEE80211_ELEMID_HTCAPS;
	info->info_length = sizeof(struct HTCapabilities);
	struct HTCapabilities htcap;
	htcap.info = htons(0xac19);
	htcap.ampduParams = 0x1b;
	htcap.rxModulation1 = htonl(0xffffff00);
	htcap.rxModulation2 = 0x00000000;
	htcap.rxModulation3 = 0x0000;
	htcap.highestDataRate = 0x0000;
	htcap.txParams = 0x00;
	htcap.empty1 = 0x0000;
	htcap.empty2 = 0x00;
	htcap.extendedCap = 0x0000;
	htcap.beanFormingCap = 0x00000000;
	htcap.antennaSelectionCap = 0x00;
	memcpy( info->info, &htcap, sizeof(htcap) );

	// Add the extended data rates
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + IEEE80211_EXTENDED_RATES_LENGTH );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + IEEE80211_EXTENDED_RATES_LENGTH;
	remainingBytes -= sizeof(struct ieee80211_info_element) + IEEE80211_EXTENDED_RATES_LENGTH;
	
	info->info_elemid = IEEE80211_ELEMID_XRATES;
	info->info_length = IEEE80211_EXTENDED_RATES_LENGTH;
	memcpy( info->info, IEEE80211_EXTENDED_RATES, IEEE80211_EXTENDED_RATES_LENGTH );

	// Add the HT-Capabilities
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + sizeof(struct HTInfo) );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + sizeof(struct HTInfo);
	remainingBytes -= sizeof(struct ieee80211_info_element) + sizeof(struct HTInfo);
	
	info->info_elemid = IEEE80211_ELEMID_HTOP;
	info->info_length = sizeof(struct HTInfo);
	struct HTInfo htinf;
	htinf.channel = 0x05;
	htinf.subset1 = 0x00;
	htinf.subset2 = htons(0x0700);
	htinf.subset3 = 0x0000;
	htinf.rxModulation1 = 0x000000000000000000;
	htinf.rxModulation2 = 0x000000000000000000;
	memcpy( info->info, &htinf, sizeof(htinf) );

	// Add the Microsoft: WMM/WME
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + sizeof(struct vendor) );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + sizeof(struct vendor);
	remainingBytes -= sizeof(struct ieee80211_info_element) + sizeof(struct vendor);
	struct vendor WMM;
	WMM.oid1 = htons(0x0050);
	WMM.oid2 = 0xf2;
	WMM.type = 0x02;
	WMM.subtype = 0x01;
	WMM.version = 0x01;
	WMM.qosInfo = 0x80;
	WMM.reserved = 0x00;
	WMM.ACI0 = 0x03;
	WMM.ECW0 = 0xa4;
	WMM.TxLim0 = 0x0000;
	WMM.ACI1 = 0x27;
	WMM.ECW1 = 0xa4;
	WMM.TxLim1 = 0x0000;
	WMM.ACI2 = 0x42;
	WMM.ECW2 = 0x43;
	WMM.TxLim2 = htons(0x005e);
	WMM.ACI3 = 0x62;
	WMM.ECW3 = 0x32;
	WMM.TxLim3 = htons(0x002f);
	memcpy( info->info, &WMM, sizeof(WMM) );

	assert( remainingBytes == 0 );
	//packet_hexdump( (const uint8_t*) packet, *beaconLength );

}

void constructADDBARequest (uint8_t* packet, uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* addBALength, const uint8_t* destinationMAC)
{
	static uint8_t token = 1;
	//uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	//assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 );

	assert( packet != NULL );
		
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
	dot80211->i_dur[0] = 0x00;
	dot80211->i_dur[1] = 0x00;
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
	} else {
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
	addBA->seq = (uint16_t)seqnumber[1]<<8|(seqnumber[0]&0xf0);

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

}

void constructDataPacket (	uint8_t* packet,	// the A-MPUDU multi-frame we are going to build. It contains a header and a number of sub-frames
							// this is the result returned by this function
				uint8_t dataRate, 
				uint8_t channel, 
				const struct AccessPointDescriptor* apDescription, 
				size_t* DataLength, uint8_t* sourceIP, 
				uint8_t* dstIP,				// destination IP address
				const uint8_t* destinationMAC,		// destination MAC address
				uint8_t numFrames,			// number of sub-frames
				int numCharDatagram )
{
	static uint32_t cont = 1502;	// This is a random number for the ID field of the IP header

	int debug_level = DEBUG_LEVEL;

	//int numCharDatagram = 500;
	//uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	//assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 );
	int zeropadding = 0;

	// We are using the format ieee80211_htframe_addr4, in order to consider HT frames for 802.11n

	// Calculate the size of an MPDU
	int MPDUsize =	sizeof(	struct ieee80211_htframe_addr4) + 
				sizeof(struct llc) +		// LLC header
				sizeof(struct snap) +		// SNAP header
				sizeof(struct iphdr) +		// IP header
				sizeof(struct udphdr) +		// UDP header
				numCharDatagram*sizeof(char);	// Payload

	struct sockaddr_in sin;
	struct pseudo_header psh;

	// check if a padding is required (if the size of the MPDU is not a multiple of 4)
	if((MPDUsize%4)!=0)
	{
		zeropadding = (4-(MPDUsize%4));
	}

	// printf("MPDU size (including padding): %d bytes\n", MPDUsize);

	assert( packet != NULL );

	size_t remainingBytes = *DataLength;

	// Add the radiotap header
	assert( remainingBytes >= sizeof(struct ieee80211_radiotap_header) );
	struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) packet;
	uint8_t* packetIterator = packet + sizeof(*radiotap);
	remainingBytes -= sizeof(*radiotap);

	radiotap->it_version = 0;
	radiotap->it_len = sizeof(*radiotap) + sizeof(dataRate);
	radiotap->it_present = (1 << IEEE80211_RADIOTAP_RATE);
	
	if(numFrames != 0) { // we are building an A-MPDU

		radiotap->it_len += (16-(sizeof(dataRate))) + sizeof(struct ampdu_status);
		radiotap->it_present = (0x00000000 |(1 << IEEE80211_RADIOTAP_RATE)) | (1 << 20);
	}

	// Add the data rate for the radiotap header
	assert( remainingBytes >= sizeof(dataRate) );
	*packetIterator = (dataRate & IEEE80211_RATE_VAL);
	packetIterator ++;
	remainingBytes -= sizeof(dataRate);

	if(numFrames != 0) { // we are building an A-MPDU
		
		assert ( remainingBytes >= (16-(sizeof(dataRate)%16)));
		packetIterator += (16-(sizeof(dataRate)%16));
		remainingBytes -= (16-(sizeof(dataRate)%16));

		assert ( remainingBytes >= sizeof(struct ampdu_status) );
		struct ampdu_status* status = (struct ampdu_status*) packetIterator;
		packetIterator += sizeof(*status);
		remainingBytes -= sizeof(*status);

		status->reference = mpduseq;
		mpduseq ++;
		enum
		{
			A_MPDU_STATUS_NONE                = 0x00, 
			A_MPDU_STATUS_REPORT_ZERO_LENGTH  = 0x01, 
			A_MPDU_STATUS_IS_ZERO_LENGTH      = 0x02, 
			A_MPDU_STATUS_LAST_KNOWN          = 0x04, 
			A_MPDU_STATUS_LAST                = 0x08, 
			A_MPDU_STATUS_DELIMITER_CRC_ERROR = 0x10, 
			A_MPDU_STATUS_DELIMITER_CRC_KNOWN = 0x20  
		};
		status->flags = A_MPDU_STATUS_LAST_KNOWN || A_MPDU_STATUS_DELIMITER_CRC_KNOWN;
	}

	// we are building a normal frame (non-aggregated one)
	if(numFrames==0)
	{
		// Build the 802.11 header
		assert( remainingBytes >= sizeof(struct ieee80211_htframe_addr4) );
		struct ieee80211_htframe_addr4* dot80211 = (struct ieee80211_htframe_addr4*) packetIterator;
		packetIterator += sizeof(*dot80211);
		remainingBytes -= sizeof(*dot80211);

		if ( debug_level > 0 )
			printf("MPDU size: %d bytes\n", MPDUsize);

		// ADDBA packet flags
		dot80211->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_QOS;
		//printf("%i\n", *dot80211->i_fc);
		dot80211->i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
		//printf("%i\n", *dot80211->i_fc);

		dot80211->i_dur[0] = 0x00;
		dot80211->i_dur[1] = 0x00;
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
		} else {
			seqnumber[0]=0;
			seqnumber[1]++;
		}

		// Add the MAC Address number 4, i.e. the Source Address
		// Destination QUESTION: the standard says N/A for this address
		memcpy( dot80211->i_addr4, destinationMAC, IEEE80211_ADDR_LEN );


		// Add the QoS Ctl field
		dot80211->i_qos[0] = 0x00;
		dot80211->i_qos[1] = 0x00;

		// We have to add HT Ctl here (Info: https://mrncciew.com/2014/10/20/cwap-ht-control-field/)
		dot80211->i_ht[0] = 0x00;
		dot80211->i_ht[1] = 0x7f;
		dot80211->i_ht[2] = 0x00;
		dot80211->i_ht[3] = 0x00;



		// Add LLC header
		assert(remainingBytes >= sizeof(struct llc) );
		struct llc* llchdr = (struct llc*) packetIterator;
		packetIterator += sizeof(*llchdr);
		remainingBytes -= sizeof(*llchdr);

		llchdr->DSAP = 0xAA;
		llchdr->SSAP = 0xAA;
		llchdr->control = 0x03;

		// Add SNAP header
		assert(remainingBytes >= sizeof(struct snap) );
		struct snap* snaphdr = (struct snap*) packetIterator;
		packetIterator += sizeof(*snaphdr);
		remainingBytes -= sizeof(*snaphdr);

		snaphdr->OID1 = 0x0000;
		snaphdr->OID2 = 0x00;
		snaphdr->protocolID = htons(0x0800);

		char *pseudogram;

		// Add the IP header
		assert( remainingBytes >= sizeof(struct iphdr) );
		struct iphdr* iph = (struct iphdr*) packetIterator;
		packetIterator += sizeof(*iph);
		remainingBytes -= sizeof(*iph);

		// Add the UDP header
		assert( remainingBytes >= sizeof(struct udphdr) );
		struct udphdr *udph = (struct udphdr *) packetIterator;
		packetIterator += sizeof(*udph);
		remainingBytes -= sizeof(*udph);

		// Add the UDP payload
		assert( remainingBytes >= numCharDatagram*sizeof(char) );
		char *data = (char *) packetIterator;
		// put a number of zeros on the packet buffer
		memset (data, '0', numCharDatagram);
		//Data part
		//strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
		packetIterator += numCharDatagram*sizeof(char);
		remainingBytes -= numCharDatagram*sizeof(char);

		sin.sin_family = AF_INET;
		sin.sin_port = htons(8080);
		u_int32_t source_address = htonl((((0x00000000 | *sourceIP<<24) | *(sourceIP+1)<<16) | *(sourceIP+2)<<8) | *(sourceIP+3));
		u_int32_t destination_address = htonl((((0x00000000 | *dstIP<<24) | *(dstIP+1)<<16) | *(dstIP+2)<<8) | *(dstIP+3));
		sin.sin_addr.s_addr = destination_address;

		// Fill in the fields of the IP Header
		iph->ihl = 5;
		iph->version = 4;
		iph->tos = 0;
		iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data));
		iph->id = htons (cont); //Id of this packet
		cont++;
		iph->frag_off = 0;
		iph->ttl = 255;
		iph->protocol = IPPROTO_UDP;
		iph->saddr = source_address;	//Spoof the source ip address
		iph->daddr = destination_address;

		//IP checksum
		iph->check = checksum((uint8_t*) iph, sizeof(iph));

		// Fill in the fields of the UDP header
		udph->source = htons (6666);
		udph->dest = htons (8622);
		udph->len = htons(sizeof(struct udphdr) + strlen(data)); //udp header size
		udph->check = 0; //leave checksum 0 now, filled later by pseudo header
	
		// Now the UDP checksum using the pseudo header
		psh.source_address = source_address;
		psh.dest_address = destination_address;
		psh.placeholder = 0;
		psh.protocol = IPPROTO_UDP;
		psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );
		int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
		pseudogram = malloc(psize);

		memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
		memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));

		udph->check = checksum( (uint8_t*) pseudogram , psize);
		free(pseudogram);
	}

	// we are building a A-MPDU. Defined in page 812 of IEEE 802.11-2012
	else {	// numFrames!=0

		for(int i = 0; i<numFrames; i++)	//for every subframe
		{
			assert( remainingBytes >= sizeof(struct mpdu_delimiter));
			struct mpdu_delimiter* delim = (struct mpdu_delimiter*) packetIterator;
			packetIterator += sizeof(*delim);
			remainingBytes -= sizeof(*delim);

			if ( debug_level > 0 )
				printf("Sub-frame #%i: MPDU size: %i bytes\n", i+1, MPDUsize);

			// uint16_t aux = 0x4004;// MPDUsize/8 & 0x0fff; //POSSIBLE ERROR HERE?
			uint16_t aux = htons (MPDUsize & 0x0fff); // the operation & 0x0fff is for making the first 4 bits be 0
					// QUESTION: Should we use htons or not???
					//uint16_t aux = MPDUsize & 0x0fff; // the operation & 0x0fff is for making the first 4 bits be 0

			// printf("aux = %04x\n", aux);
			
			// add the A-MPDU delimiter
			// - reserved
			// - MPDU length
			// - CRC
			// - Delimiter signature
			delim->reservedAndLength = htons(aux);
			uint8_t crc = 0xff;
			crc8(&crc, ((delim->reservedAndLength&0xff00)>>8));
			crc8(&crc, (delim->reservedAndLength&0x00ff));
			delim->crc = 0x47;
			//printf("%02x\n", delim->crc);
			delim->delimiterSignature = 0x4E;
			//printf("%02x\n", delim->delimiterSignature);
			uint8_t* MPDUStart = packetIterator; //Pointer to know where the mpdu starts
			assert( remainingBytes >= sizeof(struct ieee80211_htframe_addr4) );
			struct ieee80211_htframe_addr4* dot80211 = (struct ieee80211_htframe_addr4*) packetIterator;
			packetIterator += sizeof(*dot80211);
			remainingBytes -= sizeof(*dot80211);
	
			// Data packet flags
			dot80211->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_QOS;
			//printf("%i\n", *dot80211->i_fc);
			dot80211->i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
			//printf("%i\n", *dot80211->i_fc);
			//Add by CHdezFdez as an example
			dot80211->i_dur[0] = 0x00;
			dot80211->i_dur[1] = 0x00;
			// Destination 
			memcpy( dot80211->i_addr1, destinationMAC, IEEE80211_ADDR_LEN );
			// Source = our own mac address
			memcpy( dot80211->i_addr2, apDescription->macAddress, IEEE80211_ADDR_LEN );
			// BSS = our mac address
			memcpy( dot80211->i_addr3, apDescription->macAddress, IEEE80211_ADDR_LEN );
			// Sequence control
			dot80211->i_seq[0] = seqnumber[0]&0xf0;
			dot80211->i_seq[1] = seqnumber[1];
			if(i==0)
			{
				firstSequence[0]=seqnumber[0];
				firstSequence[1]=seqnumber[1];
			}
			if(seqnumber[0]<0xf0)
			{
				seqnumber[0] += (1<<4);
			} else {
				seqnumber[0]=0;
				seqnumber[1]++;
			}

			dot80211->i_qos[0] = 0x00;
			dot80211->i_qos[1] = 0x00;

			// Add the LLC header. see https://en.wikipedia.org/wiki/IEEE_802.2
			assert(remainingBytes >= sizeof(struct llc) );
			struct llc* llchdr = (struct llc*) packetIterator;
			packetIterator += sizeof(*llchdr);
			remainingBytes -= sizeof(*llchdr);

			llchdr->DSAP = 0xAA;		// destination SAP (Service Access Point)
							// AA means 'SNAP Extension Used'
			llchdr->SSAP = 0xAA;		// source SAP (Service Access Point)
			llchdr->control = 0x03;

			// Add the SNAP header. see https://en.wikipedia.org/wiki/Subnetwork_Access_Protocol
			assert(remainingBytes >= sizeof(struct snap) );
			struct snap* snaphdr = (struct snap*) packetIterator;
			packetIterator += sizeof(*snaphdr);
			remainingBytes -= sizeof(*snaphdr);

			snaphdr->OID1 = 0x0000;		// 3-octet IEEE Organizationally Unique Identifier (OUI) 
							// followed by a 2-octet protocol ID. If the OUI is hexadecimal 000000, 
							// the protocol ID is the Ethernet type (EtherType) field value for 
							// the protocol running on top of SNAP
			snaphdr->OID2 = 0x00;
			snaphdr->protocolID = htons(0x0800);	// 0x0800 means Internet Protocol version 4 (IPv4)
								// see https://en.wikipedia.org/wiki/EtherType

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
			//strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
			packetIterator += numCharDatagram*sizeof(char);
			remainingBytes -= numCharDatagram*sizeof(char);

			sin.sin_family = AF_INET;
			sin.sin_port = htons(8080);
			u_int32_t source_address = htonl((((0x00000000 | *sourceIP<<24) | *(sourceIP+1)<<16) | *(sourceIP+2)<<8) | *(sourceIP+3));
			u_int32_t destination_address = htonl((((0x00000000 | *dstIP<<24) | *(dstIP+1)<<16) | *(dstIP+2)<<8) | *(dstIP+3));
			sin.sin_addr.s_addr = destination_address;
 
			// Fill in the IP Header
			iph->ihl = 5;
			iph->version = 4;
			iph->tos = 0x00;
			iph->tot_len = (sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data));
			iph->id = htons(cont); //Id of this packet
			cont++;
			iph->frag_off = 0;
			iph->ttl = 255;
			iph->protocol = IPPROTO_UDP;
			iph->saddr = source_address;	//Spoof the source ip address
			iph->daddr = destination_address;

			// IP checksum
			iph->check = checksum((uint8_t*) iph, iph->tot_len);
	
			// UDP header
			udph->source = htons (6666);
			udph->dest = htons (8622);
			udph->len = htons(sizeof(struct udphdr) + strlen(data)); //udp header size
			udph->check = 0; //leave checksum 0 now, filled later by pseudo header
	
			// Now add the UDP checksum using the pseudo header
			psh.source_address = source_address;
			psh.dest_address = destination_address;
			psh.placeholder = 0;
			psh.protocol = IPPROTO_UDP;
			psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );
		
			int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
			pseudogram = malloc(psize);

			memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
			memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));

			udph->check = checksum( (uint8_t*) pseudogram , psize);
			free(pseudogram);

			assert( remainingBytes >= sizeof(struct FCS ) );
			struct FCS* fcsField = (struct FCS *) packetIterator;
			packetIterator += sizeof(*fcsField);
			remainingBytes -= sizeof(*fcsField);

			fcsField->FCSvalue = crc32(MPDUsize, MPDUStart);

			if (zeropadding!=0)
			{
				assert( remainingBytes >= zeropadding);
				char* padding = (char*) packetIterator;
				memset(padding, 0, zeropadding);
				packetIterator += zeropadding*sizeof(char);
				remainingBytes -= zeropadding*sizeof(char);
			}
		}
	}
	assert( remainingBytes == 0 );
	//packet_hexdump( (const uint8_t*) packet, *DataLength );
}

void constructBARequest (uint8_t* packet, uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* BALength, const uint8_t* destinationMAC)
{

	//uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	//assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 );

	assert( packet != NULL );
		
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
	assert( remainingBytes >= sizeof(struct ieee80211_baframe) );
	struct ieee80211_baframe* dot80211 = (struct ieee80211_baframe*) packetIterator;
	packetIterator += sizeof(*dot80211);
	remainingBytes -= sizeof(*dot80211);
	
	// BARequest packet flags
	dot80211->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_BAR;
	//printf("%i\n", *dot80211->i_fc);
	//dot80211->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	//printf("%i\n", *dot80211->i_fc);
	//Add by CHdezFdez as an example
	dot80211->i_dur[0] = 0x00;
	dot80211->i_dur[1] = 0x00;
	// Destination 
	memcpy( dot80211->i_addr1, destinationMAC, IEEE80211_ADDR_LEN );
	// Source = our own mac address
	memcpy( dot80211->i_addr2, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// BSS = our mac address
	
	// Add the BARequest frame
	assert( remainingBytes >= sizeof(struct ieee80211_ba_request) );
	struct ieee80211_ba_request* BAR = (struct ieee80211_ba_request*) packetIterator;
	packetIterator += sizeof(*BAR);
	remainingBytes -= sizeof(*BAR);
	
	BAR->BA_control = htons(0x01)>>8;
	BAR->BA_seq = (uint16_t)firstSequence[1]<<8|(firstSequence[0]&0xf0);

	assert( remainingBytes == 0 );
	//packet_hexdump( (const uint8_t*) packet, *beaconLength );

}


// ADD MORE ACCESS POINTS HERE, IF YOU WANT
static struct AccessPointDescriptor ap0 = {
	{ 0x60, 0xe3, 0x27, 0x1d, 0x32, 0xb7 },
	(const uint8_t*) "ap0", 3,
	IEEE80211_DEFAULT_RATES, IEEE80211_DEFAULT_RATES_LENGTH,
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
	printf( "fakeaps [raw device name (e.g. 'wlan0')] [802.11 channel] [Packet size at IP level (should be 28 or more)] [number of frames in each A-MPDU (0 means 'no frame aggregation')] [number of A-MPDUs to send] [destination IP address using (.)] [destination MAC address using (:)]\n" );
	printf( "NOTE: if the 'number of frames in each A-MPDU' is 0, then the 'number of A-MPDUs to send' will be the number of frames\n"); 
	printf( "\n");
}


int main(int argc, char *argv[])
{
	if ( argc != 8 )
	{
		help();
		return 1;
	}

	int dump_packets = DUMP_PACKETS;
	int debug_level = DEBUG_LEVEL;

	int fd;
 	struct ifreq ifr;
 	fd = socket(AF_INET, SOCK_DGRAM, 0);

 	/* I want to get an IPv4 IP address */
 	ifr.ifr_addr.sa_family = AF_INET;

 	/* I want IP address attached to the selected interface */
 	strncpy(ifr.ifr_name, argv[1], IFNAMSIZ-1);
 	ioctl(fd, SIOCGIFADDR, &ifr);
 	close(fd);

	// Read the source IP
 	u_int8_t sourceIP[4];
 	parseIPAddresses(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), &sourceIP[0]);

	// Read the destination IP (it is one of the program arguments)
	u_int8_t dstIP[4];
	parseIPAddresses(argv[6], &dstIP[0]);

	// Read the MAC address (it is one of the program arguments)
	u_int8_t dstMAC[6];
	parseMACAddresses(argv[7], &dstMAC[0]);

	uint8_t channel = strtol( argv[2], NULL, 10 );
	if ( channel <= 0 || 255 <= channel )
	{
		printf( "The channel must be between 1 and 255.\n" );
		help();
		return 1;
	}

	// Read the size of each packet at IP level (including IP header) //QUESTION
	int packet_size = atoi(argv[3]);

	// Read the number of frames to be included in each A-MPDU
	uint8_t numFrames = atoi(argv[4]);

	// Read the number of A-MPDUs to be sent
	uint8_t numPcks = atoi(argv[5]);

	// Define the data rate (in multiples of 500kbps. e.g. 108 means 54Mbps)
	const uint8_t dataRate = 108;

	// Read the name of the local wireless device to use
	const char* device = argv[1];

	// Construct the beacon frames
	// Packet size: radiotap header + 1 byte for rate + ieee80211_frame header + beacon info + tags
	size_t beaconLength = sizeof(struct ieee80211_radiotap_header) + sizeof(dataRate) + sizeof(struct ieee80211_frame) + sizeof(struct ieee80211_beacon) +
	// SSID, rates, channel
	sizeof(struct ieee80211_info_element)*7 + accessPoints[0]->ssidLength + accessPoints[0]->dataRatesLength + sizeof(channel) + sizeof(struct HTCapabilities) +
	IEEE80211_EXTENDED_RATES_LENGTH + sizeof(struct HTInfo) + sizeof(struct vendor);

	// Construct the probe response
	size_t probeResponseLength = sizeof(struct ieee80211_radiotap_header) + sizeof(dataRate) + sizeof(struct ieee80211_frame) + sizeof(struct ieee80211_beacon) +
	// SSID, rates, channel
	sizeof(struct ieee80211_info_element)*7 + accessPoints[0]->ssidLength + accessPoints[0]->dataRatesLength + sizeof(channel) + sizeof(struct HTCapabilities) +
	IEEE80211_EXTENDED_RATES_LENGTH + sizeof(struct HTInfo) + sizeof(struct vendor);

	// Construct the ACK
	//size_t ACKLength = sizeof(struct ieee80211_radiotap_header) + sizeof(dataRate) + sizeof(struct ieee80211_frame_ack);
	size_t authLength = sizeof(struct ieee80211_radiotap_header) + sizeof(dataRate) + sizeof(struct ieee80211_frame) + sizeof(struct ieee80211_authentication);
	size_t assoLength = sizeof(struct ieee80211_radiotap_header) + sizeof(dataRate) + sizeof(struct ieee80211_frame) + sizeof(struct ieee80211_association_response) +
	// SSID, rates, channel
	sizeof(struct ieee80211_info_element)*7 + accessPoints[0]->ssidLength + accessPoints[0]->dataRatesLength + sizeof(channel)  + sizeof(struct HTCapabilities) +
	IEEE80211_EXTENDED_RATES_LENGTH + sizeof(struct HTInfo) + sizeof(struct vendor);

	// Construct the AddBA
	size_t addBALength = sizeof(struct ieee80211_radiotap_header) + sizeof(dataRate) + sizeof(struct ieee80211_frame) + sizeof(struct ieee80211_addba_request) +
	
	// SSID
	sizeof(struct ieee80211_info_element) + accessPoints[0]->ssidLength;

	// Calculate the size of the payload
	int numCharDatagram = packet_size - sizeof(struct iphdr) - sizeof(struct udphdr); //Total IP length - IP Header -UDP Header
	int zeropadding = 0;

	int MPDUsize =	sizeof(struct ieee80211_htframe_addr4)+
			sizeof(struct llc)+
			sizeof(struct snap)+
			sizeof(struct iphdr)+
			sizeof(struct udphdr)+
			numCharDatagram*sizeof(char)+
			sizeof(struct FCS);

	// Add the padding if needed
	if((MPDUsize%4)!=0)
	{
		zeropadding = (4-(MPDUsize%4));
	}

	size_t dataLength;

	// If numFrames == 0 this means that I am sending normal frames
	if (numFrames == 0)
	{
		dataLength =	sizeof(struct ieee80211_radiotap_header) + 
				sizeof(dataRate) + 
				sizeof(struct ieee80211_htframe_addr4) + 
				sizeof(struct llc) + 
				sizeof(struct snap) + 
				sizeof(struct iphdr) + 
				sizeof(struct udphdr) + 
				numCharDatagram*sizeof(char);

	// If numFrames !=0, I have to add the length of the A-MPDU specific fields
	} 
	else {
										// The PLCP header is built automatically so we don't have to count it
		dataLength =	sizeof(struct ieee80211_radiotap_header) +	// Radiotap header goes first
				sizeof(dataRate) +				// It is an element of the Radiotap header
				16-(sizeof(dataRate)%16) +			// I have to align the Radiotap header
				sizeof(struct ampdu_status) +			// It is an element of the Radiotap header
				numFrames * (	sizeof(struct mpdu_delimiter) +		//A-MPDU delimiter
						sizeof(struct ieee80211_htframe_addr4) +	// Includes type, subtype, duration, MAC headers, sequence, QoS
											// QUESTION: Do we need HT Ctl field?
						sizeof(struct llc) +			// The MSDU starts with LLC and SNAP
						sizeof(struct snap) + 
						sizeof(struct iphdr) +			// IPv4 header
						sizeof(struct udphdr) +			// UDP header
						numCharDatagram*sizeof(char) +		// Payload
						sizeof(struct FCS) +	//FCS 
											// QUESTION: do we have to include FCS length here? (2 bytes)
						zeropadding				// Padding after the MPDU
						);


		/*
		dataLength +=	(16-(sizeof(dataRate)%16)) +	// 
				sizeof(struct ampdu_status) + 
				(numFrames-1)*(	sizeof(struct ieee80211_htframe_addr4) + 
						sizeof(struct llc) +
						sizeof(struct snap) + 
						sizeof(struct iphdr) + 
						sizeof(struct udphdr) + 
						numCharDatagram*sizeof(char) 
						);
						*/
	}

	// Length of a data frame if no aggregation is used
	size_t dataLengthWithoutAggr =	sizeof(struct ieee80211_radiotap_header) + 
					sizeof(dataRate) + 
					sizeof(struct ieee80211_htframe_addr4) +
					sizeof(struct llc) + 
					sizeof(struct snap) + 
					sizeof(struct iphdr) + 
					sizeof(struct udphdr) + 
					numCharDatagram*sizeof(char);

	// Size of the Block ACK Request
	size_t BARLength =	sizeof(struct ieee80211_radiotap_header) + 
				sizeof(dataRate) + 
				sizeof(struct ieee80211_baframe) + 
				sizeof(struct ieee80211_ba_request);

	// Open the raw device
	int rawSocket = openSocket( device );
	if ( rawSocket < 0 )
	{
		fprintf( stderr, "error opening socket\n" );
		return 1;
	}
	uint8_t* beaconPacket = (uint8_t*) malloc( beaconLength );
	constructBeaconPacket(beaconPacket, dataRate, channel, accessPoints[0], &beaconLength );
	assert( beaconPacket != NULL );
	assert( beaconLength > 0 );

	ssize_t bytes = write( rawSocket, beaconPacket, beaconLength);
	//printf("Beacon sent\n");
	//packet_hexdump( (const uint8_t*) beaconPacket, beaconLength );
	assert( bytes == (ssize_t) beaconLength );
	if ( bytes < (ssize_t) beaconLength )
	{
		perror( "error sending packet" );
		return 1;
	}
	free(beaconPacket);


	
	// Configure the initial timeout
	struct timeval now;
	int code = gettimeofday( &now, NULL );
	assert( code == 0 );
	
	struct timeval beaconTime = now;
	incrementTimeval( &beaconTime, BEACON_INTERVAL );

	init_crc8();
	
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
			if( bytes >= radiotap->it_len ){
				uint8_t* packetIterator = packetBuffer + radiotap->it_len;
				size_t remainingBytes = bytes - radiotap->it_len;
			
				// Get the 802.11 frame:
				// NOTE: This frame structure is larger than some packet types, so only read the initial bytes
				struct ieee80211_frame* frame = (struct ieee80211_frame*)( packetIterator );

				// check if the MAC addresses fit with ours
				if (	*frame->i_addr2 == dstMAC[0] && 
					*(frame->i_addr2+1) == dstMAC[1] && 
					*(frame->i_addr2+2) == dstMAC[2] && 
					*(frame->i_addr2+3) == dstMAC[3] &&
					*(frame->i_addr2+4) == dstMAC[4] && 
					*(frame->i_addr2+5) == dstMAC[5])
				{
					// Check to see if this is a PROBE_REQUEST
					//assert( (frame->i_fc[0] & IEEE80211_FC0_VERSION_MASK) == IEEE80211_FC0_VERSION_0 ); //Delete to receive other kinds of packets.
					if (	(frame->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_MGT &&
						(frame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_PROBE_REQ )
					{
						// To get sure that it received a probe request
						//printf("Probe Request received\n");
						//packet_hexdump( (const uint8_t*) frame, remainingBytes );

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
							uint8_t* probeResponsePacket = (uint8_t*) malloc( probeResponseLength );
							// build the probe response
							constructProbeResponse(	probeResponsePacket ,
										dataRate, 
										channel, 
										accessPoints[0], 
										&probeResponseLength, 
										frame->i_addr2 );
							
							// send the probe response
							bytes = write( rawSocket, probeResponsePacket, probeResponseLength);
							assert(bytes == (ssize_t) probeResponseLength);

							if (debug_level > 1) 
								printf("Probe response sent\n");

							if (dump_packets == 2)
								packet_hexdump((const uint8_t*) probeResponsePacket, probeResponseLength);
							
							free(probeResponsePacket);
						}
						else {
							// it is not a broadcast SSID, so it is unicast
							// Check if the SSID matches any of ours
							// If it does, send the response
							for ( size_t i = 0; i < numAccessPoints; ++ i )
							{
								if ( info->info_length == accessPoints[i]->ssidLength && memcmp( info->info, accessPoints[i]->ssid, info->info_length ) == 0 )
								{
									// It does!
									//printf( "probe for SSID '%.*s'\n", info->info_length, (char*) info->info );
									uint8_t* probeResponsePacket = (uint8_t*) malloc( probeResponseLength );
									// build the probe response
									constructProbeResponse (	probeResponsePacket ,
													dataRate, 
													channel, 
													accessPoints[i], 
													&probeResponseLength, 
													frame->i_addr2 );
									//send the probe response
									bytes = write( rawSocket, probeResponsePacket, probeResponseLength);
									assert(bytes == (ssize_t) probeResponseLength);

									if (debug_level > 1) 
										printf("Probe response sent\n");

									if (dump_packets == 2)
										packet_hexdump((const uint8_t*) probeResponsePacket, probeResponseLength);

									free(probeResponsePacket);
									break;
								}
							}
						}	
					}

					// Check if it is an Authentication Request
					else if( (frame->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_MGT &&
						(frame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_AUTH ) // We received an Authentication Request
					{
						packetIterator += sizeof(struct ieee80211_frame);
						struct ieee80211_authentication* authFrame = (struct ieee80211_authentication*)( packetIterator );

						if(authFrame->seq == IEEE80211_AUTH_OPEN_REQUEST)
						{
							/*uint8_t* ACKpacket = (uint8_t*) malloc( ACKLength );
							constructACKPacket(ACKPacket, dataRate, channel, accessPoints[0], &ACKLength, frame->i_addr2);
							ssize_t bytes = write( rawSocket, ACKPacket, ACKLength );
							assert( bytes == (ssize_t) ACKLength );
							//printf("ACK sent\n");
							//packet_hexdump( (const uint8_t*) ACKPacket, ACKLength );
							free(ACKPacket);*/
						
							uint8_t* authPacket = (uint8_t*) malloc( authLength );
							// build the Authentication Response
							constructAuthResponse (	authPacket ,
										dataRate, 
										channel, 
										accessPoints[0], 
										&authLength, 
										frame->i_addr2 );
							// send the Authentication Response
							bytes = write( rawSocket, authPacket, authLength);
							assert(bytes == (ssize_t) authLength);

							if (debug_level > 1) 
								printf("Authentication response sent\n");

							if (dump_packets == 2)
								packet_hexdump((const uint8_t*) authPacket, authLength);

							free(authPacket);
						}
					}

					// Check if it is an Association Request
					else if( (frame->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_MGT &&
						(frame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_ASSOC_REQ )
					{
						/*uint8_t* ACKpacket = (uint8_t*) malloc( ACKLength );
						constructACKPacket(ACKPacket, dataRate, channel, accessPoints[0], &ACKLength, frame->i_addr2);
						ssize_t bytes = write(rawSocket,ACKPacket,ACKLength);
						assert(bytes == (ssize_t) ACKLength);
						//printf("ACK sent\n");
						//packet_hexdump( (const uint8_t*) ACKPacket, ACKLength);
						free(ACKPacket);*/

						uint8_t* assoPacket = (uint8_t*) malloc( assoLength );
						// Build the Association Response
						constructAssoResponse (	assoPacket, 
									dataRate, 
									channel, 
									accessPoints[0], 
									&assoLength, 
									frame->i_addr2);
						// Send the Association Response
						bytes = write(rawSocket, assoPacket, assoLength);
						assert(bytes== (ssize_t) assoLength);
						//printf("Association Response\n");
						//packet_hexdump( (const uint8_t*) assoPacket, assoLength);
						free(assoPacket);

						// THE STATION IS NOW ASSOCIATED WITH THE AP, SO THE PROCESS TO SEND AMPDUs CAN START NOW
						// - if numFrames == 0, I will not send AMPDUs, so I can send the traffic now
						// - if numFrames != 0, I first have to send the ADDBA Request

						// The number of sub-frames is not null, so I have to send an ADDBA Request
						if(numFrames!=0)
						{
							uint8_t* ADDBAPacket = (uint8_t*) malloc( addBALength );
							// build the ADDBA Request
							constructADDBARequest (	ADDBAPacket, 
										dataRate, 
										channel, 
										accessPoints[0], 
										&addBALength, 
										frame->i_addr2);
							// send the ADDBA Request
							bytes = write(rawSocket, ADDBAPacket, addBALength);
							assert(bytes == (ssize_t) addBALength);

							if (debug_level > 1) 
								printf("ADDBA Request sent\n");

							if (dump_packets == 2)
								packet_hexdump( (const uint8_t*) ADDBAPacket, addBALength);

							free(ADDBAPacket);
						}

						// The number of frames is 0, which means NO AGGREGATION, i.e. only an MPDU per packet must be sent
						// if the 'number of frames in each A-MPDU' is 0, then the 'number of A-MPDUs to send' will be the number of frames
						else {
							for(int i=0; i < numPcks; i++)
							{
								// Construct and send a frame with a single MPDU
								uint8_t* dataPacket = (uint8_t*) malloc( dataLengthWithoutAggr );
								constructDataPacket(	dataPacket, 
											dataRate, 
											channel, 
											accessPoints[0], 
											&dataLengthWithoutAggr, 
											sourceIP, 
											dstIP,
											frame->i_addr2, 
											0, 
											numCharDatagram);
								// send the MPDU
								bytes = write(rawSocket, dataPacket, dataLengthWithoutAggr);
								assert(bytes== (ssize_t) dataLengthWithoutAggr);
								
								if (debug_level > 0) 
									printf("##### Frame #%i (not aggregated)\n", i+1);
								
								if (dump_packets > 0)
									packet_hexdump( (const uint8_t*) dataPacket, dataLengthWithoutAggr);

								free(dataPacket);
							}
						}				
					}

					// Check if an Action Frame has been received. ADDBA responses are a subtype of Action Frames
					else if( (frame->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_MGT &&
						(frame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_ACTION )
					{

						packetIterator += sizeof(struct ieee80211_frame);
						struct ieee80211_addba_response* addbaResponseFrame = (struct ieee80211_addba_response*)( packetIterator );

						//I check if the received frame is an ADDBA Response, which means that I can now send A-MPDUs
						if(addbaResponseFrame->category == IEEE80211_CATEG_BA && addbaResponseFrame->actionCode == IEEE80211_ACTION_ADDBA_RESP)
						{
							if(addbaResponseFrame->status == 0) // I check the status to know if the receiver can send Block Ack
							{ 
								/*uint8_t* ACKpacket = (uint8_t*) malloc( ACKLength );
								ACKPacket=constructACKPacket(dataRate, channel, accessPoints[0], &ACKLength, frame->i_addr2);
								ssize_t bytes = write( rawSocket, ACKPacket, ACKLength );
								assert( bytes == (ssize_t) ACKLength );
								//printf("ACK sent\n");
								//packet_hexdump( (const uint8_t*) ACKPacket, ACKLength );
								free(ACKPacket);*/
							
								// this is repeated 'numPcks' times
								for(int i=0; i<numPcks; i++) {
									// Construct and send A-MPDU
									if (debug_level > 0)
										printf("##### Multi-frame #%i\n", i+1);

									// Create the frame
									uint8_t* dataPacket = (uint8_t*) malloc( dataLength );
									constructDataPacket (	dataPacket,
												dataRate, 
												channel, 
												accessPoints[0], 
												&dataLength, 
												sourceIP, 
												dstIP ,
												frame->i_addr2, 
												numFrames, 
												numCharDatagram);

									// Send the frame
									bytes = write(rawSocket, dataPacket, dataLength);
									assert(bytes== (ssize_t) dataLength);

									if (dump_packets > 0 )
										packet_hexdump( (const uint8_t*) dataPacket, dataLength);

									free(dataPacket);
												
									// Construct and send Block ACK request
									uint8_t* BARPacket = (uint8_t*) malloc( BARLength );
									constructBARequest(BARPacket, dataRate, channel, accessPoints[0], &BARLength, frame->i_addr2);
									bytes = write( rawSocket, BARPacket, BARLength);
									assert( bytes == (ssize_t) BARLength);

									if (debug_level > 0)
										printf("Block ACK Request %i sent\n", i+1);

									if (dump_packets == 2)
										packet_hexdump( (const uint8_t*) BARPacket, BARLength);

									free(BARPacket);
									printf("\n");
								}
							}

							// the receiver cannot send Block Ack
							else {
								perror("Device unable to perform frame aggregation");
							}
						}
					}
				}
			} 
			else {

			}
		} 
		else {
			// We should only have 1 or 0 fds (File descriptors) ready
			assert( numFds == 0 );
		}
			
		// Get the current timestamp to calculate how much longer we need to wait
		// or if we need to send a beacon now
		int code = gettimeofday( &now, NULL );
		assert( code == 0 );
		
		if ( compareTimeval( &beaconTime, &now ) <= 0 )
		{
			//~ printf( "beacon\n" );
			// The timeout has expired. Send out the beacons
		
			//Rebuild the beacon to update the timestamp
			uint8_t* beaconPacket = (uint8_t*) malloc( beaconLength );
			constructBeaconPacket(beaconPacket, dataRate, channel, accessPoints[0], &beaconLength );

			assert( beaconPacket != NULL );
			assert( beaconLength > 0 );

			//printf("Prueba: %zu\n",beaconLength);
			ssize_t bytes = write( rawSocket, beaconPacket, beaconLength);
			//printf("Beacon sent\n");
			//packet_hexdump( (const uint8_t*) beaconPacket, beaconLength );
			assert( bytes == (ssize_t) beaconLength );
			if ( bytes < (ssize_t) beaconLength )
			{
				perror( "error sending packet" );
				return 1;
			}
			free(beaconPacket);

			// Increment the next beacon time until it is in the future
			do {
				incrementTimeval( &beaconTime, BEACON_INTERVAL );
			} while( compareTimeval( &beaconTime, &now ) <= 0 );
		}
	}
	close( rawSocket );
}