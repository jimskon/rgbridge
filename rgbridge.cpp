/* rgbridge */

#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */

#ifndef __NetBSD__
#include <linux/if.h>
#include <linux/if_tun.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <map>
#include <time.h>
#include <unistd.h>
#include <iostream>
#include <iomanip>
#include <sys/select.h>

using namespace std;

/* A mac address class */
class MACADDR {
  public:
    unsigned char mac[6]={0};
    MACADDR() {}
    MACADDR(unsigned char a[6]) {
      for (int i=0; i<6; i++) {
        mac[i]=a[i];
      }
    }
    
    void set(unsigned char a[6]) {
      for (int i=0; i<6; i++) {
        mac[i]=a[i];
      }
    }
    bool operator<(const MACADDR a) const {
      for (int i=0; i<6; i++) {
        if (a.mac[i] < this->mac[i])
          return false;
        if (a.mac[i] > this->mac[i])
          return true;
      }
      return false;
    }
    bool operator=(const MACADDR a) const {
      for (int i=0; i<6; i++) {
        if (a.mac[i]!=this->mac[i])
          return false;
      }
      return true;
    }
    void print() const {
      cout << hex;
      for (int i=0; i<6; i++) {
        cout << (int) this->mac[i] << ' ';
      }
      cout << dec;
    }
    bool is_broadcast() {
      for (int i=0; i<6; i++) {
        if (mac[i]!=0xff) return false;
      }
      return true;
    }

    bool is_multicast() {

      if (mac[0] & 0x01) {
      return true;
      }
    return false;
    }

    void get_dest_mac(unsigned char *packet)   {
        for (int i=0; i<6; i++) {
          mac[i]=packet[i];
        }
    }

    void get_src_mac(unsigned char *packet)   {
        for (int i=0; i<6; i++) {
          mac[i]=packet[i+6];
        }
    }

  void random_mac() {
    int i,tp;
    for (i = 0; i < 6; i++) {
      mac[i] = rand() % 256;
    }
  }
};

/* A bridge entry class */
class Bridge_entry {
  public:
    short src_interface;
    short vlanid;
  Bridge_entry(short src, short v) {
      src_interface = src;
      vlanid = v;
    }
    Bridge_entry(short src) {
      src_interface = src;
      vlanid = 0;
    }
    Bridge_entry() {
      src_interface = 0;
      vlanid = 0;
    }
};

void print_bridge(map<MACADDR,Bridge_entry> *bridge_map) {
  map<MACADDR,Bridge_entry>::iterator it = bridge_map->begin();
  cout << "Bridge table (" << bridge_map->size() << ")\n";
  for(; it != bridge_map->end(); it++)
    {
      it->first.print();
      cout << " :: " << it->second.src_interface << endl;
    }
}

bool dup_pkt(unsigned char *pkt1, int size1, unsigned char *pkt2, int size2) {
  if (size1 != size2)
    return false;
  return !memcmp(pkt1,pkt2,size1);
}
  

/* Transparent bridge
   returns:   0: broadcast
              1-n - dest interface
              -1 - not found, drop
  */
int bridge_packet(map<MACADDR,Bridge_entry> *bridge_map,int pkt_src, unsigned char *packet) {

  short dest_i = 0;
  MACADDR src_mac,dest_mac;
  src_mac.get_src_mac(packet);
  dest_mac.get_dest_mac(packet);

  /*  Process the source address.  Add if not in bridge.  update if interface is different 
      drop if broadcast from this interface */
  if (bridge_map->find(src_mac) != bridge_map->end()) {
    // check if changed 
    Bridge_entry b = bridge_map->find(src_mac)->second;

    int src_i = b.src_interface;
    if (src_i != pkt_src) {
      // update source
      b.src_interface=pkt_src;
      (*bridge_map)[src_mac]=b;
    }
  } else { 
    Bridge_entry new_entry(pkt_src);
    bridge_map->emplace(src_mac,new_entry);
  }

  if (dest_mac.is_multicast() || dest_mac.is_broadcast()) {
    dest_i = 0;
  } else {

    /* find where to send packet in the bridge */
    if (bridge_map->find(dest_mac) != bridge_map->end()) {
      dest_i=(*bridge_map)[dest_mac].src_interface;
    } else {
      dest_i=-1;
    }
  }
  // If we don't find the destination, just drop
  return dest_i;
}


void printpacket(const char* msg, const unsigned char* p, size_t len) {
    int i;
    printf("%s len=%d ", msg, len);
    for(i=0; i<len; ++i) {
        printf("%02x", p[i]);
    }
    printf("\n");
}

int parseMac(char* mac, u_int8_t addr[])
{
    int i;
    for (i = 0; i < 6; i++) {
        long b = strtol(mac+(3*i), (char **) NULL, 16);
        addr[i] = (char)b;
    }
    return 0;
}


void init_MAC_addr(int pf, char *interface, char *addr, int *card_index)
{
    struct ifreq card;

    strcpy(card.ifr_name, interface);

    if(!getenv("SOURCE_MAC_ADDRESS")) {
        if (ioctl(pf, SIOCGIFHWADDR, &card) == -1) {
            fprintf(stderr, "Could not get MAC address for %s\n", card.ifr_name);
            perror("ioctl SIOCGIFHWADDR");
            exit(1);
        }

        memcpy(addr, card.ifr_hwaddr.sa_data, 6);
    } else {
        parseMac(getenv("SOURCE_MAC_ADDRESS"), (unsigned char*)addr);
	}

    if (ioctl(pf, SIOCGIFINDEX, &card) == -1) {
        fprintf(stderr, "Could not find device index number for %s\n", card.ifr_name);
        perror("ioctl SIOCGIFINDEX"); 
        exit(1);
    }
    *card_index = card.ifr_ifindex;
}

// Interface Structure                                                              
struct interface {
  char name[100];
  int dev;
  int sock;
  char source_mac[6];
  int card_index;
  struct sockaddr_ll device;
};

void create_tap(char* name, struct interface *inter) {
    if((inter->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))==-1) {
      perror("socket() failed");
      exit(4);
    }
    strcpy(inter->name,name);
   
    memset(&inter->device, 0, sizeof(inter->device));
    init_MAC_addr(inter->sock, inter->name, inter->source_mac, &inter->card_index);
    inter->device.sll_ifindex=inter->card_index;

    cout << "Adding interface: " << inter->name << " Sock: " << inter->sock << " ";
    MACADDR mac1((unsigned char *) inter->source_mac);
    mac1.print();
    cout << endl;
    
    inter->device.sll_family = AF_PACKET;
    memcpy(inter->device.sll_addr, inter->source_mac, 6);
    inter->device.sll_halen = htons(6);
}

int main(int argc, char **argv)
{
    int cnt1,cntout1;
    int cnt2,cntout2;
    struct interface interfaces[3];
    unsigned char buf_frame1[1536+sizeof(struct ether_header)];
    unsigned char buf_frame2[1536+sizeof(struct ether_header)];
    unsigned char out_frame1[1536+sizeof(struct ether_header)];
    unsigned char out_frame2[1536+sizeof(struct ether_header)];
    /* The vlan bridge */
    map<MACADDR,Bridge_entry> bridge_map;
  
    int debug=0;

    if(getenv("DEBUG")) { debug = atoi(getenv("DEBUG")); }

    if(argc<=1) {
      fprintf(stderr,
	      "Usage: tap_interface interface\n"
	      "Example: tap_copy eth0\n"
	      "    DEBUG=0,1,2 print send and recv packets\n"
	      "    \n"
	      );
      exit(1);
    }
    cout << "DEBUG=" << debug << endl;

    // Tap 1                                                                        
    create_tap(argv[1],&interfaces[1]);
    // Tap 2                                                                        
    create_tap(argv[2],&interfaces[2]);

    int print_cnt=0;
    fcntl(interfaces[1].sock, F_SETFL, O_NONBLOCK);
    fcntl(interfaces[2].sock, F_SETFL, O_NONBLOCK);
    int maxfd = (interfaces[1].sock>interfaces[2].sock)?interfaces[1].sock:interfaces[2].sock;

    for (;;) {
      fd_set rfds;
      FD_ZERO(&rfds);
      FD_SET(interfaces[1].sock, &rfds);
      FD_SET(interfaces[2].sock, &rfds);
      int sel_ret = select(maxfd+1, &rfds, NULL, NULL, NULL);
      
      if (sel_ret<0) continue;
      while (FD_ISSET(interfaces[1].sock, &rfds)) {
	// Read from interface1 and send to interface2
	size_t size1 = sizeof interfaces[1].device;
	cnt1=recvfrom(interfaces[1].sock,buf_frame1,1536,0,(struct sockaddr *)&interfaces[1].device,&size1);
	if(cnt1<0) {
	  break;
	}
	if(interfaces[1].device.sll_ifindex != interfaces[1].card_index) {
	  break; /* Not our interface */
	}
	// Check for dup of what we sent
	if (dup_pkt(buf_frame1,cnt1,out_frame2,cntout2)) {
	  cout << " DUP12 " << cnt1 << endl;	  break;
	}
	if (dup_pkt(buf_frame1,cnt1,out_frame1,cntout1)) {
	  cout << " DUP11 " << cnt1 << endl;
	  break;
	}
	short forward_to1 = bridge_packet(&bridge_map,1,buf_frame1);
	if (forward_to1 == 1 || forward_to1 == -1) {
	  break;
	}
	if(debug==1) {
	  cout << "F1>" << forward_to1 << endl;
	}
	if(debug==2 ) printpacket("1 to 2", buf_frame1, cnt1);

	// Save frame to watch for it coming back in
	memcpy(out_frame2,buf_frame1,cnt1);
	cntout2 = sendto(interfaces[2].sock, buf_frame1, cnt1,0,(struct sockaddr *)&interfaces[2].device, sizeof interfaces[2].device);
	cout << "Sent2: " << cntout2 << endl;
	if (print_cnt++%10==0)
	  print_bridge(&bridge_map);
	break;
      }

      while (FD_ISSET(interfaces[2].sock, &rfds)) {
	// Read from interface1 and send to interface2
	size_t size2 = sizeof interfaces[2].device;
	cnt2=recvfrom(interfaces[2].sock,buf_frame2,1536,0,(struct sockaddr *)&interfaces[2].device,&size2);
	if(cnt2<0) {
	  break;
	}
	if(interfaces[2].device.sll_ifindex != interfaces[2].card_index) {
	  break; /* Not our interface */
	}
	// Check for dup of what we sent
	if (dup_pkt(buf_frame2,cnt2,out_frame2,cntout2)) {
	  cout << " DUP22 " << cnt2 << endl;
	  break;
	}
	if (dup_pkt(buf_frame2,cnt2,out_frame1,cntout1)) {
	  cout << " DUP21 " << cnt2 << endl;
	  break;
	}
	short forward_to2 = bridge_packet(&bridge_map,2,buf_frame2);
	if (forward_to2 == 2 || forward_to2 == -1) {
	  break;
	}
	if(debug==1) {
	  cout << "F2>" << forward_to2 << endl;
	}
	if(debug==2 ) printpacket("2 to 1", buf_frame2, cnt2);

	// Save frame to watch for it coming back in
	memcpy(out_frame1,buf_frame2,cnt2);
	cntout1 = sendto(interfaces[1].sock, buf_frame2, cnt2,0,(struct sockaddr *)&interfaces[1].device, sizeof interfaces[1].device);
	cout << "Sent1: " << cntout1 << endl;

	continue;
      }

    }
}
