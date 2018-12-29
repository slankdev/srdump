
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <time.h>
#include <slankdev/extra/pcap.h>
#include <slankdev/hexdump.h>
#include <slankdev/net/hdr.h>
#include <slankdev/net/addr.h>
#include <string>
#include "argparse/argparse.hpp"

static inline size_t
get_len(const void* base,
  const void* cur, size_t base_len)
{ return base_len - size_t((const uint8_t*)cur-(const uint8_t*)base); }

static void ipv4_input(const void* ptr, size_t len);
static void ipv6_input(const void* ptr, size_t len);
static void srh_input(const void* ptr, size_t len);

static void
binary_input(const void* ptr, size_t len)
{
  printf(" IP6-NoNxt{binary}\n");
  const uint8_t* cur = (const uint8_t*)ptr;
  const size_t pkt_tot_len = len;
  const size_t payload_len = pkt_tot_len - (cur - (const uint8_t*)ptr);
  for (size_t i=0; i<payload_len; i+=16) {
    printf("\t");
    for (size_t j=0; j<16; j++) {
      const size_t idx = i + j;
      printf("%02x ", cur[idx]);
      if (idx+1 >= payload_len) break;
    }
    printf("\n");
  }
}

static void
tcp_input(const void* ptr, size_t len)
{
  using slankdev::tcp;
  if (len < sizeof(tcp)) {
    printf(" TCP{malformed}");
    return;
  }
  printf(" TCP{%p}", ptr);
}

static void
udp_input(const void* ptr, size_t len)
{
  using slankdev::udp;
  if (len < sizeof(udp)) {
    printf(" UDP{malformed}");
    return;
  }
  printf(" UDP{%p}", ptr);
}

static void
icmp6_input(const void* ptr, size_t len)
{
  using slankdev::icmp;
  if (len < sizeof(icmp)) {
    printf(" ICMP6{malformed}");
    return;
  }
  icmp* h = (icmp*)ptr;
  printf(" ICMP6{%u,%u}", h->type, h->code);
}

static inline void
ipv6_nxthdr_input(uint8_t nh,
    const void* np, size_t len)
{
  switch (nh) {
    case 0x29: ipv6_input  (np, len); break;
    case 0x04: ipv4_input  (np, len); break;
    case 0x3b: binary_input(np, len); break;
    case 0x2B: srh_input   (np, len); break;
    case 0x06: tcp_input   (np, len); break;
    case 0x11: udp_input   (np, len); break;
    case 0x3A: icmp6_input (np, len); break;
    default:
      printf(" UNKNOWN{%u,0x%02x}", nh, nh);
      break;
  }
}

static void
srh_input(const void* ptr, size_t len)
{
  using slankdev::srh;
  using slankdev::in6_addr_to_string;
  const srh* sh = reinterpret_cast<const srh*>(ptr);
  printf(" SR6{sl=%u,[", sh->segments_left);
  constexpr size_t sizeof_in6_addr = 16;
  const size_t segslist_len_byte = sh->hdr_len() - 8;
  const size_t n_segs = segslist_len_byte / sizeof_in6_addr;
  for (size_t i=0; i<n_segs; i++) {
    const char* str;
    str = in6_addr_to_string(&sh->segment_list[i]).c_str();
    printf("%s%s", str, i+1<n_segs?",":"]}");
  }

  const uint8_t next_hdr = sh->next_hdr;
  const uint8_t* np = (const uint8_t*)sh->get_next();
  const size_t nlen = get_len(ptr, np, len);
  ipv6_nxthdr_input(next_hdr, np, nlen);
}

static void
ipv4_input(const void* ptr, size_t len)
{
  using slankdev::ip;
  if (len < sizeof(ip)) {
    printf(" IP4{malformed}");
    return;
  }

  using slankdev::inaddr2str;
  const ip* hdr = reinterpret_cast<const ip*>(ptr);
  printf(" IP4{%s>%s}",
      inaddr2str(hdr->src).c_str(),
      inaddr2str(hdr->dst).c_str());
}

static void
ipv6_input(const void* ptr, size_t len)
{
  using slankdev::ip6;
  using slankdev::in6_addr_to_string;
  const ip6* ih = reinterpret_cast<const ip6*>(ptr);
  printf(" IP6{%s>%s}",
      in6_addr_to_string(&ih->src).c_str(),
      in6_addr_to_string(&ih->dst).c_str());

  const uint8_t next_hdr = ih->proto;
  const uint8_t* np = (const uint8_t*)ih->get_next();
  const size_t nlen = get_len(ptr, np, len);
  ipv6_nxthdr_input(next_hdr, np, nlen);
}

inline void
callback(uint8_t* user __attribute__((unused)),
    const struct pcap_pkthdr* h __attribute__((unused)),
    const uint8_t* byte)
{
  char timestamp_str_buf[100];
  time_t timer = time(NULL);
  struct tm* local = localtime(&timer);
  snprintf(timestamp_str_buf, sizeof(timestamp_str_buf),
      "%02d:%02d:%02d", local->tm_hour, local->tm_min, local->tm_sec);
  printf("%s", timestamp_str_buf);

  using slankdev::ether;
  const ether* eh = reinterpret_cast<const ether*>(byte);
  if (ntohs(eh->type) != 0x86dd)
    return ;

  const uint8_t* np = (const uint8_t*)(eh + 1);
  ipv6_input(np, get_len(byte, np, h->len));
  printf("\n");
}


int main(int argc, const char** argv)
{
  ArgumentParser parser;
  // parser.addArgument("-n");
  parser.addArgument("-f", "--filter", 1);
  parser.addArgument("-Q", "--direction", 1);
  parser.addArgument("-i", "--interface", 1, false);

  parser.parse(argc, argv);
  std::string ifname = parser.retrieve<std::string>("interface");
  std::string filter = parser.retrieve<std::string>("filter");
  std::string dir = parser.retrieve<std::string>("direction");

  slankdev::pcap pcap;
  pcap.open_live(ifname.c_str());
  pcap.setfilter_str(filter.c_str());

  if (dir == "inout" || dir == "") pcap.setdirection(PCAP_D_INOUT);
  else if (dir == "in") pcap.setdirection(PCAP_D_IN);
  else if (dir == "out") pcap.setdirection(PCAP_D_OUT);
  else throw slankdev::exception("direction can be choose in/out/inout");

  pcap.loop(0, callback, NULL);
}

