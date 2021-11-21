#ifndef HEADERS_P4
#define HEADERS_P4

                            // Byte Offsets
header ethernet_t {
    bit<48> dst_addr;       // 00-05
    bit<48> src_addr;       // 06-11
    bit<16> ether_type;     // 12-13
}

// EtherType 0x6605         
header ddosd_t {
    bit<32> pkt_num;        // 14-17
    bit<32> src_entropy;    // 18-21
    bit<32> src_ewma;       // 22-25
    bit<32> src_ewmmd;      // 26-29
    bit<32> dst_entropy;    // 30-33
    bit<32> dst_ewma;       // 34-37
    bit<32> dst_ewmmd;      // 38-41
    bit<8> alarm;           // 42
    bit<8> dr_state;        // 43
    bit<16> ether_type;     // 44-45    [Copied from Ethernet.]
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

struct headers {
    ethernet_t ethernet;
    ddosd_t ddosd;
    ipv4_t ipv4;
}

struct metadata {
    int<32> ip_count;
    bit<32> entropy_term;
    bit<32> pkt_num;
    bit<32> src_entropy;
    bit<32> src_ewma;
    bit<32> src_ewmmd;
    bit<32> dst_entropy;
    bit<32> dst_ewma;
    bit<32> dst_ewmmd;
    bit<8> alarm;
    bit<8> dr_state; 
    bit<32> nhop_ipv4;     
}

#endif /* HEADERS_P4 */
