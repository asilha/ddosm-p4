#include <v1model.p4>

#include "parser.p4"

#define ALARM_SESSION 250
#define CS_WIDTH 1280

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // verify_checksum(true, {hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn, hdr.ipv4.total_len, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, hdr.ipv4.hdr_checksum, HashAlgorithm.csum16);
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    // Observation Window Parameters
    register<bit<5>>(1) log2_m;
    register<bit<32>>(1) training_len;

    // Observation Window Control
    register<bit<32>>(1) ow_counter;
    register<bit<32>>(1) pkt_counter;

    // Mitigation Threshold
    register<int<32>>(1) mitigation_t;

    // Count Sketch Counters
    register<int<32>>(CS_WIDTH) src_cs1;
    register<int<32>>(CS_WIDTH) src_cs2;
    register<int<32>>(CS_WIDTH) src_cs3;
    register<int<32>>(CS_WIDTH) src_cs4;
    register<int<32>>(CS_WIDTH) dst_cs1;
    register<int<32>>(CS_WIDTH) dst_cs2;
    register<int<32>>(CS_WIDTH) dst_cs3;
    register<int<32>>(CS_WIDTH) dst_cs4;

    // Count Sketch Observation Window Annotation
    register<bit<8>>(CS_WIDTH) src_cs1_ow;
    register<bit<8>>(CS_WIDTH) src_cs2_ow;
    register<bit<8>>(CS_WIDTH) src_cs3_ow;
    register<bit<8>>(CS_WIDTH) src_cs4_ow;
    register<bit<8>>(CS_WIDTH) dst_cs1_ow;
    register<bit<8>>(CS_WIDTH) dst_cs2_ow;
    register<bit<8>>(CS_WIDTH) dst_cs3_ow;
    register<bit<8>>(CS_WIDTH) dst_cs4_ow;

    // Count Sketch Counters (t -1)
    register<int<32>>(CS_WIDTH) src_cs1_tm_a;
    register<int<32>>(CS_WIDTH) src_cs2_tm_a;
    register<int<32>>(CS_WIDTH) src_cs3_tm_a;
    register<int<32>>(CS_WIDTH) src_cs4_tm_a;
    // register<int<32>>(CS_WIDTH) dst_cs1_tm_a;
    // register<int<32>>(CS_WIDTH) dst_cs2_tm_a;
    // register<int<32>>(CS_WIDTH) dst_cs3_tm_a;
    // register<int<32>>(CS_WIDTH) dst_cs4_tm_a;

    // Count Sketch Observation Window Annotation (t -1)
    register<bit<8>>(CS_WIDTH) src_cs1_ow_tm_a;
    register<bit<8>>(CS_WIDTH) src_cs2_ow_tm_a;
    register<bit<8>>(CS_WIDTH) src_cs3_ow_tm_a;
    register<bit<8>>(CS_WIDTH) src_cs4_ow_tm_a;
    // register<bit<8>>(CS_WIDTH) dst_cs1_ow_tm_a;
    // register<bit<8>>(CS_WIDTH) dst_cs2_ow_tm_a;
    // register<bit<8>>(CS_WIDTH) dst_cs3_ow_tm_a;
    // register<bit<8>>(CS_WIDTH) dst_cs4_ow_tm_a;  

    // Count Sketch Counters (t -2)
    register<int<32>>(CS_WIDTH) src_cs1_tm_b;
    register<int<32>>(CS_WIDTH) src_cs2_tm_b;
    register<int<32>>(CS_WIDTH) src_cs3_tm_b;
    register<int<32>>(CS_WIDTH) src_cs4_tm_b;
    // register<int<32>>(CS_WIDTH) dst_cs1_tm_b;
    // register<int<32>>(CS_WIDTH) dst_cs2_tm_b;
    // register<int<32>>(CS_WIDTH) dst_cs3_tm_b;
    // register<int<32>>(CS_WIDTH) dst_cs4_tm_b;

    // Count Sketch Observation Window Annotation (t -2)
    register<bit<8>>(CS_WIDTH) src_cs1_ow_tm_b;
    register<bit<8>>(CS_WIDTH) src_cs2_ow_tm_b;
    register<bit<8>>(CS_WIDTH) src_cs3_ow_tm_b;
    register<bit<8>>(CS_WIDTH) src_cs4_ow_tm_b;
    // register<bit<8>>(CS_WIDTH) dst_cs1_ow_tm_b;
    // register<bit<8>>(CS_WIDTH) dst_cs2_ow_tm_b;
    // register<bit<8>>(CS_WIDTH) dst_cs3_ow_tm_b;
    // register<bit<8>>(CS_WIDTH) dst_cs4_ow_tm_b;  

    // Entropy Norms - Fixed point representation: 28 integer bits, 4 fractional bits.
    register<bit<32>>(1) src_S;
    register<bit<32>>(1) dst_S;

    // Entropy EWMA and EWMMD - Fixed point representation: 14 integer bits, 18 fractional bits.
    register<bit<32>>(1) src_ewma;
    register<bit<32>>(1) src_ewmmd;
    register<bit<32>>(1) dst_ewma;
    register<bit<32>>(1) dst_ewmmd;

    // Smoothing and Sensitivity Coefficients
    register<bit<8>>(1) alpha;    // Fixed point representation: 0 integer bits, 8 fractional bits.
    register<bit<8>>(1) k;        // Fixed point representation: 5 integer bits, 3 fractional bits.

    // DEFCON Status
    register<bit<8>>(1) defcon; 

    action drop() {
        mark_to_drop();
    }

    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table ipv4_fib {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            forward;
            drop;
        }
        default_action = drop();
    }

    table ipv4_dpi_fib {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            forward;
            drop;
        }
        default_action = drop();
    }

    action get_entropy_term(bit<32> entropy_term) {
        meta.entropy_term = entropy_term;
    }

    // The two tables below are supposed to be implemented as a single one,
    // but our target (i.e., the simple_switch) does not support two table lookups within the the same control flow.
    table src_entropy_term {
        key = {
            meta.ip_count: lpm;
        }
        actions = {
            get_entropy_term;
        }
        default_action = get_entropy_term(0);
    }

    table dst_entropy_term {
        key = {
            meta.ip_count: lpm;
        }
        actions = {
            get_entropy_term;
        }
        default_action = get_entropy_term(0);
    }

    action cs_hash(in bit<32> ipv4_addr, out bit<32> h1, out bit<32> h2, out bit<32> h3, out bit<32> h4) {
        hash(h1, HashAlgorithm.h1, 32w0, {ipv4_addr}, 32w0xffffffff);
        hash(h2, HashAlgorithm.h2, 32w0, {ipv4_addr}, 32w0xffffffff);
        hash(h3, HashAlgorithm.h3, 32w0, {ipv4_addr}, 32w0xffffffff);
        hash(h4, HashAlgorithm.h4, 32w0, {ipv4_addr}, 32w0xffffffff);
    }

    action cs_ghash(in bit<32> ipv4_addr, out int<32> g1, out int<32> g2, out int<32> g3, out int<32> g4) {
        hash(g1, HashAlgorithm.g1, 32w0, {ipv4_addr}, 32w0xffffffff);
        hash(g2, HashAlgorithm.g2, 32w0, {ipv4_addr}, 32w0xffffffff);
        hash(g3, HashAlgorithm.g3, 32w0, {ipv4_addr}, 32w0xffffffff);
        hash(g4, HashAlgorithm.g4, 32w0, {ipv4_addr}, 32w0xffffffff);

        // As ghash outputs 0 or 1, we must map 0 to -1.
        g1 = 2*g1 - 1;
        g2 = 2*g2 - 1;
        g3 = 2*g3 - 1;
        g4 = 2*g4 - 1;
    }

    action median(in int<32> x1, in int<32> x2, in int<32> x3, in int<32> x4, out int<32> y) {
        // This is why we should minimize the sketch depth: the median operator is hardcoded.
        if      ((x1 <= x2 && x1 <= x3 && x1 <= x4 && x2 >= x3 && x2 >= x4) || 
                 (x2 <= x1 && x2 <= x3 && x2 <= x4 && x1 >= x3 && x1 >= x4))
            y = (x3 + x4) >> 1;
        else if ((x1 <= x2 && x1 <= x3 && x1 <= x4 && x3 >= x2 && x3 >= x4) || 
                 (x3 <= x1 && x3 <= x2 && x3 <= x4 && x1 >= x2 && x1 >= x4))
            y = (x2 + x4) >> 1;
        else if ((x1 <= x2 && x1 <= x3 && x1 <= x4 && x4 >= x2 && x4 >= x3) || 
                 (x4 <= x1 && x4 <= x2 && x4 <= x3 && x1 >= x2 && x1 >= x3))
            y = (x2 + x3) >> 1;
        else if ((x2 <= x1 && x2 <= x3 && x2 <= x4 && x3 >= x1 && x3 >= x4) || 
                 (x3 <= x1 && x3 <= x2 && x3 <= x4 && x2 >= x1 && x2 >= x4))
            y = (x1 + x4) >> 1;
        else if ((x2 <= x1 && x2 <= x3 && x2 <= x4 && x4 >= x1 && x4 >= x3) || 
                 (x4 <= x1 && x4 <= x2 && x4 <= x3 && x2 >= x1 && x2 >= x3))
            y = (x1 + x3) >> 1;
        else
            y = (x1 + x2) >> 1;
    }

    apply {
        if (hdr.ipv4.isValid()) {

            // Obtain Observation Window number from the register.
            bit<32> current_ow;
            ow_counter.read(current_ow, 0);

            // Obtain DEFCON state from the register.
            bit<8> defcon_aux;
            defcon.read(defcon_aux, 0);

            // Obtain mitigation threshold from the register
            int<32> mitigation_t_aux;
            mitigation_t.read(mitigation_t_aux, 0);

            // Auxiliary variables for counter and annotation:
            int<32> c_aux;
            bit<8>  ow_aux;

            // --------------------------------------------------------------------------------------------------------            
            // Beginning of source address frequency and entropy norm estimation.

            // Obtain column IDs for all rows
            bit<32> src_h1;
            bit<32> src_h2;
            bit<32> src_h3;
            bit<32> src_h4;
            cs_hash(hdr.ipv4.src_addr, src_h1, src_h2, src_h3, src_h4);

            // Determine whether to increase or decrease counters
            int<32> src_g1;
            int<32> src_g2;
            int<32> src_g3;
            int<32> src_g4;
            cs_ghash(hdr.ipv4.src_addr, src_g1, src_g2, src_g3, src_g4);

            // Estimate Frequencies for Source Addresses

            // Row 1 Estimate
            int<32> src_c1;
            bit<8>  src_c1_ow;
            src_cs1.read(src_c1, src_h1);           // Read current counter.
            src_cs1_ow.read(src_c1_ow, src_h1);     // Read current annotation. 
            if (src_c1_ow != current_ow[7:0]) {      // If we're in a different window:
                if (current_ow[7:0] > 1 && defcon_aux == 0) {
                    src_cs1_tm_a.read(c_aux, src_h1);            // Read tm_a counter.
                    src_cs1_ow_tm_a.read(ow_aux, src_h1);        // Read tm_a annotation. 
                    src_cs1_tm_b.write(src_h1, c_aux);           // Copy tm_a counter to tm_b.
                    src_cs1_ow_tm_b.write(src_h1, ow_aux);       // Copy tm_a annotation to tm_b.
                }     
                src_cs1_tm_a.write(src_h1, src_c1);          // Copy w counter to tm_a.
                src_cs1_ow_tm_a.write(src_h1, src_c1_ow);    // Copy w annotation to tm_a.
                src_c1 = 0;                                  // Reset the counter.
                src_cs1_ow.write(src_h1, current_ow[7:0]);   // Update the annotation. 
            }
            src_c1 = src_c1 + src_g1;               // Update the counter.
            src_cs1.write(src_h1, src_c1);          // Write the counter.
            src_c1 = src_c1 * src_g1;               // If g1 is negative, c1 will also be negative; this computes the absolute value.

            // Row 2 Estimate
            int<32> src_c2;
            bit<8>  src_c2_ow;
            src_cs2.read(src_c2, src_h2);           // Read current counter.
            src_cs2_ow.read(src_c2_ow, src_h2);     // Read annotation. 
            if (src_c2_ow != current_ow[7:0]) {      // If we're in a different window:
                if (current_ow[7:0] > 1 && defcon_aux == 0) {
                    src_cs2_tm_a.read(c_aux, src_h2);            // Read tm_a counter.
                    src_cs2_ow_tm_a.read(ow_aux, src_h2);        // Read tm_a annotation. 
                    src_cs2_tm_b.write(src_h2, c_aux);           // Copy tm_a counter to tm_b.
                    src_cs2_ow_tm_b.write(src_h2, ow_aux);       // Copy tm_a annotation to tm_b.
                }     
                src_cs2_tm_a.write(src_h2, src_c2);          // Copy w counter to tm_a.
                src_cs2_ow_tm_a.write(src_h2, src_c2_ow);    // Copy w annotation to tm_a.
                src_c2 = 0;                                  // Reset the counter.
                src_cs2_ow.write(src_h2, current_ow[7:0]);   // Update the annotation. 
            }
            src_c2 = src_c2 + src_g2;               // Update the counter.
            src_cs2.write(src_h2, src_c2);          // Write the counter.
            src_c2 = src_c2 * src_g2;               // If g2 is negative, c2 will also be negative; this computes the absolute value.

            // Row 3 Estimate
            int<32> src_c3;
            bit<8>  src_c3_ow;
            src_cs3.read(src_c3, src_h3);           // Read current counter.
            src_cs3_ow.read(src_c3_ow, src_h3);     // Read annotation. 
            if (src_c3_ow != current_ow[7:0]) {      // If we're in a different window:
                if (current_ow[7:0] > 1 && defcon_aux == 0) {
                    src_cs3_tm_a.read(c_aux, src_h3);            // Read tm_a counter.
                    src_cs3_ow_tm_a.read(ow_aux, src_h3);        // Read tm_a annotation. 
                    src_cs3_tm_b.write(src_h3, c_aux);           // Copy tm_a counter to tm_b.
                    src_cs3_ow_tm_b.write(src_h3, ow_aux);       // Copy tm_a annotation to tm_b.
                }     
                src_cs3_tm_a.write(src_h3, src_c3);          // Copy w counter to tm_a.
                src_cs3_ow_tm_a.write(src_h3, src_c3_ow);    // Copy w annotation to tm_a.
                src_c3 = 0;                                  // Reset the counter.
                src_cs3_ow.write(src_h3, current_ow[7:0]);   // Update the annotation. 
            }
            src_c3 = src_c3 + src_g3;               // Update the counter.
            src_cs3.write(src_h3, src_c3);          // Write the counter.
            src_c3 = src_c3 * src_g3;               // If g3 is negative, c3 will also be negative; this computes the absolute value.

            // Row 4 Estimate
            int<32> src_c4;
            bit<8>  src_c4_ow;
            src_cs4.read(src_c4, src_h4);           // Read current counter.
            src_cs4_ow.read(src_c4_ow, src_h4);     // Read annotation. 
            if (src_c4_ow != current_ow[7:0]) {      // If we're in a different window:
                if (current_ow[7:0] > 1 && defcon_aux == 0) {
                    src_cs4_tm_a.read(c_aux, src_h4);            // Read tm_a counter.
                    src_cs4_ow_tm_a.read(ow_aux, src_h4);        // Read tm_a annotation. 
                    src_cs4_tm_b.write(src_h4, c_aux);           // Copy tm_a counter to tm_b.
                    src_cs4_ow_tm_b.write(src_h4, ow_aux);       // Copy tm_a annotation to tm_b.
                }     
                src_cs4_tm_a.write(src_h4, src_c4);          // Copy w counter to tm_a.
                src_cs4_ow_tm_a.write(src_h4, src_c4_ow);    // Copy w annotation to tm_a.
                src_c4 = 0;                                  // Reset the counter.
                src_cs4_ow.write(src_h4, current_ow[7:0]);   // Update the annotation. 
            }
            src_c4 = src_c4 + src_g4;               // Update the counter.
            src_cs4.write(src_h4, src_c4);          // Write the counter.
            src_c4 = src_c4 * src_g4;               // If g4 is negative, c4 will also be negative; this computes the absolute value.

            // At this point, we have updated counters in src_c1, src_c2, src_c3, and src_c4.

            // Count Sketch Source IP Frequency Estimate: store it in meta.ip_count.
            median(src_c1, src_c2, src_c3, src_c4, meta.ip_count);

            // LPM Table Lookup
            if (meta.ip_count > 0)              // This prevents having to perform a lookup when the argument is zero.
                src_entropy_term.apply();
            else
                meta.entropy_term = 0;
            // At this point, meta.entropy_term has the 'increment'.    

            // Source Entropy Norm Update       
            bit<32> src_S_aux;
            src_S.read(src_S_aux, 0);
            src_S_aux = src_S_aux + meta.entropy_term;
            src_S.write(0, src_S_aux);

            // End of source address frequency and entropy norm estimation.
            // --------------------------------------------------------------------------------------------------------

            // --------------------------------------------------------------------------------------------------------
            // Beginning of destination address frequency and entropy norm estimation. 

            // Obtain column IDs for all rows
            bit<32> dst_h1;
            bit<32> dst_h2;
            bit<32> dst_h3;
            bit<32> dst_h4;
            cs_hash(hdr.ipv4.dst_addr, dst_h1, dst_h2, dst_h3, dst_h4);

            // Determine whether to increase or decrease counters
            int<32> dst_g1;
            int<32> dst_g2;
            int<32> dst_g3;
            int<32> dst_g4;
            cs_ghash(hdr.ipv4.dst_addr, dst_g1, dst_g2, dst_g3, dst_g4);

            // Estimate Frequencies for Destination Addresses

            // Row 1 Estimate
            int<32> dst_c1;
            bit<8>  dst_c1_ow;
            dst_cs1.read(dst_c1, dst_h1);           // Read current counter.
            dst_cs1_ow.read(dst_c1_ow, dst_h1);     // Read annotation. 
            if (dst_c1_ow != current_ow[7:0]) {      // If we're in a different window:
                // if (current_ow[7:0] > 1 && defcon_aux == 0) {
                //     dst_cs1_tm_a.read(c_aux, dst_h1);            // Read tm_a counter.
                //     dst_cs1_ow_tm_a.read(ow_aux, dst_h1);        // Read tm_a annotation. 
                //     dst_cs1_tm_b.write(dst_h1, c_aux);           // Copy tm_a counter to tm_b.
                //     dst_cs1_ow_tm_b.write(dst_h1, ow_aux);       // Copy tm_a annotation to tm_b.
                // }     
                // dst_cs1_tm_a.write(dst_h1, dst_c1);          // Copy w counter to tm_a.
                // dst_cs1_ow_tm_a.write(dst_h1, dst_c1_ow);    // Copy w annotation to tm_a.
                dst_c1 = 0;                                  // Reset the counter.
                dst_cs1_ow.write(dst_h1, current_ow[7:0]);   // Update the annotation. 
            }
            dst_c1 = dst_c1 + dst_g1;               // Update the counter.
            dst_cs1.write(dst_h1, dst_c1);          // Write the counter.
            dst_c1 = dst_c1 * dst_g1;               // If g1 is negative, c1 will also be negative; this computes the absolute value.

            // Row 2 Estimate
            int<32> dst_c2;
            bit<8>  dst_c2_ow;
            dst_cs2.read(dst_c2, dst_h2);           // Read current counter.
            dst_cs2_ow.read(dst_c2_ow, dst_h2);     // Read annotation. 
            if (dst_c2_ow != current_ow[7:0]) {      // If we're in a different window:
                // if (current_ow[7:0] > 1 && defcon_aux == 0) {
                //     dst_cs2_tm_a.read(c_aux, dst_h2);            // Read tm_a counter.
                //     dst_cs2_ow_tm_a.read(ow_aux, dst_h2);        // Read tm_a annotation. 
                //     dst_cs2_tm_b.write(dst_h2, c_aux);           // Copy tm_a counter to tm_b.
                //     dst_cs2_ow_tm_b.write(dst_h2, ow_aux);       // Copy tm_a annotation to tm_b.
                // }     
                // dst_cs2_tm_a.write(dst_h2, dst_c2);          // Copy w counter to tm_a.
                // dst_cs2_ow_tm_a.write(dst_h2, dst_c2_ow);    // Copy w annotation to tm_a.
                dst_c2 = 0;                                  // Reset the counter.
                dst_cs2_ow.write(dst_h2, current_ow[7:0]);   // Update the annotation. 
            }
            dst_c2 = dst_c2 + dst_g2;               // Update the counter.
            dst_cs2.write(dst_h2, dst_c2);          // Write the counter.
            dst_c2 = dst_c2 * dst_g2;               // If g2 is negative, c2 will also be negative; this computes the absolute value.

            // Row 3 Estimate
            int<32> dst_c3;
            bit<8>  dst_c3_ow;
            dst_cs3.read(dst_c3, dst_h3);           // Read current counter.
            dst_cs3_ow.read(dst_c3_ow, dst_h3);     // Read annotation. 
            if (dst_c3_ow != current_ow[7:0]) {      // If we're in a different window:
                // if (current_ow[7:0] > 1 && defcon_aux == 0) {
                //     dst_cs3_tm_a.read(c_aux, dst_h3);            // Read tm_a counter.
                //     dst_cs3_ow_tm_a.read(ow_aux, dst_h3);        // Read tm_a annotation. 
                //     dst_cs3_tm_b.write(dst_h3, c_aux);           // Copy tm_a counter to tm_b.
                //     dst_cs3_ow_tm_b.write(dst_h3, ow_aux);       // Copy tm_a annotation to tm_b.
                // }     
                // dst_cs3_tm_a.write(dst_h3, dst_c3);          // Copy w counter to tm_a.
                // dst_cs3_ow_tm_a.write(dst_h3, dst_c3_ow);    // Copy w annotation to tm_a.
                dst_c3 = 0;                                  // Reset the counter.
                dst_cs3_ow.write(dst_h3, current_ow[7:0]);   // Update the annotation. 
            }
            dst_c3 = dst_c3 + dst_g3;               // Update the counter.
            dst_cs3.write(dst_h3, dst_c3);          // Write the counter.
            dst_c3 = dst_c3 * dst_g3;               // If g3 is negative, c3 will also be negative; this computes the absolute value.

            // Row 4 Estimate
            int<32> dst_c4;
            bit<8>  dst_c4_ow;
            dst_cs4.read(dst_c4, dst_h4);           // Read current counter.
            dst_cs4_ow.read(dst_c4_ow, dst_h4);     // Read annotation. 
            if (dst_c4_ow != current_ow[7:0]) {      // If we're in a different window:
                // if (current_ow[7:0] > 1 && defcon_aux == 0) {
                //     dst_cs4_tm_a.read(c_aux, dst_h4);            // Read tm_a counter.
                //     dst_cs4_ow_tm_a.read(ow_aux, dst_h4);        // Read tm_a annotation. 
                //     dst_cs4_tm_b.write(dst_h4, c_aux);           // Copy tm_a counter to tm_b.
                //     dst_cs4_ow_tm_b.write(dst_h4, ow_aux);       // Copy tm_a annotation to tm_b.
                // }     
                // dst_cs4_tm_a.write(dst_h4, dst_c4);          // Copy w counter to tm_a.
                // dst_cs4_ow_tm_a.write(dst_h4, dst_c4_ow);    // Copy w annotation to tm_a.
                dst_c4 = 0;                                  // Reset the counter.
                dst_cs4_ow.write(dst_h4, current_ow[7:0]);   // Update the annotation. 
            }
            dst_c4 = dst_c4 + dst_g4;               // Update the counter.
            dst_cs4.write(dst_h4, dst_c4);          // Write the counter.
            dst_c4 = dst_c4 * dst_g4;               // If g4 is negative, c4 will also be negative; this computes the absolute value.

            // At this point, we have updated counters in dst_c1, dst_c2, dst_c3, and dst_c4.

            // Count Sketch Destination IP Frequency Estimate
            median(dst_c1, dst_c2, dst_c3, dst_c4, meta.ip_count);

            // LPM Table Lookup
            if (meta.ip_count > 0)
                dst_entropy_term.apply();
            else
                meta.entropy_term = 0;
            // At this point, meta.entropy_term has the 'increment'.    

            // Destination Entropy Norm Update
            bit<32> dst_S_aux;
            dst_S.read(dst_S_aux, 0);
            dst_S_aux = dst_S_aux + meta.entropy_term;
            dst_S.write(0, dst_S_aux);

            // At this point, we already have source and destination entropy norms (src_S and dst_S). 

            // End  of destination address frequency and entropy norm estimation. 
            // --------------------------------------------------------------------------------------------------------

            // --------------------------------------------------------------------------------------------------------
            // Beginning of anomaly detection. 
            // Step 1: Check whether the Observation Window has ended.
            // Step 2: If the OW has ended, estimate the entropies.
            // Step 3: If we detect an entropy anomaly, signal this condition. Otherwise, just update the moving averages. 

            // Step 1: Check whether the Observation Window has ended. 
           
            bit<32> m;                              // Observation Window Size
            bit<5> log2_m_aux;
            log2_m.read(log2_m_aux, 0);
            m = 32w1 << log2_m_aux;                 // m = 2^log2(m)
            pkt_counter.read(meta.pkt_num, 0);      // Packet Counter
            meta.pkt_num = meta.pkt_num + 1;

            if (meta.pkt_num != m) {  // Observation Window has not ended yet; just update the counter.
                pkt_counter.write(0, meta.pkt_num);
            } else {                   // End of Observation Window. Begin OW Summarization.
                current_ow = current_ow + 1;
                ow_counter.write(0, current_ow); // Save the number of the new OW in its register. 

                // Step 2: Estimate the entropies. 

                // We need to calculate Ĥ = log2(m) - Ŝ/m .
                // Since our pipeline doesn't implement division, we can use the identity 1/m = 2^(-log2(m)), for positive m. 
                // Given that m is an integer power of two and that we already know log2(m), division becomes a right shift by log2(m) bits. 
                // Therefore,  Ĥ = log2(m) - Ŝ/m  =  log2(m) - Ŝ * 2^(-log2(m)).
                meta.src_entropy = ((bit<32>)log2_m_aux << 4) - (src_S_aux >> log2_m_aux);
                meta.dst_entropy = ((bit<32>)log2_m_aux << 4) - (dst_S_aux >> log2_m_aux);

                // Read moving averages and deviations. 
                src_ewma.read(meta.src_ewma, 0);
                src_ewmmd.read(meta.src_ewmmd, 0);
                dst_ewma.read(meta.dst_ewma, 0);
                dst_ewmmd.read(meta.dst_ewmmd, 0);

                if (current_ow == 0) {                           // In the first window... [changed to 0th window, which will never happen.]
                    meta.src_ewma = meta.src_entropy << 14;      // Initialize averages with the first estimated entropies. Averages have 18 fractional bits. 
                    meta.src_ewmmd = 0;
                    meta.dst_ewma = meta.dst_entropy << 14;
                    meta.dst_ewmmd = 0;
                 } else {                                            // Beginning with the second window... 
                    meta.alarm = 0;                                  // By default, there's no alarm. 

                    // Step 3: If we detect an anomaly, signal this condition. Otherwise, just update the moving averages. 

                    bit<32> training_len_aux;
                    training_len.read(training_len_aux, 0);
                    if (current_ow > training_len_aux) {            // If we've finished training, we check for anomalies.
                        bit<8> k_aux;
                        k.read(k_aux, 0);

                        bit<32> src_thresh;
                        src_thresh = meta.src_ewma + ((bit<32>)k_aux*meta.src_ewmmd >> 3);  // k has 3 fractional bits.

                        bit<32> dst_thresh;
                        dst_thresh = meta.dst_ewma - ((bit<32>)k_aux*meta.dst_ewmmd >> 3);

                        if ((meta.src_entropy << 14) > src_thresh || (meta.dst_entropy << 14) < dst_thresh) { // ANOMALY DETECTED. 
                            meta.alarm = 1;  
                            meta.defcon = 1; 
                            defcon.write(0, 1);                     // When defcon = 1, the switch stays "on alert".
                        }
                            
                    }

                    if (meta.alarm == 0) {  // No attack detected; let's update EWMA and EWMMD. 
                        bit<8> alpha_aux;
                        alpha.read(alpha_aux, 0);
 
                        // Fixed-point alignments:
                        //   Alpha: 8 fractional bits; Entropy: 4 fractional bits. EWMA and EWMMD: 18 fractional bits.  
                        //   Alpha*Entropy: 8 +  4 = 12 bits; shift left  6 bits to obtain 18 bits. 
                        //   Alpha*EWMx:    8 + 18 = 26 bits; shift right 8 bits to obtain 18 bits. 

                        meta.src_ewma = (((bit<32>)alpha_aux*meta.src_entropy) << 6) + (((0x00000100 - (bit<32>)alpha_aux)*meta.src_ewma) >> 8);
                        meta.dst_ewma = (((bit<32>)alpha_aux*meta.dst_entropy) << 6) + (((0x00000100 - (bit<32>)alpha_aux)*meta.dst_ewma) >> 8);

                        if ((meta.src_entropy << 14) >= meta.src_ewma)
                           meta.src_ewmmd = (((bit<32>)alpha_aux*((meta.src_entropy << 14) - meta.src_ewma)) >> 8) + (((0x00000100 - (bit<32>)alpha_aux)*meta.src_ewmmd) >> 8);
                        else
                           meta.src_ewmmd = (((bit<32>)alpha_aux*(meta.src_ewma - (meta.src_entropy << 14))) >> 8) + (((0x00000100 - (bit<32>)alpha_aux)*meta.src_ewmmd) >> 8);

                        if ((meta.dst_entropy << 14) >= meta.dst_ewma)
                           meta.dst_ewmmd = (((bit<32>)alpha_aux*((meta.dst_entropy << 14) - meta.dst_ewma)) >> 8) + (((0x00000100 - (bit<32>)alpha_aux)*meta.dst_ewmmd) >> 8);
                        else
                            meta.dst_ewmmd = (((bit<32>)alpha_aux*(meta.dst_ewma - (meta.dst_entropy << 14))) >> 8) + (((0x00000100 - (bit<32>)alpha_aux)*meta.dst_ewmmd) >> 8);
                    
                    }

                    // End of Step 3 (Anomaly Detection). 
                    
                } 
                
                // End of Step 2 (Entropy Estimation). 

                // Write back the values for EWMA and EWMMD. 
                src_ewma.write(0, meta.src_ewma);
                src_ewmmd.write(0, meta.src_ewmmd);
                dst_ewma.write(0, meta.dst_ewma);
                dst_ewmmd.write(0, meta.dst_ewmmd);

                // Reset the packet counter and the entropy term.
                pkt_counter.write(0, 0);
                src_S.write(0, 0);
                dst_S.write(0, 0);

                // Check whether we should reset DEFCON or not. 
                defcon.read(meta.defcon,0);
                if (meta.alarm == 0 && meta.defcon == 1) {
                    defcon.write(0, 0);
                }

                // Generate a signaling packet. 
                clone3(CloneType.I2E, ALARM_SESSION, { meta.pkt_num, meta.src_entropy, meta.src_ewma, meta.src_ewmmd, meta.dst_entropy, meta.dst_ewma, meta.dst_ewmmd, meta.alarm, meta.defcon });

            } // End OW summarization. 

            // End of Step 1 (OW Summarization)
            // --------------------------------------------------------------------------------------------------------

            // --------------------------------------------------------------------------------------------------------
            // Beginning of conditional diversion. 

            // Detour has a default value of zero.
            // It will be set to one for packets that should undergo external inspection.
            bit<1> detour;
            detour = 0;

            if (defcon_aux == 1) {  // An attack was detected at t-1 or t-2.        
              
                // These variables will hold the estimated counters for t-1 and t-2. 
                int<32> src_count_tm_a;
                int<32> src_count_tm_b;
                // int<32> dst_count_tm_a;
                // int<32> dst_count_tm_b;

                int<32> src_delta;
                
                // Get the estimated counter for the source address at t-1.
                src_cs1_tm_a.read(src_c1, src_h1);
                src_cs2_tm_a.read(src_c2, src_h2);
                src_cs3_tm_a.read(src_c3, src_h3);
                src_cs4_tm_a.read(src_c4, src_h4);
                src_c1 = src_c1 * src_g1;
                src_c2 = src_c2 * src_g2;
                src_c3 = src_c3 * src_g3;
                src_c4 = src_c4 * src_g4;
                median(src_c1, src_c2, src_c3, src_c4, src_count_tm_a);

                // Get the estimated counter for the source address at t-2.
                src_cs1_tm_b.read(src_c1, src_h1);
                src_cs2_tm_b.read(src_c2, src_h2);
                src_cs3_tm_b.read(src_c3, src_h3);
                src_cs4_tm_b.read(src_c4, src_h4);
                src_c1 = src_c1 * src_g1;
                src_c2 = src_c2 * src_g2;
                src_c3 = src_c3 * src_g3;
                src_c4 = src_c4 * src_g4;
                median(src_c1, src_c2, src_c3, src_c4, src_count_tm_b);

                // Get the estimated counter for the destination address at t-1.
                // dst_cs1_tm_a.read(dst_c1, dst_h1);
                // dst_cs2_tm_a.read(dst_c2, dst_h2);
                // dst_cs3_tm_a.read(dst_c3, dst_h3);
                // dst_cs4_tm_a.read(dst_c4, dst_h4);
                // dst_c1 = dst_c1 * dst_g1;
                // dst_c2 = dst_c2 * dst_g2;
                // dst_c3 = dst_c3 * dst_g3;
                // dst_c4 = dst_c4 * dst_g4;
                // median(dst_c1, dst_c2, dst_c3, dst_c4, dst_count_tm_a);

                // Get the estimated counter for the destination address at t-2.
                // dst_cs1_tm_b.read(dst_c1, dst_h1);
                // dst_cs2_tm_b.read(dst_c2, dst_h2);
                // dst_cs3_tm_b.read(dst_c3, dst_h3);
                // dst_cs4_tm_b.read(dst_c4, dst_h4);
                // dst_c1 = dst_c1 * dst_g1;
                // dst_c2 = dst_c2 * dst_g2;
                // dst_c3 = dst_c3 * dst_g3;
                // dst_c4 = dst_c4 * dst_g4;
                // median(dst_c1, dst_c2, dst_c3, dst_c4, dst_count_tm_b);

                // This means that the address has had a significant increase in frequency. 
                // Hence, we consider it more likely to be a source of attack.  
                // For now, we're only using the source address. 
                // if (src_count_tm_a > src_count_tm_b) {
                //         src_delta = src_count_tm_a - src_count_tm_b;
                //         if (src_delta > mitigation_t_aux) { // 1% of window size: 0.01 * 8192  =~ 81. 
                //             detour = 1;
                //         }
                // } 

                // Experiment: write the values in the packet. 
                if (src_count_tm_a > src_count_tm_b) {
                        src_delta = src_count_tm_a - src_count_tm_b;
                        hdr.ipv4.identification = (bit<16>) src_delta[15:0] ;
                        detour = 1;
                } 

            } // End of DEFCON state processing. 

            // Experiment: unconditional detour
            

            // Detour is set to one for packets that must undergo further inspection.
            if (detour == 0) {
                ipv4_fib.apply();       // Use the regular forwarding table.
            }
            else { 
                ipv4_dpi_fib.apply();   // Use the "deep packet inspection" forwarding table. 
            }


            // End of conditional diversion. 
            // --------------------------------------------------------------------------------------------------------

        } // End of IPv4 header processing. 
    } // End of ingress pipeline control block. 
} // End of ingress pipeline definition. 

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    const bit<32> CLONE = 1;

    apply {
        if (standard_metadata.instance_type == CLONE) {
            hdr.ddosd.setValid();
            hdr.ddosd.pkt_num = meta.pkt_num;
            hdr.ddosd.src_entropy = meta.src_entropy;
            hdr.ddosd.src_ewma = meta.src_ewma;
            hdr.ddosd.src_ewmmd = meta.src_ewmmd;
            hdr.ddosd.dst_entropy = meta.dst_entropy;
            hdr.ddosd.dst_ewma = meta.dst_ewma;
            hdr.ddosd.dst_ewmmd = meta.dst_ewmmd;
            hdr.ddosd.alarm = meta.alarm;
            hdr.ddosd.defcon = meta.defcon;
            hdr.ddosd.ether_type = hdr.ethernet.ether_type;
            hdr.ethernet.ether_type = ETHERTYPE_DDOSD;
        }
    }
}

control computeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        // update_checksum(true, {hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn, hdr.ipv4.total_len, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.src_addr, hdr.ipv4.dst_addr}, hdr.ipv4.hdr_checksum, HashAlgorithm.csum16);
    }
}

control DeparserImpl(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
