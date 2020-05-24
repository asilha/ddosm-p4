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

    /*  
    
        Extended count sketch declarations.
        
        Our prototype has six extended count sketches: 

        CS_Src_Curr, CS_Src_Last, CS_Src_Safe, 
        CS_Dst_Curr, CS_Dst_Last, CS_Dst_Safe.

        "Src" and "Dst" indicate whether the sketch approximates counts for source or destination IP addresses. 
        "Curr", "Last", and "Safe" indicate the type of observation window to which the sketch refers.  

        Since P4 does not provide matrices or records, each sketch row requires two sketches, 
        being one for the counter and one for the observation window ID annotations. 
        
    */ 
    
    // CS_Src_Curr (Source IP) (Current OW)
    // Counters 
    register<int<32>>(CS_WIDTH) cs_src_curr_1;
    register<int<32>>(CS_WIDTH) cs_src_curr_2;
    register<int<32>>(CS_WIDTH) cs_src_curr_3;
    register<int<32>>(CS_WIDTH) cs_src_curr_4;
    // Annotations 
    register<bit<8>>(CS_WIDTH) cs_src_curr_1_wid;
    register<bit<8>>(CS_WIDTH) cs_src_curr_2_wid;
    register<bit<8>>(CS_WIDTH) cs_src_curr_3_wid;
    register<bit<8>>(CS_WIDTH) cs_src_curr_4_wid;

    // CS_Dst_Curr (Destination IP) (Current OW)
    // Counters 
    register<int<32>>(CS_WIDTH) cs_dst_curr_1;
    register<int<32>>(CS_WIDTH) cs_dst_curr_2;
    register<int<32>>(CS_WIDTH) cs_dst_curr_3;
    register<int<32>>(CS_WIDTH) cs_dst_curr_4;
    // Annotations
    register<bit<8>>(CS_WIDTH) cs_dst_curr_1_wid;
    register<bit<8>>(CS_WIDTH) cs_dst_curr_2_wid;
    register<bit<8>>(CS_WIDTH) cs_dst_curr_3_wid;
    register<bit<8>>(CS_WIDTH) cs_dst_curr_4_wid;

    // CS_Src_Last (Source IP) (Last OW)
    // Counters
    register<int<32>>(CS_WIDTH) cs_src_last_1;
    register<int<32>>(CS_WIDTH) cs_src_last_2;
    register<int<32>>(CS_WIDTH) cs_src_last_3;
    register<int<32>>(CS_WIDTH) cs_src_last_4;
    // Annotations
    register<bit<8>>(CS_WIDTH) cs_src_last_1_wid;
    register<bit<8>>(CS_WIDTH) cs_src_last_2_wid;
    register<bit<8>>(CS_WIDTH) cs_src_last_3_wid;
    register<bit<8>>(CS_WIDTH) cs_src_last_4_wid;

    // CS_Dst_Last (Destination IP) (Last OW)
    // Counters
    register<int<32>>(CS_WIDTH) cs_dst_last_1;
    register<int<32>>(CS_WIDTH) cs_dst_last_2;
    register<int<32>>(CS_WIDTH) cs_dst_last_3;
    register<int<32>>(CS_WIDTH) cs_dst_last_4;
    // Annotations
    register<bit<8>>(CS_WIDTH) cs_dst_last_1_wid;
    register<bit<8>>(CS_WIDTH) cs_dst_last_2_wid;
    register<bit<8>>(CS_WIDTH) cs_dst_last_3_wid;
    register<bit<8>>(CS_WIDTH) cs_dst_last_4_wid;  

    // CS_Src_Safe (Source IP) (Safe OW)
    // Counters
    register<int<32>>(CS_WIDTH) cs_src_safe_1;
    register<int<32>>(CS_WIDTH) cs_src_safe_2;
    register<int<32>>(CS_WIDTH) cs_src_safe_3;
    register<int<32>>(CS_WIDTH) cs_src_safe_4;
    // Annotations
    register<bit<8>>(CS_WIDTH) cs_src_safe_1_wid;
    register<bit<8>>(CS_WIDTH) cs_src_safe_2_wid;
    register<bit<8>>(CS_WIDTH) cs_src_safe_3_wid;
    register<bit<8>>(CS_WIDTH) cs_src_safe_4_wid;

    // CS_Dst_Safe (Destination IP) (Safe OW)
    // Counters
    register<int<32>>(CS_WIDTH) cs_dst_safe_1;
    register<int<32>>(CS_WIDTH) cs_dst_safe_2;
    register<int<32>>(CS_WIDTH) cs_dst_safe_3;
    register<int<32>>(CS_WIDTH) cs_dst_safe_4;
    // Annotations
    register<bit<8>>(CS_WIDTH) cs_dst_safe_1_wid;
    register<bit<8>>(CS_WIDTH) cs_dst_safe_2_wid;
    register<bit<8>>(CS_WIDTH) cs_dst_safe_3_wid;
    register<bit<8>>(CS_WIDTH) cs_dst_safe_4_wid;  

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

    // Defense Readiness State
    register<bit<8>>(1) dr_state; 

    // Debug Mode Flag
    register<int<8>>(1) debug_mode;

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
            bit<32> current_wid;
            ow_counter.read(current_wid, 0);

            // Obtain Defense Readiness state from the register.
            bit<8> dr_state_aux;
            dr_state.read(dr_state_aux, 0);

            // Obtain mitigation threshold from the register
            int<32> mitigation_t_aux;
            mitigation_t.read(mitigation_t_aux, 0);

            // Auxiliary variables for counter and annotation:
            int<32> c_aux;
            bit<8>  ow_aux;

            // --------------------------------------------------------------------------------------------------------            
            // Beginning of source address frequency and entropy norm estimation.

            // Obtain column IDs for all rows
            bit<32> src_hash_1;
            bit<32> src_hash_2;
            bit<32> src_hash_3;
            bit<32> src_hash_4;
            cs_hash(hdr.ipv4.src_addr, src_hash_1, src_hash_2, src_hash_3, src_hash_4);

            // Determine whether to increase or decrease counters
            int<32> src_ghash_1;
            int<32> src_ghash_2;
            int<32> src_ghash_3;
            int<32> src_ghash_4;
            cs_ghash(hdr.ipv4.src_addr, src_ghash_1, src_ghash_2, src_ghash_3, src_ghash_4);

            // Estimate Frequencies for Source Addresses

            // Variables for counters and annotations.
            int<32> src_curr_1;
            bit<8>  src_curr_1_wid;
            int<32> src_curr_2;
            bit<8>  src_curr_2_wid;
            int<32> src_curr_3;
            bit<8>  src_curr_3_wid;
            int<32> src_curr_4;
            bit<8>  src_curr_4_wid;

            // Read counters and annotations.
            cs_src_curr_1.read(src_curr_1, src_hash_1);                     // Read current counter.
            cs_src_curr_1_wid.read(src_curr_1_wid, src_hash_1);             // Read current annotation. 
            cs_src_curr_2.read(src_curr_2, src_hash_2);                     // Read current counter.
            cs_src_curr_2_wid.read(src_curr_2_wid, src_hash_2);             // Read current annotation. 
            cs_src_curr_3.read(src_curr_3, src_hash_3);                     // Read current counter.
            cs_src_curr_3_wid.read(src_curr_3_wid, src_hash_3);             // Read current annotation. 
            cs_src_curr_4.read(src_curr_4, src_hash_4);                     // Read current counter.
            cs_src_curr_4_wid.read(src_curr_4_wid, src_hash_4);             // Read current annotation. 

            // Row 1 Estimate
            if (src_curr_1_wid != current_wid[7:0]) {                       // If we're in a different window:
                if (current_wid[7:0] > 1 && dr_state_aux == 0) {            // If we're not in the first window.
                    cs_src_last_1.read(c_aux, src_hash_1);                  // Read counter from Wlast.
                    cs_src_last_1_wid.read(ow_aux, src_hash_1);             // Read annotation from Wlast. 
                    cs_src_safe_1.write(src_hash_1, c_aux);                 // Copy Wlast counter to Wsafe.
                    cs_src_safe_1_wid.write(src_hash_1, ow_aux);            // Copy Wlast annotation to Wsafe.
                }     
                cs_src_last_1.write(src_hash_1, src_curr_1);                // Copy Wcurr counter to Wlast.
                cs_src_last_1_wid.write(src_hash_1, src_curr_1_wid);        // Copy wcurr annotation to Wlast.
                src_curr_1 = 0;                                             // Reset the counter.
                cs_src_curr_1_wid.write(src_hash_1, current_wid[7:0]);      // Update the annotation. 
            }

            // Row 2 Estimate
            if (src_curr_2_wid != current_wid[7:0]) {                       // If we're in a different window:
                if (current_wid[7:0] > 1 && dr_state_aux == 0) {            // If we're not in the first window.
                    cs_src_last_2.read(c_aux, src_hash_2);                  // Read counter from Wlast.
                    cs_src_last_2_wid.read(ow_aux, src_hash_2);             // Read annotation from Wlast. 
                    cs_src_safe_2.write(src_hash_2, c_aux);                 // Copy Wlast counter to Wsafe.
                    cs_src_safe_2_wid.write(src_hash_2, ow_aux);            // Copy Wlast annotation to Wsafe.
                }     
                cs_src_last_2.write(src_hash_2, src_curr_2);                // Copy Wcurr counter to Wlast.
                cs_src_last_2_wid.write(src_hash_2, src_curr_2_wid);        // Copy wcurr annotation to Wlast.
                src_curr_2 = 0;                                             // Reset the counter.
                cs_src_curr_2_wid.write(src_hash_2, current_wid[7:0]);      // Update the annotation. 
            }

            // Row 3 Estimate
            if (src_curr_3_wid != current_wid[7:0]) {                       // If we're in a different window:
                if (current_wid[7:0] > 1 && dr_state_aux == 0) {            // If we're not in the first window.
                    cs_src_last_3.read(c_aux, src_hash_3);                  // Read counter from Wlast.
                    cs_src_last_3_wid.read(ow_aux, src_hash_3);             // Read annotation from Wlast. 
                    cs_src_safe_3.write(src_hash_3, c_aux);                 // Copy Wlast counter to Wsafe.
                    cs_src_safe_3_wid.write(src_hash_3, ow_aux);            // Copy Wlast annotation to Wsafe.
                }     
                cs_src_last_3.write(src_hash_3, src_curr_3);                // Copy Wcurr counter to Wlast.
                cs_src_last_3_wid.write(src_hash_3, src_curr_3_wid);        // Copy wcurr annotation to Wlast.
                src_curr_3 = 0;                                             // Reset the counter.
                cs_src_curr_3_wid.write(src_hash_3, current_wid[7:0]);      // Update the annotation. 
            }

            // Row 4 Estimate
            if (src_curr_4_wid != current_wid[7:0]) {                       // If we're in a different window:
                if (current_wid[7:0] > 1 && dr_state_aux == 0) {            // If we're not in the first window.
                    cs_src_last_4.read(c_aux, src_hash_4);                  // Read counter from Wlast.
                    cs_src_last_4_wid.read(ow_aux, src_hash_4);             // Read annotation from Wlast. 
                    cs_src_safe_4.write(src_hash_4, c_aux);                 // Copy Wlast counter to Wsafe.
                    cs_src_safe_4_wid.write(src_hash_4, ow_aux);            // Copy Wlast annotation to Wsafe.
                }     
                cs_src_last_4.write(src_hash_4, src_curr_4);                // Copy Wcurr counter to Wlast.
                cs_src_last_4_wid.write(src_hash_4, src_curr_4_wid);        // Copy wcurr annotation to Wlast.
                src_curr_4 = 0;                                             // Reset the counter.
                cs_src_curr_4_wid.write(src_hash_4, current_wid[7:0]);      // Update the annotation. 
            }

            // Update the counters.
            src_curr_1 = src_curr_1 + src_ghash_1;                          // Update the counter.
            src_curr_2 = src_curr_2 + src_ghash_2;                          // Update the counter.
            src_curr_3 = src_curr_3 + src_ghash_3;                          // Update the counter.
            src_curr_4 = src_curr_4 + src_ghash_4;                          // Update the counter.
            
            // Write the counters back to the sketches.
            cs_src_curr_1.write(src_hash_1, src_curr_1);                    // Write the counter.
            cs_src_curr_2.write(src_hash_2, src_curr_2);                    // Write the counter.
            cs_src_curr_3.write(src_hash_3, src_curr_3);                    // Write the counter.
            cs_src_curr_4.write(src_hash_4, src_curr_4);                    // Write the counter.

            // ghash and the counter have the same sign; this computes the absolute value.
            src_curr_1 = src_curr_1 * src_ghash_1;                         
            src_curr_2 = src_curr_2 * src_ghash_2;                          
            src_curr_3 = src_curr_3 * src_ghash_3;                          
            src_curr_4 = src_curr_4 * src_ghash_4;                          

            // At this point, we have updated counters in src_curr_1, src_curr_2, src_curr_3, and src_curr_4.

            // Count Sketch Source IP Frequency Estimate: store it in meta.ip_count.
            median(src_curr_1, src_curr_2, src_curr_3, src_curr_4, meta.ip_count);

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
            bit<32> dst_hash_1;
            bit<32> dst_hash_2;
            bit<32> dst_hash_3;
            bit<32> dst_hash_4;
            cs_hash(hdr.ipv4.dst_addr, dst_hash_1, dst_hash_2, dst_hash_3, dst_hash_4);

            // Determine whether to increase or decrease counters
            int<32> dst_ghash_1;
            int<32> dst_ghash_2;
            int<32> dst_ghash_3;
            int<32> dst_ghash_4;
            cs_ghash(hdr.ipv4.dst_addr, dst_ghash_1, dst_ghash_2, dst_ghash_3, dst_ghash_4);

            // Estimate Frequencies for Destination Addresses

            // Variables for counters and annotations.
            int<32> dst_curr_1;
            bit<8>  dst_curr_1_wid;
            int<32> dst_curr_2;
            bit<8>  dst_curr_2_wid;
            int<32> dst_curr_3;
            bit<8>  dst_curr_3_wid;
            int<32> dst_curr_4;
            bit<8>  dst_curr_4_wid;

            // Read counters and annotations.
            cs_dst_curr_1.read(dst_curr_1, dst_hash_1);                     // Read current counter.
            cs_dst_curr_1_wid.read(dst_curr_1_wid, dst_hash_1);             // Read current annotation. 
            cs_dst_curr_2.read(dst_curr_2, dst_hash_2);                     // Read current counter.
            cs_dst_curr_2_wid.read(dst_curr_2_wid, dst_hash_2);             // Read current annotation. 
            cs_dst_curr_3.read(dst_curr_3, dst_hash_3);                     // Read current counter.
            cs_dst_curr_3_wid.read(dst_curr_3_wid, dst_hash_3);             // Read current annotation. 
            cs_dst_curr_4.read(dst_curr_4, dst_hash_4);                     // Read current counter.
            cs_dst_curr_4_wid.read(dst_curr_4_wid, dst_hash_4);             // Read current annotation. 

            // Row 1 Estimate
            if (dst_curr_1_wid != current_wid[7:0]) {                       // If we're in a different window:
                if (current_wid[7:0] > 1 && dr_state_aux == 0) {            // If we're not in the first window.
                    cs_dst_last_1.read(c_aux, dst_hash_1);                  // Read counter from Wlast.
                    cs_dst_last_1_wid.read(ow_aux, dst_hash_1);             // Read annotation from Wlast. 
                    cs_dst_safe_1.write(dst_hash_1, c_aux);                 // Copy Wlast counter to Wsafe.
                    cs_dst_safe_1_wid.write(dst_hash_1, ow_aux);            // Copy Wlast annotation to Wsafe.
                }     
                cs_dst_last_1.write(dst_hash_1, dst_curr_1);                // Copy Wcurr counter to Wlast.
                cs_dst_last_1_wid.write(dst_hash_1, dst_curr_1_wid);        // Copy wcurr annotation to Wlast.
                dst_curr_1 = 0;                                             // Reset the counter.
                cs_dst_curr_1_wid.write(dst_hash_1, current_wid[7:0]);      // Update the annotation. 
            }

            // Row 2 Estimate
            if (dst_curr_2_wid != current_wid[7:0]) {                       // If we're in a different window:
                if (current_wid[7:0] > 1 && dr_state_aux == 0) {            // If we're not in the first window.
                    cs_dst_last_2.read(c_aux, dst_hash_2);                  // Read counter from Wlast.
                    cs_dst_last_2_wid.read(ow_aux, dst_hash_2);             // Read annotation from Wlast. 
                    cs_dst_safe_2.write(dst_hash_2, c_aux);                 // Copy Wlast counter to Wsafe.
                    cs_dst_safe_2_wid.write(dst_hash_2, ow_aux);            // Copy Wlast annotation to Wsafe.
                }     
                cs_dst_last_2.write(dst_hash_2, dst_curr_2);                // Copy Wcurr counter to Wlast.
                cs_dst_last_2_wid.write(dst_hash_2, dst_curr_2_wid);        // Copy wcurr annotation to Wlast.
                dst_curr_2 = 0;                                             // Reset the counter.
                cs_dst_curr_2_wid.write(dst_hash_2, current_wid[7:0]);      // Update the annotation. 
            }

            // Row 3 Estimate
            if (dst_curr_3_wid != current_wid[7:0]) {                       // If we're in a different window:
                if (current_wid[7:0] > 1 && dr_state_aux == 0) {            // If we're not in the first window.
                    cs_dst_last_3.read(c_aux, dst_hash_3);                  // Read counter from Wlast.
                    cs_dst_last_3_wid.read(ow_aux, dst_hash_3);             // Read annotation from Wlast. 
                    cs_dst_safe_3.write(dst_hash_3, c_aux);                 // Copy Wlast counter to Wsafe.
                    cs_dst_safe_3_wid.write(dst_hash_3, ow_aux);            // Copy Wlast annotation to Wsafe.
                }     
                cs_dst_last_3.write(dst_hash_3, dst_curr_3);                // Copy Wcurr counter to Wlast.
                cs_dst_last_3_wid.write(dst_hash_3, dst_curr_3_wid);        // Copy wcurr annotation to Wlast.
                dst_curr_3 = 0;                                             // Reset the counter.
                cs_dst_curr_3_wid.write(dst_hash_3, current_wid[7:0]);      // Update the annotation. 
            }

            // Row 4 Estimate
            if (dst_curr_4_wid != current_wid[7:0]) {                       // If we're in a different window:
                if (current_wid[7:0] > 1 && dr_state_aux == 0) {            // If we're not in the first window.
                    cs_dst_last_4.read(c_aux, dst_hash_4);                  // Read counter from Wlast.
                    cs_dst_last_4_wid.read(ow_aux, dst_hash_4);             // Read annotation from Wlast. 
                    cs_dst_safe_4.write(dst_hash_4, c_aux);                 // Copy Wlast counter to Wsafe.
                    cs_dst_safe_4_wid.write(dst_hash_4, ow_aux);            // Copy Wlast annotation to Wsafe.
                }     
                cs_dst_last_4.write(dst_hash_4, dst_curr_4);                // Copy Wcurr counter to Wlast.
                cs_dst_last_4_wid.write(dst_hash_4, dst_curr_4_wid);        // Copy wcurr annotation to Wlast.
                dst_curr_4 = 0;                                             // Reset the counter.
                cs_dst_curr_4_wid.write(dst_hash_4, current_wid[7:0]);      // Update the annotation. 
            }

            // Update the counters.
            dst_curr_1 = dst_curr_1 + dst_ghash_1;                          // Update the counter.
            dst_curr_2 = dst_curr_2 + dst_ghash_2;                          // Update the counter.
            dst_curr_3 = dst_curr_3 + dst_ghash_3;                          // Update the counter.
            dst_curr_4 = dst_curr_4 + dst_ghash_4;                          // Update the counter.
            
            // Write the counters back to the sketches.
            cs_dst_curr_1.write(dst_hash_1, dst_curr_1);                    // Write the counter.
            cs_dst_curr_2.write(dst_hash_2, dst_curr_2);                    // Write the counter.
            cs_dst_curr_3.write(dst_hash_3, dst_curr_3);                    // Write the counter.
            cs_dst_curr_4.write(dst_hash_4, dst_curr_4);                    // Write the counter.

            // ghash and the counter have the same sign; this computes the absolute value.
            dst_curr_1 = dst_curr_1 * dst_ghash_1;                         
            dst_curr_2 = dst_curr_2 * dst_ghash_2;                          
            dst_curr_3 = dst_curr_3 * dst_ghash_3;                          
            dst_curr_4 = dst_curr_4 * dst_ghash_4;                          

            // At this point, we have updated counters in dst_curr_1, dst_curr_2, dst_curr_3, and dst_curr_4.

            // Count Sketch Destination IP Frequency Estimate
            median(dst_curr_1, dst_curr_2, dst_curr_3, dst_curr_4, meta.ip_count);

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
                current_wid = current_wid + 1;
                ow_counter.write(0, current_wid); // Save the number of the new OW in its register. 

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

                if (current_wid == 0) {                           // In the first window... [changed to 0th window, which will never happen.]
                    meta.src_ewma = meta.src_entropy << 14;      // Initialize averages with the first estimated entropies. Averages have 18 fractional bits. 
                    meta.src_ewmmd = 0;
                    meta.dst_ewma = meta.dst_entropy << 14;
                    meta.dst_ewmmd = 0;
                 } else {                                            // Beginning with the second window... 
                    meta.alarm = 0;                                  // By default, there's no alarm. 

                    // Step 3: If we detect an anomaly, signal this condition. Otherwise, just update the moving averages. 

                    bit<32> training_len_aux;
                    training_len.read(training_len_aux, 0);
                    if (current_wid > training_len_aux) {            // If we've finished training, we check for anomalies.
                        bit<8> k_aux;
                        k.read(k_aux, 0);

                        bit<32> src_thresh;
                        src_thresh = meta.src_ewma + ((bit<32>)k_aux*meta.src_ewmmd >> 3);  // k has 3 fractional bits.

                        bit<32> dst_thresh;
                        dst_thresh = meta.dst_ewma - ((bit<32>)k_aux*meta.dst_ewmmd >> 3);

                        if ((meta.src_entropy << 14) > src_thresh || (meta.dst_entropy << 14) < dst_thresh) { // ANOMALY DETECTED. 
                            meta.alarm = 1;  
                            meta.dr_state = 1; 
                            dr_state.write(0, 1);                     // When dr_state = 1, the switch stays "on alert".
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

                // Check whether we should reset Defense Readiness or not. 
                dr_state.read(meta.dr_state,0);
                if (meta.alarm == 0 && meta.dr_state == 1) {
                    dr_state.write(0, 0);
                }

                // Generate a signaling packet. 
                clone3(CloneType.I2E, ALARM_SESSION, { meta.pkt_num, meta.src_entropy, meta.src_ewma, meta.src_ewmmd, meta.dst_entropy, meta.dst_ewma, meta.dst_ewmmd, meta.alarm, meta.dr_state });

            } // End OW summarization. 

            // End of Step 1 (OW Summarization)
            // --------------------------------------------------------------------------------------------------------

            // --------------------------------------------------------------------------------------------------------
            // Beginning of Defense-Readiness Processing. 

            // Divert has a default value of zero.
            // It will be set to one for packets that should undergo external inspection.
            bit<1> divert;
            divert = 0;

            if (dr_state_aux == 1) {  // Mitigation is active.        
              
                // Frequency Variation Analysis

                // These variables will hold the estimated counters for Wlast and Wsafe. 
                int<32> f_src_last;
                int<32> f_src_safe;
                int<32> f_dst_last;
                int<32> f_dst_safe;

                int<32> v_src;
                int<32> v_dst;
                int<32> v;
                
                // Get the estimated counter for the source address at Wlast.
                cs_src_last_1.read(src_curr_1, src_hash_1);
                cs_src_last_2.read(src_curr_2, src_hash_2);
                cs_src_last_3.read(src_curr_3, src_hash_3);
                cs_src_last_4.read(src_curr_4, src_hash_4);
                src_curr_1 = src_curr_1 * src_ghash_1;
                src_curr_2 = src_curr_2 * src_ghash_2;
                src_curr_3 = src_curr_3 * src_ghash_3;
                src_curr_4 = src_curr_4 * src_ghash_4;
                median(src_curr_1, src_curr_2, src_curr_3, src_curr_4, f_src_last);

                // Get the estimated counter for the source address at Wsafe.
                cs_src_safe_1.read(src_curr_1, src_hash_1);
                cs_src_safe_2.read(src_curr_2, src_hash_2);
                cs_src_safe_3.read(src_curr_3, src_hash_3);
                cs_src_safe_4.read(src_curr_4, src_hash_4);
                src_curr_1 = src_curr_1 * src_ghash_1;
                src_curr_2 = src_curr_2 * src_ghash_2;
                src_curr_3 = src_curr_3 * src_ghash_3;
                src_curr_4 = src_curr_4 * src_ghash_4;
                median(src_curr_1, src_curr_2, src_curr_3, src_curr_4, f_src_safe);

                // Get the estimated counter for the destination address at Wlast.
                cs_dst_last_1.read(dst_curr_1, dst_hash_1);
                cs_dst_last_2.read(dst_curr_2, dst_hash_2);
                cs_dst_last_3.read(dst_curr_3, dst_hash_3);
                cs_dst_last_4.read(dst_curr_4, dst_hash_4);
                dst_curr_1 = dst_curr_1 * dst_ghash_1;
                dst_curr_2 = dst_curr_2 * dst_ghash_2;
                dst_curr_3 = dst_curr_3 * dst_ghash_3;
                dst_curr_4 = dst_curr_4 * dst_ghash_4;
                median(dst_curr_1, dst_curr_2, dst_curr_3, dst_curr_4, f_dst_last);

                // Get the estimated counter for the destination address at Wsafe.
                cs_dst_safe_1.read(dst_curr_1, dst_hash_1);
                cs_dst_safe_2.read(dst_curr_2, dst_hash_2);
                cs_dst_safe_3.read(dst_curr_3, dst_hash_3);
                cs_dst_safe_4.read(dst_curr_4, dst_hash_4);
                dst_curr_1 = dst_curr_1 * dst_ghash_1;
                dst_curr_2 = dst_curr_2 * dst_ghash_2;
                dst_curr_3 = dst_curr_3 * dst_ghash_3;
                dst_curr_4 = dst_curr_4 * dst_ghash_4;
                median(dst_curr_1, dst_curr_2, dst_curr_3, dst_curr_4, f_dst_safe);

                // Compute the frequency variations.
                v_src = f_src_last - f_src_safe;
                v_dst = f_dst_last - f_dst_safe;
                v = v_dst - v_src;

                // Packet Classification

                // Normal operation mode: check whether the frequency variation has exceeded the mitigation threshold.
                // if (v > mitigation_t_aux) {
                //     divert = 1;
                // } 

                // Debug mode: write the values in the packet. 
                // Note: the maximum count is 2^18; we divide it by four to make sure it fits in the header field. 
                hdr.ipv4.identification = (bit<16>) v_src[17:2] ;
                hdr.ipv4.hdr_checksum   = (bit<16>) v_dst[17:2] ;


            } // End of Defense-Readiness Processing. 

            // Policy Enforcement. 

            // Debug mode: unconditional divert
            divert = 1;

            // Divert is set to one for packets that must undergo further inspection.
            if (divert == 0) {
                ipv4_fib.apply();       // Use the regular forwarding table.
            }
            else { 
                ipv4_dpi_fib.apply();   // Use the "deep packet inspection" forwarding table. 
            }

            // End of Policy Enforcement. 
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
            hdr.ddosd.dr_state = meta.dr_state;
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
