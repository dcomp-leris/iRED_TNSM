#include <core.p4>
#include <t2na.p4>

/*** Types of variable ***/
typedef bit<4> header_type_t;
typedef bit<4> header_info_t;
typedef bit<32> number_of_ports_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
typedef bit<16> value_t;
typedef bit<10> index_t;

/*** Constants ***/
const number_of_ports_t N_PORTS                = 512;
const header_type_t HEADER_TYPE_NORMAL_PKT     = 0;
const header_type_t HEADER_TYPE_MIRROR_EGRESS  = 1;
const ether_type_t ETHERTYPE_IPV4              = 16w0x0800;
const value_t TARGET_DELAY                     = 20000000;  // 20 ms
const value_t TARGET_DELAY_DOUBLE              = 40000000;  // 40ms

#define INTERNAL_HEADER         \
    header_type_t header_type;  \
    header_info_t header_info

/*** Headers ***/
header ethernet_h {
    mac_addr_t dst_mac_addr;
    mac_addr_t src_mac_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<5>  diffserv;
    bit<1>  l4s;
    bit<2>  ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

/*** Mirror Header to carry port metadata ***/
header mirror_h {
    INTERNAL_HEADER;
    @flexible PortId_t egress_port;
    @flexible MirrorId_t  mirror_session;
    @flexible bit<48> egress_global_tstamp;
}

//*** Bridge header to carry ingress timestamp from Ingress to Egress ***//
header bridge_h {
    bit<48> ingress_global_tstamp;
}

struct headers_t {
    bridge_h            bridge;
    mirror_h            mirror;
    ethernet_h          ethernet;
    ipv4_h              ipv4;
}

struct metadata_t{
    bridge_h    bridge;
    mirror_h    mirror;
    MirrorId_t  mirror_session;
    PortId_t    egress_port;
    header_type_t header_type;
    header_info_t header_info;
    bit<48> egress_global_tstamp;
    bit<32> queue_delay;
}


// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
       pkt.extract(ig_intr_md);
        transition select(ig_intr_md.ingress_port){
            (256): parse_mirror;
            (_): parse_port_metadata;
        }
    }

    /* NORMAL PKTS */
    state parse_port_metadata{
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    /* E2E MIRRORED PKTS */
    state parse_mirror{
        pkt.advance(PORT_METADATA_SIZE);
        pkt.extract(hdr.mirror);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}


// SwitchIngress
control SwitchIngress(
        inout headers_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    
    bit<32> recirculationTime;
    Register<bit<32>, _> (1) recircTime;
    Register<bit<16>, _>(N_PORTS) congest_port;
    Counter<bit<32>, bit<32>>(N_PORTS, CounterType_t.PACKETS) drop_cloned_pkt;
    Counter<bit<32>, bit<32>>(N_PORTS, CounterType_t.PACKETS) drop_regular_pkt;


    RegisterAction<bit<16>, bit<16>, bit<16>>(congest_port) write_congest_port = {
            void apply(inout bit<16> value){
                value = 1;
            }
    };

    RegisterAction<bit<16>, bit<16>, bit<16>>(congest_port) read_congest_port = {
            void apply(inout bit<16> value, out bit<16> port){
                
                port = value;
            
                value = 0;
            
            }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(recircTime) recirc_action = {
            void apply(inout bit<32> value) {
                value = recirculationTime;
            }

    };


    action drop_regular_pkts(){
        ig_intr_dprsr_md.drop_ctl = 0x1;
    }

    action drop_cloned_pkts(){
        ig_intr_dprsr_md.drop_ctl = 0x1;
    }

    apply {
        
        //* Check for cloned pkts *//
        if (ig_intr_md.ingress_port == 256){
            
            //* Cloned pkts *//
            //* Turn ON congestion flag. Write '1' in the register index port *//
            write_congest_port.execute((bit<16>)hdr.mirror.egress_port);
            
            //* Compute recirculation time from egress to ingress *//
            recirculationTime = (bit<32>)ig_intr_prsr_md.global_tstamp - (bit<32>)hdr.mirror.egress_global_tstamp;
            recirc_action.execute(0);

            //* Drop cloned pkt *//
            drop_cloned_pkt.count((bit<32>)hdr.mirror.egress_port);
            drop_cloned_pkts();

        }else{
            
           if (ig_intr_md.ingress_port == 264) {
                ig_tm_md.ucast_egress_port = 265;
            }
            else if (ig_intr_md.ingress_port == 265) {
                ig_tm_md.ucast_egress_port = 264;
            }

            if (hdr.ipv4.l4s == 1){
                //* L4S queue *//
                ig_tm_md.qid=1;
            
            }else{
                //* Classic queue *//
                ig_tm_md.qid=0;
            
            }
    
            //* Read the output port state from the register*//
            bit<16> flag;
            flag = read_congest_port.execute((bit<16>)ig_tm_md.ucast_egress_port);
            
            //* Check if the congestion flag is 1 (Drop ON). *//
                    
                if(flag == 1){
                
                    if (hdr.ipv4.l4s != 1){ //for L4S not drop.
                        
                        drop_regular_pkt.count((bit<32>)ig_tm_md.ucast_egress_port);
                        drop_regular_pkts();

                    }
                }            

            //** Insert ingress timestamp into bridge header to be used in the egress**//
            hdr.bridge.setValid();
            hdr.bridge.ingress_global_tstamp = ig_intr_prsr_md.global_tstamp;
            
        }
    }    
    
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    Checksum() ipv4_checksum;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.l4s,
            hdr.ipv4.ecn,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr});
        pkt.emit(hdr.bridge);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}


// ---------------------------------------------------------------------------
// Traffic Manager - non-programmable block (queues)
// ---------------------------------------------------------------------------
// TM will receive the packet cloned at the Egress, and will recirculate this 
// packet to the Ingress.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser EgressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        transition select(eg_intr_md.egress_port){
            (256): parse_mirror;
            (_): parse_bridge;
        }
    }

    /** E2E MIRRORED PKTS **/
    state parse_mirror{
        pkt.extract(hdr.mirror);
        transition accept;
    }


    state parse_bridge{
        pkt.extract(hdr.bridge);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control Egress(
        inout headers_t hdr,
        inout metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
        
        value_t queue_delay_current;
        value_t queue_delay;
        value_t EWMA;
        bit<16> rand_classic;
        bit<16> rand_l4s;
        
        Counter<bit<32>, bit<32>>(N_PORTS, CounterType_t.PACKETS) mark_ecn_pkt;
        Register<bit<16>, bit<16>>(N_PORTS) qdelay_classic;
        Register<bit<16>, bit<16>>(N_PORTS) qdelay_l4s;
        Register<bit<16>, bit<16>>(N_PORTS) dropProbability;
        Register<bit<16>, bit<16>>(N_PORTS) target_violation;
        Random<bit<16>>() rand;
        MathUnit<bit<16>>(MathOp_t.DIV, 1) right_shift;


        RegisterAction<bit<16>, bit<16>, bit<16>>(qdelay_classic) qdelay_classic_action = {
            void apply(inout bit<16> value, out bit<16> result) {
                //* Compute Exponentially-Weighted Mean Average (EWMA) of queue delay *//
                // EWMA = alpha*qdelay + (1 - alpha)*previousEWMA
                // We use alpha = 0.5 such that multiplications can be replaced by bit shifts
                bit<16> avg_temp;
                
                avg_temp =  queue_delay + value;
               
                // update register        
                value = avg_temp;
                result = avg_temp;
            }

        };

        RegisterAction<bit<16>, bit<16>, bit<16>>(qdelay_l4s) qdelay_l4s_action = {
            void apply(inout bit<16> value, out bit<16> result) {
                
                    
                //* Compute Exponentially-Weighted Mean Average (EWMA) of queue delay *//
                // EWMA = alpha*qdelay + (1 - alpha)*previousEWMA
                // We use alpha = 0.5 such that multiplications can be replaced by bit shifts
                bit<16> avg_temp;
              
                avg_temp =  queue_delay + value;
               
                // update register        
                value = avg_temp;
                result = avg_temp;
              

            }

        };


        RegisterAction<bit<16>, bit<16>, bool>(dropProbability) getProb_l4s = {
            void apply(inout bit<16> value, out bool result){

                if (rand_l4s < value){
                    
                    value = value - 1;
                    result = true;

                }else{

                    value = value + 1;
                    result = false;
                
                }
            }
        };
        
        RegisterAction<bit<16>, bit<16>, bool>(dropProbability) getProb_classic = {
            void apply(inout bit<16> value, out bool result){
                if (rand_classic < value){

                    value = value - 1;
                    result = true;
                
                }else{

                    value = value + 1;
                    result = false;
                
                }
            }
        };

        RegisterAction<bit<16>, bit<16>, bit<16>>(target_violation) compute_target_violations = {
            void apply(inout bit<16> value, out bit<16> violation){

                value = EWMA;
                
                //* No drop *//
                if (value <= TARGET_DELAY){
                    
                    violation = 0;
                }

                //* Maybe drop *//
                if ((value > TARGET_DELAY) && (value < TARGET_DELAY_DOUBLE)){
                    
                    violation = 1;

                }

                //* Drop *//
                if (value > TARGET_DELAY_DOUBLE){

                    violation = 2;

                }

            }
        };    


        action decisionMirror(){
            hdr.mirror.egress_port = eg_intr_md.egress_port;
            hdr.mirror.header_info = 1;
            hdr.mirror.mirror_session = 1;
            eg_intr_dprs_md.mirror_type = HEADER_TYPE_MIRROR_EGRESS;
            hdr.mirror.egress_global_tstamp = (bit<48>)eg_intr_md_from_prsr.global_tstamp;
        }
       
    apply {

        //* Only regular pkts *//
        if (eg_intr_md.egress_port != 256){   
            

            //* Compute queue delay *//
            queue_delay = (value_t)eg_intr_md_from_prsr.global_tstamp - (value_t)hdr.bridge.ingress_global_tstamp;
            hdr.bridge.setInvalid();
        

            bit<16> EWMA_temp;
            
            if (hdr.ipv4.l4s == 1){
                EWMA_temp = qdelay_l4s_action.execute((value_t)eg_intr_md.egress_port);
            }else{

                EWMA_temp = qdelay_classic_action.execute((value_t)eg_intr_md.egress_port);
            }
            
            EWMA = EWMA_temp>>1; 

            //* Check if the queue delay reach the target limit *//
            //* 0 = no drop    *//
            //* 1 = Maybe drop *//
            //* 2 = drop       *//

            bit<16> target_violation;
            target_violation = compute_target_violations.execute((bit<16>)eg_intr_md.egress_port);

            if (target_violation == 1){
                
                //* rand_classic is a is a random number, used to compute the new drop probability of Classic flows *//
                //** For each new pkt with average queue occupancy between MinTh-MaxTh, the drop probability will be a double *// 
                rand_classic = rand.get();
                rand_l4s = rand_classic >> 1; //Coupling
                
                bool drop_decision_l4s;
                bool drop_decision_classic;

                if (hdr.ipv4.l4s ==1){

                    drop_decision_l4s = getProb_l4s.execute((bit<16>)eg_intr_md.egress_port);
                    
                    if (drop_decision_l4s == true){
                        
                        mark_ecn_pkt.count((bit<32>)eg_intr_md.egress_port);
                        hdr.ipv4.ecn = 3;    
                    
                    } 

                }else{

                    drop_decision_classic = getProb_classic.execute((bit<16>)eg_intr_md.egress_port);

                    if (drop_decision_classic == true){
                    
                        decisionMirror();

                    }

                }
                
            }else if (target_violation == 2){

         
                if (hdr.ipv4.l4s == 1){
                        mark_ecn_pkt.count((bit<32>)eg_intr_md.egress_port);
                        hdr.ipv4.ecn = 3;

                }else{

                        decisionMirror();

                }
                    
            }

        }
    
    }
}

control EgressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md) {
    
    Mirror() mirror;
    Checksum() ipv4_checksum;
    
    apply {
        if (eg_intr_dprs_md.mirror_type == HEADER_TYPE_MIRROR_EGRESS){
            
            mirror.emit<mirror_h>(hdr.mirror.mirror_session, {hdr.mirror.header_type, 
                                      hdr.mirror.header_info, 
                                      hdr.mirror.egress_port,
                                      hdr.mirror.mirror_session,
                                      hdr.mirror.egress_global_tstamp});
        
        }

        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.l4s,
            hdr.ipv4.ecn,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr});
        
        pkt.emit(hdr);
    }
}


Pipeline(SwitchIngressParser(),
        SwitchIngress(),
        SwitchIngressDeparser(),
        EgressParser(),
        Egress(),
        EgressDeparser()) pipe;

Switch(pipe) main;

