library(reshape2)
library(stringr)
library(svglite)
library(tidyverse)
library(ggthemes)

################################################################################
# Helper Functions 

# Input: packet quantity / index.
# Output: observation window index. 

get_ow = function(index, m) as.integer((index - 1) %/% m + 1) 

# Input: 
#   n: Length of the detection phase, passed to trafg (as '-n 1024000', for instance).
#   m: Length of the observation window, passed to tcad JSON file (as '"window_size": 262144', for instance)
# Output: packet quantity / index. 

detection = function(log2n, log2m) as.integer(2^(log2n - log2m - 10) * 1000)     
training  = function(log2n, log2m) as.integer(detection(log2n, log2m) / 2) # Training length = detection / 2 
attack    = function(log2n, log2m) as.integer(detection(log2n, log2m) / 2) # Attack length   = detection / 2
safety    = function(log2n, log2m) as.integer(detection(log2n, log2m) / 4) # Pre-attack and post-attack lengths = detection / 4 (each)

attack_first = function(log2n, log2m) as.integer(training(log2n, log2m) + safety(log2n, log2m) + 1)
attack_last  = function(log2n, log2m) as.integer(training(log2n, log2m) + safety(log2n, log2m) + attack(log2n, log2m))

################################################################################
# TCAD Traces

read_tcad_trace = function(trace_file) {
  
  col_names = c("ts",
                "src_ent",
                "src_ewma",
                "src_ewmmd",
                "dst_ent",
                "dst_ewma",
                "dst_ewmmd",
                "alarm")
  
  col_types = "ciddiddl"
  
  tcad_trace = readr::read_table2(trace_file,
                                  col_names = col_names,
                                  col_types = col_types)
  
  tcad_trace = tcad_trace %>% tibble::rowid_to_column("ow")
  
  # Entropy values: 4 fractional bits.
  # EWMA/EWMMD: 18 fractional bits.
  
  tcad_trace = tcad_trace %>% dplyr::mutate(
    src_ent   = src_ent/16,
    dst_ent   = dst_ent/16,
    src_ewma  = src_ewma/262144,
    dst_ewma  = dst_ewma/262144,
    src_ewmmd = src_ewmmd/262144,
    dst_ewmmd = dst_ewmmd/262144)  
  return(tcad_trace)
  
}

get_plot_tcad = function(tcad, k) {
  
  plot_options = list(  
    labs(x="OW number", y="Entropy"),
    geom_point(mapping=aes(y=src_ent), size=0.25, color="seagreen4"), 
    geom_point(mapping=aes(y=dst_ent), size=0.25, color="steelblue4"),
    geom_line(mapping=aes(y=src_ewma+k*src_ewmmd), color="seagreen4"),
    geom_line(mapping=aes(y=dst_ewma-k*dst_ewmmd), color="steelblue4"),
    theme_classic())
  
  plot = tcad %>% ggplot(mapping=aes(x=ow)) + plot_options
  
  return(plot)
}

get_plot_tcad_attack = function(tcad, tcad_k, log2n, log2m) {
  
  first = attack_first(log2n, log2m) + 1
  last  = attack_last(log2n, log2m)
  
  plot = get_plot_tcad(tcad %>% filter(ow>=first, ow<=last), tcad_k) 
  
  return(plot)
  
}

################################################################################
# Packet Traces

read_pcap_csv = function(log2n, log2m, pcap_csv, attack_only) {
  
  m = as.integer(2^log2m)
  
  # This is the format of the CSV files we import.
  col_types = cols(
    src = col_character(),
    dst = col_character(),
    src_delta = col_character(),
    dst_delta = col_character(),
    attack = col_logical())
  
  packets = read_csv(pcap_csv, col_types = col_types)  
  
  # Add index column.
  packets = packets %>% tibble::rowid_to_column("index")
  
  # Add an offset to compensate the pre-initializing of training coefficients.
  offset = training(log2n, log2m) * m 
  packets = packets %>% mutate(index = index + offset)
  
  # Add OW numbers.
  packets = packets %>% mutate(ow = get_ow(index,m)) 
  
  # Adjust numeric representations of src_delta and dst_delta. 
  
  # Convert from hexadecimal to decimal
  packets = packets %>% mutate_at(vars(src_delta, dst_delta), funs(strtoi)) 
  
  # Convert from 16-bit two's complement representation to integer representation. 
  twos_complement = function(x) as.integer(ifelse(x > 32767, x - 65536, x))
  packets = packets %>% mutate_at(vars(src_delta, dst_delta), funs(twos_complement)) 
  
  # Add the difference between dst_delta and src_delta
  packets = packets %>% mutate(diff = dst_delta - src_delta)
  
  # Keep only the attack phase. 
  
  if (attack_only) {
    # Original experiments.
    # packets = packets %>% filter(ow >= attack_first(log2n,log2m) + 2, ow <= attack_last(log2n,log2m))
    # Let's see what happens when we don't filter out the window at which Euclid detects the attack.
    packets = packets %>% filter(ow >= attack_first(log2n,log2m) + 1, ow <= attack_last(log2n,log2m)) 
  } 
  
  return(packets)
  
}

check_first_attack_ow = function(log2n, log2m, packets) {
  
  m = as.integer(2^log2m)
  
  attack_first_ow = attack_first(log2n, log2m)
  attack_last_ow = attack_last(log2n, log2m)
  
  attack_first_packet = (attack_first_ow - 1) * m + 1
  attack_last_packet  = (attack_last_ow) * m
  
  message(str_c(attack_first_ow, attack_last_ow, attack_first_packet, attack_last_packet, sep="\n"))
  
  packets %>% filter(index >= attack_first_packet)    
  
}

summarize_deltas = function (log2n, log2m, packets) {
  
  attack_first_ow = attack_first(log2n, log2m) + 1
  attack_last_ow = attack_last(log2n, log2m)  
  
  result = packets %>%
    filter(ow >= attack_first_ow, ow<=attack_last_ow) %>%
    group_by(ow, attack) %>% 
    summarize(
      diffmin=min(diff),
      diffq1=quantile(diff, 0.10),
      diffq2=median(diff),
      diffq3=quantile(diff, 0.90),
      diffmax=max(diff),
      diffiqr=IQR(diff))
  
  return(result)  
  
}

get_stats = function(packets) {
  
  # packets = packets %>% ungroup() 
  
  stats = packets %>% 
    # mutate(tp =  attack & diverted, fp = !attack & diverted) %>% 
    group_by(ow) %>%
    summarize(n_good = sum(!attack),
              n_evil = sum(attack),
              p_good = mean(!attack),
              p_evil = mean(attack),
              n_fwd  = sum(!diverted),
              n_div  = sum(diverted),
              p_fwd  = mean(!diverted),
              p_div  = mean(diverted),
              n_tp   = sum(tp),
              n_fp   = sum(fp)) %>%
    mutate(tpr = n_tp / n_evil,
           fpr = n_fp / n_good)
  
  return (stats)
}

get_summary = function(stats, log2n, log2m, t) {
  
  summary = stats %>% 
    summarize(log2n = log2n,
              log2m  = log2m,
              t = t,
              n = n(),
              t_evil = sum(n_evil),
              t_tp   = sum(n_tp),
              t_good = sum(n_good),
              t_fp   = sum(n_fp)) %>%
    mutate(p_tp = t_tp / t_evil,
           p_fp = t_fp / t_good) %>% 
    mutate(se_tp = sqrt(p_tp * (1 - p_tp) / n),
           se_fp = sqrt(p_fp * (1 - p_fp) / n)) %>% 
    mutate(i95_tp = qnorm(0.975) * se_tp,
           i95_fp = qnorm(0.975) * se_fp) %>%
    mutate(i95_tp_lb = max(p_tp - i95_tp, 0),
           i95_tp_ub = min(p_tp + i95_tp, 1),
           i95_fp_lb = max(p_fp - i95_fp, 0),
           i95_fp_ub = min(p_fp + i95_fp, 1)) %>%
    mutate_if(is.double, funs(round(.,4))) %>%
    select(log2n, log2m, t, 
           p_tp, i95_tp_lb, i95_tp_ub, 
           p_fp, i95_fp_lb, i95_fp_ub)  
  
  return(summary)
  
}

my_ggsave = function(plot, path, filename, width=8, height=6, units="in") { 
  
  ggsave(plot = plot, path = path, filename = stringr::str_c(filename, ".pdf"), width=width, height=height, units=units)
  # ggsave(plot = plot, path = path, filename = stringr::str_c(filename, ".svg"), width=width, height=height, units=units)
  
}

graph_actual_good = function(packets) { packets %>% filter(attack==FALSE)   %>% summarize(n=n()) %>% ggplot(mapping=aes(x=ow,y=n)) + geom_point() + ggtitle("Actual Good") }
graph_actual_evil = function(packets) { packets %>% filter(attack==TRUE)    %>% summarize(n=n()) %>% ggplot(mapping=aes(x=ow,y=n)) + geom_point() + ggtitle("Actual Evil") }

graph_marked_good = function(packets) { packets %>% filter(diverted==FALSE) %>% summarize(n=n()) %>% ggplot(mapping=aes(x=ow,y=n)) + geom_point() + ggtitle("Forwarded") }
graph_marked_evil = function(packets) { packets %>% filter(diverted==TRUE)  %>% summarize(n=n()) %>% ggplot(mapping=aes(x=ow,y=n)) + geom_point() + ggtitle("Diverted")  }

graph_false_negatives = function(packets) { packets %>% filter(diverted==FALSE, attack==TRUE)  %>% summarize(n=n()) %>% ggplot(mapping=aes(x=ow,y=n)) + geom_point() + ggtitle("False Negatives") }
graph_false_positives = function(packets) { packets %>% filter(diverted==TRUE, attack==FALSE)  %>% summarize(n=n()) %>% ggplot(mapping=aes(x=ow,y=n)) + geom_point() + ggtitle("False Positives") }

graph_results = function(packets, m_annotation) {
  
  packets %>% group_by(ow, attack, diverted) %>% summarize(n=n()) %>% 
  ggplot(mapping=aes(x=ow, y=n, color=attack, shape=diverted)) + 
  geom_point(size=2.0) + 
  #coord_cartesian(xlim=c(770,810),ylim=c(0,16384)) + 
  labs(x="Observation Window", y="Packet Count", title = str_c("Classification Results ", m_annotation)) +
  #scale_x_continuous(expand=expand_scale(add=0)) + 
  #scale_y_continuous(expand=expand_scale(add=0)) +
  scale_color_manual(values=c("seagreen4", "orangered1")) + 
  theme_classic()  

}

