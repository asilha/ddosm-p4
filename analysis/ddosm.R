library(reshape2)
library(stringr)
library(tidyverse)
knitr::opts_chunk$set(tidy=TRUE, tidy.opts=list(width.cutoff=160))

log2n = as.integer(24)  # n is passed to trafg. 
n = as.integer(2^log2n)

pcap_dir = "~/p4sec/ddosm-p4/pcaps"

pcap_csv_m14 = str_c(pcap_dir,"/ddos20m14b/if3_attack_out.csv")
pcap_csv_m16 = str_c(pcap_dir,"/ddos20m16b/if3_attack_out.csv")
pcap_csv_m18 = str_c(pcap_dir,"/ddos20m18b/if3_attack_out.csv")

tcad_m14_k = 4.125
tcad_m16_k = 4.500
tcad_m18_k = 3.625

trace_dir = "~/p4sec/ddosm-p4/lab/ddos20/tcad_logs"

tcad_m14_trace = str_c(trace_dir,"/tcad_m_2_14_k_4.125.log")
tcad_m16_trace = str_c(trace_dir,"/tcad_m_2_16_k_4.500.log")
tcad_m18_trace = str_c(trace_dir,"/tcad_m_2_18_k_3.625.log")

# Function inputs are expressed in numbers of packets.
#   Log2n: Length of the detection phase, passed to trafg (as '-n 1048576', for instance).
#   Log2m: Length of the observation window, passed to tcad JSON file (as '"window_size": 262144', for instance)
# Function outputs are expressed in numbers of observation windows. 

detection = function(log2n, log2m) as.integer(2^(log2n - log2m))     
training  = function(log2n, log2m) as.integer(2^(log2n - log2m - 1)) # Training length = detection / 2 
attack    = function(log2n, log2m) as.integer(2^(log2n - log2m - 1)) # Attack length   = detection / 2
safety    = function(log2n, log2m) as.integer(2^(log2n - log2m - 2)) # Pre-attack and post-attack = attack / 4 (each)

attack_first = function(log2n, log2m) as.integer(training(log2n, log2m) + safety(log2n, log2m) + 1)
attack_last  = function(log2n, log2m) as.integer(training(log2n, log2m) + safety(log2n, log2m) + attack(log2n, log2m))

# We also define a helper function to get the OW number from a packet index.

get_ow = function(index, m) as.integer((index - 1) %/% m + 1) 

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

read_pcap_csv = function(log2n, log2m, pcap_csv) {
  
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
      srcmn=min(src_delta),
      srcq1=quantile(src_delta, 0.25),
      srcq2=median(src_delta),
      srcq3=quantile(src_delta, 0.75),
      srqmx=max(src_delta),
      dstmn=min(dst_delta),
      dstq1=quantile(dst_delta, 0.25),
      dstq2=median(dst_delta),
      dstq3=quantile(dst_delta, 0.75),
      dstmx=max(dst_delta),
      srciqr=IQR(src_delta),
      dstiqr=IQR(dst_delta))
  
  return(result)  
  
}

stats = function(packets, log2n, log2m) {
  
  #attack_first_ow = attack_first(log2n, log2m) + 1
  #attack_last_ow = attack_last(log2n, log2m)  
  
  #query = packets %>% filter(ow>=attack_first_ow, ow<=attack_last_ow)
  
  true_evil = packets %>% ungroup() %>% filter(attack==TRUE) %>% tally()
  true_good = packets %>% ungroup() %>% filter(attack==FALSE) %>% tally()
  message("True evil: ", true_evil, " True good: ", true_good, " Total: ", true_evil + true_good)
  
  class_evil = packets %>% ungroup() %>% filter(divert(src_delta,dst_delta)) %>% tally() 
  class_good = packets %>% ungroup() %>% filter(!divert(src_delta,dst_delta)) %>% tally() 
  message("Class evil: ", class_evil, " Class good: ", class_good, " Total: ", class_evil + class_good)
  
  error_evil = packets %>% ungroup() %>% filter(!divert(src_delta,dst_delta), attack==TRUE)  %>% tally() 
  error_good = packets %>% ungroup() %>% filter(divert(src_delta,dst_delta), attack==FALSE) %>% tally() 
  
  message("FNcount: ", error_evil, " FPcount: ", error_good, " Total: ", error_evil + error_good)
  message("FNR: ", round(error_evil/true_evil,4), " FPR: ", round(error_good/true_good,4))  
  
}

stats_ci = function(packets, log2n, log2m) {
  
  attack_first_ow = attack_first(log2n, log2m) + 1
  attack_last_ow = attack_last(log2n, log2m)
  attack_length = attack_last_ow - attack_first_ow + 1
  m = 2^log2m
  
  tpr = packets %>% 
    filter(ow>=attack_first_ow, ow<=attack_last_ow, attack==TRUE, divert(src_delta, dst_delta)==TRUE) %>% 
    group_by(ow) %>%
    summarize(n = n()) %>%
    summarize(mean = mean(n) / (0.2 * m), margin = qnorm(0.975) * sd(n)/sqrt(attack_length) / (0.2 * m))
  
  fpr = packets %>% 
    filter(ow>=attack_first_ow, ow<=attack_last_ow, attack==FALSE, divert(src_delta, dst_delta)==TRUE) %>% 
    group_by(ow) %>%
    summarize(n = n()) %>%
    summarize(mean = mean(n) / (0.8 * m), margin = qnorm(0.975) * sd(n)/sqrt(attack_length) / (0.8 * m))

  message(str_c("TPR: ", round(tpr$mean,6), " ± ", round(tpr$margin,6)))
  message(str_c("FPR: ", round(fpr$mean,6), " ± ", round(fpr$margin,6)))
  
}


graph_actual_good = function(packets) { packets %>% filter(attack==FALSE)   %>% summarize(n=n()) %>% ggplot(mapping=aes(x=ow,y=n)) + geom_point() + ggtitle("Actual Good") }
graph_actual_evil = function(packets) { packets %>% filter(attack==TRUE)    %>% summarize(n=n()) %>% ggplot(mapping=aes(x=ow,y=n)) + geom_point() + ggtitle("Actual Evil") }

graph_marked_good = function(packets) { packets %>% filter(diverted==FALSE) %>% summarize(n=n()) %>% ggplot(mapping=aes(x=ow,y=n)) + geom_point() + ggtitle("Forwarded") }
graph_marked_evil = function(packets) { packets %>% filter(diverted==TRUE)  %>% summarize(n=n()) %>% ggplot(mapping=aes(x=ow,y=n)) + geom_point() + ggtitle("Diverted")  }

graph_false_negatives = function(packets) { packets %>% filter(!divert(src_delta,dst_delta), attack==TRUE)  %>% summarize(n=n()) %>% ggplot(mapping=aes(x=ow,y=n)) + geom_point() + ggtitle("False Negatives") }
graph_false_positives = function(packets) { packets %>% filter(divert(src_delta,dst_delta), attack==FALSE)  %>% summarize(n=n()) %>% ggplot(mapping=aes(x=ow,y=n)) + geom_point() + ggtitle("False Positives") }

graph_results = function(packets) {
  
  packets %>% group_by(ow, attack, diverted) %>% summarize(n=n()) %>% 
  ggplot(mapping=aes(x=ow, y=n, color=attack, shape=diverted)) + 
  geom_point(size=2.0) + 
  #coord_cartesian(xlim=c(770,810),ylim=c(0,16384)) + 
  labs(x="Observation Window", y="Packet Count", title ="Classification Results") +
  scale_x_continuous(expand=expand_scale(add=0)) + 
  scale_y_continuous(expand=expand_scale(add=0)) +
  scale_color_manual(values=c("seagreen4", "orangered1")) + 
  theme_classic()  

}
