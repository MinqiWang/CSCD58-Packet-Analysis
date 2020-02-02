import numpy
from plot import plot_cdf_and_save
import matplotlib.pyplot as plt
import statistics

# Metrics
total_num_pkts = 0 # Total number of packets
total_num_pkts_Ethernet = 0 # Total number of Ethernet packets
total_num_pkts_IP = 0 # Total number of IP packets
total_num_pkts_ICMP = 0 # Total number of ICMP packets
total_num_pkts_TCP = 0 # Total number of TCP packets
total_num_pkts_UDP = 0 # Total nubmer of UDP packets
total_size_pkts_ICMP = 0 # Total size of ICMP packets
all_packets_size = [] # The size of all packets
TCP_packets_size = [] # The size of TCP packets
UDP_packets_size = [] # The size of UDP packets
IP_packets_size = [] # The size of IP packets
non_IP_packets_size = [] # The size of non-IP packets
IP_header_size = [] # The size of IP packet headers
TCP_header_size = [] # The size of TCP packet headers
UDP_header_size = [] # The size of UDP packet headers
flows = dict() # Flow data
           # Format: <Endpoint-Port-Endpoint-Port-Portocol> --> { "Type": <Type>, "Start": <Start_Time>, "End": <End_Time>, "Num_Packets": <Num_Packets>,
           # "Size": <Size>, "Header_Size": <Header_Size>, "Arrival_Time": [ Packet arrival times ... ], "TCP_State": <TCP_State>, "Is_Failed": <If_TCP_Failed>,
           # "RTT": { <Seq_Num>: [ <Packet_Sent_Time>, <RTT> ] }, "Seq_Num": [ <Sequence_Number> ], "Ack_Num": [ <Acknowledgement_Number> ], 
           # "TCP_Times": [ <TCP_Packet_Sent_Times> ] }
TYPE = "Type"
START = "Start_Time"
END = "End_Time"
NUM_PACKETS = "Num_Packets"
SIZE = "Size"
HEADER_SIZE = "Header_Size"
ARRIVAL_TIME = "Arrival_Time"
TCP_STATE = "TCP_State"
IS_FAILED = "Is_Failed"
RTT = "RTT"
SEQ = "Seq_Num"
ACK = "Ack_Num"
TCP_TIMES = "TCP_Times"

# Collect the data that I need
with open("pkts_csv", "r") as f:
  for line in f:

    # Parse the data
    arr = line.strip().split(",")
    packet_No = arr[0].strip('"') # Packet No.
    time = arr[1].strip('"') # Packet sending time
    src = arr[2].strip('"') # Source address
    dest = arr[3].strip('"') # Destination address
    protocol = arr[4].strip('"') # Highest layer protocol
    length = arr[5].strip('"') # Packet size
    link_protocol = arr[6].strip('"') # Link layer protocol
    network_protocol = arr[7].strip('"') # Network layer protocol
    ip_header_length = arr[8].strip('"') # IP header length
    transport_protocol = arr[9].strip('"') # Transport layer protocol
    ip_packet_length = arr[10].strip('"') # IP packet size
    tcp_header_length = arr[11].strip('"') # TCP header length
    frame_size = arr[12].strip('"') # Packet size; Duplicate with "length"
    udp_packet_length = arr[13].strip('"') # UDP packet length
    syn = arr[14].strip('"') # TCP SYN flag
    fin = arr[15].strip('"') # TCP FIN flag
    reset = arr[16].strip('"') # TCP Reset flag
    ack = arr[17].strip('"') # TCP ACK flag
    tcp_packet_length = arr[18].strip('"') # TCP packet length
    tcp_src = arr[19].strip('"') # TCP source port
    tcp_dest = arr[20].strip('"') # TCP destination port
    seq_num = arr[21].strip('"') # TCP Sequence number
    next_seq_num = arr[22].strip('"') # TCP Next Sequence number
    ack_num = arr[23].strip('"') # TCP ACK number
    udp_src = arr[24].strip('"') # UDP source port
    udp_dest = arr[25].strip('"') # UDP destination port

    

    # Per packet stats
    total_num_pkts = total_num_pkts + 1
    all_packets_size.append(int(length))
    if link_protocol == "Ethernet":
      total_num_pkts_Ethernet = total_num_pkts_Ethernet + 1
    if network_protocol == "IPv4":
      total_num_pkts_IP = total_num_pkts_IP + 1
      IP_packets_size.append(int(length))
      IP_header_size.append(int(ip_header_length))
    else:
      non_IP_packets_size.append(int(length))
    if transport_protocol == "ICMP": # Note: ICMP is a network layer protocol. It's just I made it to be shown in this column, for convenience.
      total_num_pkts_ICMP = total_num_pkts_ICMP + 1
      total_size_pkts_ICMP = total_size_pkts_ICMP + int(length)
    if transport_protocol == "TCP":
      total_num_pkts_TCP = total_num_pkts_TCP + 1
      TCP_packets_size.append(int(length))
      TCP_header_size.append(int(tcp_header_length))
    if transport_protocol == "UDP":
      total_num_pkts_UDP = total_num_pkts_UDP + 1
      UDP_packets_size.append(int(length))
      UDP_header_size.append(int(ip_packet_length) - int(ip_header_length) - int(udp_packet_length))

    # ---------------------------------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------------------------------

    # Per flow stats
    # Only consider TCP and UDP flows
    LAST_PACKET_TIME = 345.002842 # The time when the last packet was sent
    if transport_protocol == "TCP" or transport_protocol == "UDP":
      src_port = 0
      dest_port = 0
      if transport_protocol == "TCP":
        src_port = tcp_src
        dest_port = tcp_dest
      if transport_protocol == "UDP":
        src_port = udp_src
        dest_port = udp_dest

      flow_key = src + "-" + src_port + "-" + dest + "-" + dest_port + "-" + transport_protocol
      if not flow_key in flows:
        # Might be from the other direction
        flow_key = dest + "-" + dest_port + "-" + src + "-" + src_port + "-" + transport_protocol
      if not flow_key in flows:
        # Record this new flow
        flows[flow_key] = {TYPE: "", START: 0, END: 0, NUM_PACKETS: 0, SIZE: 0, HEADER_SIZE: 0, ARRIVAL_TIME: [], TCP_STATE: "", IS_FAILED: True}
        flows[flow_key][TYPE] = transport_protocol
        flows[flow_key][START] = float(time)
        flows[flow_key][END] = float(time)
        flows[flow_key][NUM_PACKETS] = 1
        flows[flow_key][SIZE] = int(length)
        if transport_protocol == "TCP":
          flows[flow_key][HEADER_SIZE] = int(length) - int(tcp_packet_length)
          tcp_state = "Ongoing"
          if syn == "Set":
            tcp_state = "Request"
          if reset == "Set":
            tcp_state = "Reset"
          if fin == "Set":
            tcp_state = "Finished"
          flows[flow_key][TCP_STATE] = tcp_state
          if float(time) > (LAST_PACKET_TIME - 300):
            flows[flow_key][IS_FAILED] = False
          flows[flow_key][RTT] = dict()
          flows[flow_key][SEQ] = []
          flows[flow_key][ACK] = []
          flows[flow_key][TCP_TIMES] = []
        flows[flow_key][ARRIVAL_TIME].append(float(time))
      else:
        # I've recorded this flow, so just add this packet
        flows[flow_key][END] = float(time)
        flows[flow_key][NUM_PACKETS] =  flows[flow_key][NUM_PACKETS] + 1
        flows[flow_key][SIZE] = flows[flow_key][SIZE] + int(length)
        flows[flow_key][ARRIVAL_TIME].append(float(time))
        if transport_protocol == "TCP":
          flows[flow_key][HEADER_SIZE] = flows[flow_key][HEADER_SIZE] + int(length) - int(tcp_packet_length)
          tcp_state = "Ongoing"
          if syn == "Set":
            tcp_state = "Request"
          if reset == "Set":
            tcp_state = "Reset"
          if fin == "Set":
            tcp_state = "Finished"
          flows[flow_key][TCP_STATE] = tcp_state
          if float(time) > (LAST_PACKET_TIME - 300):
            flows[flow_key][IS_FAILED] = False
      if transport_protocol == "TCP":
        flows[flow_key][RTT][seq_num] = [float(time), -1]
        flows[flow_key][SEQ].append(seq_num)
        flows[flow_key][ACK].append(ack_num)
        flows[flow_key][TCP_TIMES].append(float(time))

# Record RTT for each packet (while excluding the retransmitted ones)
for flow_key in flows:
  if flows[flow_key][TYPE] == "TCP":
    for i in range(len(flows[flow_key][SEQ])):
      seq_num = flows[flow_key][SEQ][i]
      ack_num = flows[flow_key][ACK][i]
      time = flows[flow_key][TCP_TIMES][i]
      if seq_num in flows[flow_key][RTT]:
        if flows[flow_key][RTT][seq_num][1] == -1:
          flows[flow_key][RTT][seq_num][1] = 0
        elif flows[flow_key][RTT][seq_num][1] == 0:
          flows[flow_key][RTT].pop(seq_num)
      if ack_num in flows[flow_key][RTT]:
        if flows[flow_key][RTT][ack_num][1] == 0:
          flows[flow_key][RTT][ack_num][1] = flows[flow_key][RTT][ack_num][0] - time
#print(flows['244.3.93.198-4112-41.177.241.108-3389-TCP'][TCP_STATE])


# Analyze and draw CDFs
# Per packet stats
'''print("Ethernet packets -- count: " + str(total_num_pkts_Ethernet) + ", percentage: " + str(total_num_pkts_Ethernet / total_num_pkts) + ", size: " + str(sum(all_packets_size)) + ", size percentage: 1") # Actually all packets in this dataset are Ethernet packets
print("IP packets -- count: " + str(total_num_pkts_IP) + ", percentage: " + str(total_num_pkts_IP / total_num_pkts) + ", size: " + str(sum(IP_packets_size)) + ", size percentage: " + str(sum(IP_packets_size) / sum(all_packets_size)))
print("ICMP packets -- count: " + str(total_num_pkts_ICMP) + ", percentage: " + str(total_num_pkts_ICMP / total_num_pkts) + ", size: " + str(total_size_pkts_ICMP) + ", size percentage: " + str(total_size_pkts_ICMP / sum(all_packets_size)))
print("TCP packets -- count: " + str(total_num_pkts_TCP) + ", percentage: " + str(total_num_pkts_TCP / total_num_pkts) + ", size: " + str(sum(TCP_packets_size)) + ", size percentage: " + str(sum(TCP_packets_size) / sum(all_packets_size)))
print("UDP packets -- count: " + str(total_num_pkts_UDP) + ", percentage: " + str(total_num_pkts_UDP / total_num_pkts) + ", size: " + str(sum(UDP_packets_size)) + ", size percentage: " + str(sum(UDP_packets_size) / sum(all_packets_size)))

plot_cdf_and_save(all_packets_size, "All_Packets_Size_CDF.png")
plot_cdf_and_save(TCP_packets_size, "TCP_Packets_Size_CDF.png")
plot_cdf_and_save(UDP_packets_size, "UDP_Packets_Size_CDF.png")
plot_cdf_and_save(IP_packets_size, "IP_Packets_Size_CDF.png")
plot_cdf_and_save(non_IP_packets_size, "Non-IP_Packets_Size_CDF.png")
plot_cdf_and_save(IP_header_size, "IP_Header_Size_CDF.png")
plot_cdf_and_save(TCP_header_size, "TCP_Header_Size_CDF.png")
plot_cdf_and_save(UDP_header_size, "UDP_Header_Size_CDF.png")'''

# Per flow stats
num_TCP_flows = 0 # Number of TCP flows
num_UDP_flows = 0 # Number of UDP flows
all_flows_duration = [] # The duration of all flows
TCP_flows_duration = [] # The duration of TCP flows
UDP_flows_duration = [] # The duration of UDP flows
all_flows_num_pkts = [] # The number of packets of all flows
TCP_flows_num_pkts = [] # The number of packets of TCP flows
UDP_flows_num_pkts = [] # The number of packets of UDP flows
all_flows_size = [] # The size of all flows
TCP_flows_size = [] # The size of TCP flows
UDP_flows_size = [] # The size of UDP flows
TCP_hit_ratio = [] # Overhead ratio of TCP flows
all_inter_arrival_time = numpy.array([]) # Inter-arrival time of all flows
TCP_inter_arrival_time = numpy.array([]) # Inter-arrival time of TCP flows
UDP_inter_arrival_time = numpy.array([]) # Inter-arrival time of UDP flows
num_TCP_Request = 0 # Number of TCP connections in "Request" state
num_TCP_Reset = 0 # Number of TCP connections in "Reset" state
num_TCP_Finished = 0 # Number of TCP connections in "Finished" state
num_TCP_Ongoing = 0 # Number of TCP connections in "Ongoing" state
num_TCP_Failed = 0 # Number of TCP connections in "Failed" state
for stats in flows.values():
  flow_type = stats[TYPE]
  duration = stats[END] - stats[START]
  num_pkts = stats[NUM_PACKETS]
  flow_size = stats[SIZE]
  inter_arrival_time = numpy.array(stats[ARRIVAL_TIME][1:]) - numpy.array(stats[ARRIVAL_TIME][:-1])
  if flow_type == "TCP":
    num_TCP_flows = num_TCP_flows + 1
    TCP_flows_duration.append(duration)
    TCP_flows_num_pkts.append(num_pkts)
    TCP_flows_size.append(flow_size)
    TCP_inter_arrival_time = numpy.append(TCP_inter_arrival_time, inter_arrival_time)
    header_size = stats[HEADER_SIZE]
    data_size = flow_size - header_size
    ratio = 9999
    if data_size != 0:
      ratio = header_size / data_size
    TCP_hit_ratio.append(ratio)
    if stats[TCP_STATE] == "Finished":
      num_TCP_Finished = num_TCP_Finished + 1
    if stats[TCP_STATE] == "Reset":
      num_TCP_Reset = num_TCP_Reset + 1
    if stats[TCP_STATE] == "Request":
      num_TCP_Request = num_TCP_Request + 1
    if stats[TCP_STATE] == "Ongoing":
      if stats[IS_FAILED] == True:
      	num_TCP_Failed = num_TCP_Failed + 1
      else:
        num_TCP_Ongoing = num_TCP_Ongoing + 1
  else:
    # UDP case
    num_UDP_flows = num_UDP_flows + 1
    UDP_flows_duration.append(duration)
    UDP_flows_num_pkts.append(num_pkts)
    UDP_flows_size.append(flow_size)
    UDP_inter_arrival_time = numpy.append(UDP_inter_arrival_time, inter_arrival_time)
  all_flows_duration.append(duration)
  all_flows_num_pkts.append(num_pkts)
  all_flows_size.append(flow_size)
  all_inter_arrival_time = numpy.append(all_inter_arrival_time, inter_arrival_time)

'''print("Total number of flows: " + str(len(flows)))
print("Number of TCP flows: " + str(num_TCP_flows) + ", percentage: " + str(num_TCP_flows / len(flows)))
print("Number of UDP flows: " + str(num_UDP_flows) + ", percentage: " + str(num_UDP_flows / len(flows)))
print("TCP connection state -- Request count: " + str(num_TCP_Request) + ", Ongoing count: " + str(num_TCP_Ongoing) + ", Failed count: " + str(num_TCP_Failed) + ", Reset count: " + str(num_TCP_Reset) + ", Finished count: " + str(num_TCP_Finished))
plot_cdf_and_save(all_flows_duration, "All_Flows_Duration_CDF.png")
plot_cdf_and_save(TCP_flows_duration, "TCP_Flows_Duration_CDF.png")
plot_cdf_and_save(UDP_flows_duration, "UDP_Flows_Duration_CDF.png")
plot_cdf_and_save(all_flows_num_pkts, "All_Flows_Num_Packets_CDF.png")
plot_cdf_and_save(TCP_flows_num_pkts, "TCP_Flows_Num_Packets_CDF.png")
plot_cdf_and_save(UDP_flows_num_pkts, "UDP_Flows_Num_Packets_CDF.png")
plot_cdf_and_save(all_flows_size, "All_Flows_Size_CDF.png")
plot_cdf_and_save(TCP_flows_size, "TCP_Flows_Size_CDF.png")
plot_cdf_and_save(UDP_flows_size, "UDP_Flows_Size_CDF.png")
plot_cdf_and_save(TCP_hit_ratio, "TCP_Flows_Header_Overhead_CDF.png")
plot_cdf_and_save(all_inter_arrival_time, "All_Flows_Inter_Packet_Arrival_Time_CDF.png")
plot_cdf_and_save(TCP_inter_arrival_time, "TCP_Flows_Inter_Packet_Arrival_Time_CDF.png")
plot_cdf_and_save(UDP_inter_arrival_time, "UDP_Flows_Inter_Packet_Arrival_Time_CDF.png")'''

# RTT Estimation
def RTT_estimation(RTT_arr):
  result = []
  estimated_RTT = RTT_arr[0]
  result.append(estimated_RTT)
  for i in range(1, len(RTT_arr)):
    estimated_RTT = 0.875 * estimated_RTT + 0.125 * RTT_arr[i]
    result.append(estimated_RTT)
  return result

def plot_and_save(x, y, fname):
  plt.plot(x,y,linestyle='-', color='b')
  plt.savefig(fname)

# Find the top3 largest TCP flows in terms of packet number,
# the top3 largest TCP flows in terms of size and
# the top3 largest TCP flows in terms of duration
top3_pkt_num = []
top3_size = []
top3_duration = []
for flow_key in flows:
  if flows[flow_key][TYPE] == "TCP":
    flows[flow_key]["sample_RTT"] = []
    flows[flow_key]["pkt_times"] = []
    for key in flows[flow_key][RTT]:
      if flows[flow_key][RTT][key][1] != 0:
        flows[flow_key]["sample_RTT"].append(flows[flow_key][RTT][key][1])
        flows[flow_key]["pkt_times"].append(flows[flow_key][RTT][key][0])
    if len(top3_pkt_num) < 3:
      top3_pkt_num.append([flow_key, flows[flow_key][NUM_PACKETS]])
      top3_size.append([flow_key, flows[flow_key][SIZE]])
      top3_duration.append([flow_key, flows[flow_key][END] - flows[flow_key][START]])
      if len(top3_pkt_num) == 3:
        top3_pkt_num.sort(key=lambda x: x[1], reverse=True)
        top3_size.sort(key=lambda x: x[1], reverse=True)
        top3_duration.sort(key=lambda x: x[1], reverse=True)
    else:
      if flows[flow_key][NUM_PACKETS] > top3_pkt_num[2][1]:
        top3_pkt_num[2] = [flow_key, flows[flow_key][NUM_PACKETS]]
      if flows[flow_key][SIZE] > top3_size[2][1]:
        top3_size[2] = [flow_key, flows[flow_key][SIZE]]
      if flows[flow_key][END] - flows[flow_key][START] > top3_duration[2][1]:
        top3_duration[2] = [flow_key, flows[flow_key][END] - flows[flow_key][START]]
      top3_pkt_num.sort(key=lambda x: x[1], reverse=True)
      top3_size.sort(key=lambda x: x[1], reverse=True)
      top3_duration.sort(key=lambda x: x[1], reverse=True)

# Draw the estimated RRT and sample RRT
'''pkt_time = flows[top3_pkt_num[0][0]]["pkt_times"]
sample_RTT = flows[top3_pkt_num[0][0]]["sample_RTT"]
estimated_RTT = RTT_estimation(sample_RTT)
plt.plot(pkt_time,estimated_RTT,linestyle='-', color='r')
plt.savefig("Top1_Pkt_Num_Flow_Estimated_RTT.png")
plt.plot(pkt_time,sample_RTT,linestyle='-', color='b')
plt.savefig("Top1_Pkt_Num_Flow_Sample_RTT.png")

pkt_time = flows[top3_pkt_num[1][0]]["pkt_times"]
sample_RTT = flows[top3_pkt_num[1][0]]["sample_RTT"]
estimated_RTT = RTT_estimation(sample_RTT)
plt.plot(pkt_time,estimated_RTT,linestyle='-', color='r')
plt.savefig("Top2_Pkt_Num_Flow_Estimated_RTT.png")
plt.plot(pkt_time,sample_RTT,linestyle='-', color='b')
plt.savefig("Top2_Pkt_Num_Flow_Sample_RTT.png")

pkt_time = flows[top3_pkt_num[2][0]]["pkt_times"]
sample_RTT = flows[top3_pkt_num[2][0]]["sample_RTT"]
estimated_RTT = RTT_estimation(sample_RTT)
plt.plot(pkt_time,estimated_RTT,linestyle='-', color='r')
plt.savefig("Top3_Pkt_Num_Flow_Estimated_RTT.png")
plt.plot(pkt_time,sample_RTT,linestyle='-', color='b')
plt.savefig("Top3_Pkt_Num_Flow_Sample_RTT.png")

pkt_time = flows[top3_size[0][0]]["pkt_times"]
sample_RTT = flows[top3_size[0][0]]["sample_RTT"]
estimated_RTT = RTT_estimation(sample_RTT)
plt.plot(pkt_time,estimated_RTT,linestyle='-', color='r')
plt.savefig("Top1_Size_Flow_Estimated_RTT.png")
plt.plot(pkt_time,sample_RTT,linestyle='-', color='b')
plt.savefig("Top1_Size_Flow_Sample_RTT.png")

pkt_time = flows[top3_size[1][0]]["pkt_times"]
sample_RTT = flows[top3_size[1][0]]["sample_RTT"]
estimated_RTT = RTT_estimation(sample_RTT)
plt.plot(pkt_time,estimated_RTT,linestyle='-', color='r')
plt.savefig("Top2_Size_Flow_Estimated_RTT.png")
plt.plot(pkt_time,sample_RTT,linestyle='-', color='b')
plt.savefig("Top2_Size_Flow_Sample_RTT.png")

pkt_time = flows[top3_size[2][0]]["pkt_times"]
sample_RTT = flows[top3_size[2][0]]["sample_RTT"]
estimated_RTT = RTT_estimation(sample_RTT)
plt.plot(pkt_time,estimated_RTT,linestyle='-', color='r')
plt.savefig("Top3_Size_Flow_Estimated_RTT.png")
plt.plot(pkt_time,sample_RTT,linestyle='-', color='b')
plt.savefig("Top3_Size_Flow_Sample_RTT.png")

pkt_time = flows[top3_duration[0][0]]["pkt_times"]
sample_RTT = flows[top3_duration[0][0]]["sample_RTT"]
estimated_RTT = RTT_estimation(sample_RTT)
plt.plot(pkt_time,estimated_RTT,linestyle='-', color='r')
plt.savefig("Top1_Duration_Flow_Estimated_RTT.png")
plt.plot(pkt_time,sample_RTT,linestyle='-', color='b')
plt.savefig("Top1_Duration_Flow_Sample_RTT.png")

pkt_time = flows[top3_duration[1][0]]["pkt_times"]
sample_RTT = flows[top3_duration[1][0]]["sample_RTT"]
estimated_RTT = RTT_estimation(sample_RTT)
plt.plot(pkt_time,estimated_RTT,linestyle='-', color='r')
plt.savefig("Top2_Duration_Flow_Estimated_RTT.png")
plt.plot(pkt_time,sample_RTT,linestyle='-', color='b')
plt.savefig("Top2_Duration_Flow_Sample_RTT.png")

pkt_time = flows[top3_duration[2][0]]["pkt_times"]
sample_RTT = flows[top3_duration[2][0]]["sample_RTT"]
estimated_RTT = RTT_estimation(sample_RTT)
plt.plot(pkt_time,estimated_RTT,linestyle='-', color='r')
plt.savefig("Top3_Duration_Flow_Estimated_RTT.png")
plt.plot(pkt_time,sample_RTT,linestyle='-', color='b')
plt.savefig("Top3_Duration_Flow_Sample_RTT.png")'''

# Find the top3 pair of hosts that have the highest number of TCP connections
host_pairs = []
flow_count = []
for flow_key in flows:
  if flows[flow_key][TYPE] == "TCP":
    flow_key_arr = flow_key.split("-")
    host1 = flow_key_arr[0]
    host2 = flow_key_arr[2]
    if [host1, host2] in host_pairs:
      idx = host_pairs.index([host1, host2])
      flow_count[idx] = flow_count[idx] + 1
    else:
      if [host2, host1] in host_pairs:
        idx = host_pairs.index([host2, host1])
        flow_count[idx] = flow_count[idx] + 1
      else:
        host_pairs.append([host1, host2])
        flow_count.append(1)
host_pairs_and_flow_count = dict()
for host_pair in host_pairs:
  idx = host_pairs.index(host_pair)
  host_pairs_and_flow_count[flow_count[idx]] = host_pair
top1_host_pair = host_pairs_and_flow_count.pop(max(host_pairs_and_flow_count.keys()))
top2_host_pair = host_pairs_and_flow_count.pop(max(host_pairs_and_flow_count.keys()))
top3_host_pair = host_pairs_and_flow_count.pop(max(host_pairs_and_flow_count.keys()))

top1_pair_representative_RTTs = []
top1_pair_flow_start_times = []
top2_pair_representative_RTTs = []
top2_pair_flow_start_times = []
top3_pair_representative_RTTs = []
top3_pair_flow_start_times = []
for flow_key in flows:
  if flows[flow_key][TYPE] == "TCP":
    RTT_array = flows[flow_key]["sample_RTT"]
    if len(RTT_array) > 0:
      RTT_estimated = RTT_estimation(RTT_array)
      representative_RTT = statistics.median(RTT_estimated)
      flow_key_arr = flow_key.split("-")
      host1 = flow_key_arr[0]
      host2 = flow_key_arr[2]
      if [host1, host2] == top1_host_pair or [host2, host1] == top1_host_pair:
        top1_pair_representative_RTTs.append(representative_RTT)
        top1_pair_flow_start_times.append(flows[flow_key][START])
      if [host1, host2] == top2_host_pair or [host2, host1] == top2_host_pair:
        top2_pair_representative_RTTs.append(representative_RTT)
        top2_pair_flow_start_times.append(flows[flow_key][START])
      if [host1, host2] == top3_host_pair or [host2, host1] == top3_host_pair:
        top3_pair_representative_RTTs.append(representative_RTT)
        top3_pair_flow_start_times.append(flows[flow_key][START])
plot_and_save(top1_pair_flow_start_times, top1_pair_representative_RTTs, "Top1_Host_Pair_Representative_RTTs.png")
plot_and_save(top2_pair_flow_start_times, top2_pair_representative_RTTs, "Top2_Host_Pair_Representative_RTTs.png")
plot_and_save(top3_pair_flow_start_times, top3_pair_representative_RTTs, "Top3_Host_Pair_Representative_RTTs.png")




