#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

LISTENING = "listening"
BLOCKING = "blocking"
own_bridge_ID = 0
root_bridge_ID = 0
root_path_cost = 0
root_port = 0
sender_bridge_ID = 0
sender_path_cost = 0
port_states = {} # used to track the state of each port (LISTENING or BLOCKING)

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def create_bpdu_packet(root_bridge_ID, sender_bridge_ID, sender_path_cost, port) -> bytes:
    data = bytes([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00])
    data += get_switch_mac()
    data += struct.pack('!q', root_bridge_ID)
    data += struct.pack('!q', sender_bridge_ID)
    data += struct.pack('!i', sender_path_cost)
    data += struct.pack('!H', port)
    return data

def send_bdpu_every_sec(port_config):
    global root_bridge_ID, own_bridge_ID
    while True:
        # TODO Send BDPU every second if necessary
        # send BPDU package if switch is root bridge
        if root_bridge_ID == own_bridge_ID:
            for i in port_config:
                if port_config[i] == -1: # if port is trunk
                    root_bridge_ID = own_bridge_ID
                    sender_bridge_ID = own_bridge_ID
                    sender_path_cost = 0
                    data = create_bpdu_packet(root_bridge_ID, sender_bridge_ID, sender_path_cost, i)
                    send_to_link(i, len(data), data)
        time.sleep(1)

def init_stp(interfaces, port_config, switch_priority):
    global root_bridge_ID, own_bridge_ID, root_path_cost, root_port
    root_port = -1

    # all trunk ports will be blocked because cycles can appear only there
    for i in interfaces:
        if port_config[i] == -1:
            port_states[i] = BLOCKING

    own_bridge_ID = switch_priority
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0

    # if switch is root bridge, all trunk ports are listening
    if own_bridge_ID == root_bridge_ID:
        for port in port_config:
            if port_config[port] == -1:
                port_states[port] = LISTENING
    
    return root_port

def receive_bpdu(data, port, port_config):
    global root_bridge_ID, root_path_cost, root_port, port_states

    # Parcing reveived BPDU
    bpdu_root_bridge_id = int.from_bytes(data[12:20], byteorder='big')
    bpdu_sender_path_cost = int.from_bytes(data[20:28], byteorder='big')
    bpdu_sender_bridge_id = int.from_bytes(data[28:32], byteorder='big')
    bpdu_port = int.from_bytes(data[32:34], byteorder='big')
    
    # if received BPDU is samller, update STP information
    # there will be a new root bridge
    if bpdu_root_bridge_id < root_bridge_ID:
        
        # add 10 to cost because all links are 100 mps
        root_path_cost = bpdu_sender_path_cost + 10
        root_port = port

        if root_bridge_ID == own_bridge_ID:
            for t_port in port_config:
                if port_config[t_port] == -1:
                    if t_port == root_port:
                        port_states[t_port] = LISTENING
                    else:
                        port_states[t_port] = BLOCKING

        root_bridge_ID = bpdu_root_bridge_id

        for t_port in port_config:
                if port_config[t_port] == -1:
                    if t_port != root_port and port_states[t_port] != BLOCKING:
                        sender_bridge_ID = own_bridge_ID
                        sender_path_cost = root_path_cost
                        new_data = create_bpdu_packet(root_bridge_ID, sender_bridge_ID, sender_path_cost, t_port)
                        send_to_link(t_port, len(new_data), new_data)
    # if root bridge is the same
    elif bpdu_root_bridge_id == root_bridge_ID:
        if port == root_port:
            if bpdu_sender_path_cost + 10 < root_path_cost:
                root_path_cost = bpdu_sender_path_cost + 10
        elif port != root_port:
            if bpdu_sender_path_cost > root_path_cost:
                if port_states[port] == BLOCKING:
                    port_states[port] = LISTENING
    
    elif bpdu_sender_bridge_id == own_bridge_ID:
        port_states[port] = BLOCKING
    
    else:
        return
    
    # this switch is root bridge
    # set all trunk ports to LISTENING
    if own_bridge_ID == root_bridge_ID:
        for t_port in port_config:
                if port_config[t_port] == -1:
                    port_states[t_port] = LISTENING

def unicast_from_trunk(length, data, vlan_id, interface, port_config, dest_port):
    if port_config[dest_port] == -1:  # Destination is also trunk
        if port_states[dest_port] == LISTENING:
            send_to_link(dest_port, length, data)
    elif port_config[dest_port] == vlan_id:  # Destination is access
            no_tag_data = data[:12] + data[16:]
            send_to_link(dest_port, length - 4, no_tag_data)

def unicast_from_access(length, data, interface, port_config, dest_port):
    if port_config[dest_port] == -1:  # Destination is trunk
        if port_states[dest_port] == LISTENING:
            tagged = data[:12] + create_vlan_tag(port_config[interface]) + data[12:]
            send_to_link(dest_port, length + 4, tagged)
    elif port_config[dest_port] == port_config[interface]:  # destination is also access
        send_to_link(dest_port, length, data)

def noMAC_or_noUnicast_from_trunk(length, data, vlan_id, interface, port_config, interfaces):
    for i in interfaces:
        if i != interface:
            if port_config[i] == -1:  # To another trunk port
                if port_states[i] == LISTENING:
                    send_to_link(i, length, data)
            elif port_config[i] == vlan_id:  # To another access port
                no_tag_data = data[:12] + data[16:]
                send_to_link(i, length - 4, no_tag_data)

def noMAC_or_noUnicast_from_access(length, data, interface, port_config, interfaces):
    for i in interfaces:
        if i != interface:
            if port_config[i] == -1:  # To another trunk port
                if port_states[i] == LISTENING:
                    tagged = data[:12] + create_vlan_tag(port_config[interface]) + data[12:]
                    send_to_link(i, length + 4, tagged)
            elif port_config[i] == port_config[interface]:  # To another access port
                send_to_link(i, length, data)

def main():
    # asta ai declarat tu
    MAC_table = {}
    port_config = {}
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    # print("# Starting switch with id {}".format(switch_id), flush=True)
    # print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec, args=(port_config,))
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))
    
    file = open('configs/switch{}.cfg'.format(switch_id), "r")
    switch_priority = int(file.readline().strip())

    lines = file.readlines()

    for line in lines:
        f_port = line.split(" ")
        for i in interfaces:
            if f_port[0].strip() == get_interface_name(i):
                if f_port[1].strip() == "T":
                    port_config[i] = -1  # used -1 to check for trunk port
                else:
                    config_vlan_id = int(f_port[1].strip())
                    port_config[i] = config_vlan_id  # Acces port with VLAN ID


    file.close()

    root_port = init_stp(interfaces, port_config, switch_priority)

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # modificat de tine
        # Print the MAC src and MAC dst in human readable format
        dest_mac_human = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac_human = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        # print(f'Destination MAC: {dest_mac_human}')
        # print(f'Source MAC: {src_mac_human}')
        # print(f'EtherType: {ethertype}')

        # print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # TODO: Implement forwarding with learning
        # TODO: Implement VLAN support
        # TODO: Implement STP support

        # check if the received packet is BPDU
        if dest_mac_human == '01:80:c2:00:00:00':
            receive_bpdu(data, interface, port_config)
        else:
            # skip if the interface is trunk and the state is blocked
            if port_config[interface] == -1:
                if port_states[interface] == BLOCKING:
                    continue

            MAC_table[src_mac] = interface

            # Check if the destination is unicast
            if dest_mac[0] & 1 == 0:
                # Check if the destination mac is in the mac table
                if dest_mac in MAC_table:
                    dest_port = MAC_table[dest_mac]
                    if port_config[interface] == -1:  # Current port is trunk
                        unicast_from_trunk(length, data, vlan_id, interface, port_config, dest_port)
                    else:  # Current port is access
                        unicast_from_access(length, data, interface, port_config, dest_port)
                else:  # Destination is not in the mac table
                    if port_config[interface] == -1:  # Current port is trunk
                        noMAC_or_noUnicast_from_trunk(length, data, vlan_id, interface, port_config, interfaces)
                    else:  # Current port is access
                        noMAC_or_noUnicast_from_access(length, data, interface, port_config, interfaces)
            else:  # Destination is multicast or broadcast
                if port_config[interface] == -1:  # Current port is trunk
                    noMAC_or_noUnicast_from_trunk(length, data, vlan_id, interface, port_config, interfaces)
                else:  # Current port is access
                    noMAC_or_noUnicast_from_access(length, data, interface, port_config, interfaces)

            # data is of type bytes.
            # send_to_link(i, length, data)

if __name__ == "__main__":
    main()