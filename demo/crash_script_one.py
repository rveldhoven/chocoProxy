def handle_packet(str_source_ip, str_dest_ip, str_packet_type, str_str_port, str_dst_port, bytes_packet):
    if bytes_packet[0] == 0x26:
        packet = bytearray.fromhex("2601000000A20008fca9fefb700000000000000000A20008fca9fefb7000000000000000001600000062006f006200270073002000470061006d0065000000")
        return packet