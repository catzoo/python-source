from io import BytesIO
import struct
import socket
import time

PACKET_SIZE = 1400
WHOLE = -1
SPLIT = -2

A2S_INFO_HEADER = ord('T')
A2S_INFO_PAYLOAD = "Source Engine Query"

A2S_RULES_HEADER = ord('V')

REQUEST_CHALLENGE_NUMBER = -1


class QueryError(Exception):
    pass


class SourcePacket(BytesIO):
    """This will help store and make packets for steam queries
     This goes with the valve query data types. For example, strings will always end with 0x00
     (more information here: https://developer.valvesoftware.com/wiki/Server_queries)

     This class helps write and reads:
     byte, short, long (ints), long_long, float, string

     This uses struct to help pack and unpack the data
     Besides strings."""
    def write_byte(self, value):
        self.write(struct.pack('<B', value))

    def get_byte(self):
        return struct.unpack('<B', self.read1(1))[0]

    def write_short(self, value):
        self.write(struct.pack('<h', value))

    def get_short(self):
        return struct.unpack('<h', self.read1(2))[0]

    def write_long(self, value):
        self.write(struct.pack('<l', value))

    def get_long(self):
        return struct.unpack('<l', self.read1(4))[0]

    def write_long_long(self, value):
        self.write(struct.pack('<Q', value))

    def get_long_long(self):
        return struct.unpack('<Q', self.read1(8))[0]

    def write_float(self, value):
        self.write(struct.pack('<f', value))

    def get_float(self):
        return struct.unpack('<f', self.read1(4))[0]

    def write_string(self, value):
        """Converting the string to bytes and writing to it"""
        value = bytes(value, 'utf-8')
        value = value + b'\x00'
        self.write(value)

    def get_string(self):
        value = self.getvalue()
        start = self.tell()
        end = value.index(b'\x00', start)  # getting the end of the string
        value = value[start:end]  # grabbing only the string, nothing else
        value = value.decode("utf-8")
        self.seek(end + 1)  # going to the next bit (passing the 0x00)
        return value


class Query:
    def __init__(self, address, port, timeout=10.0):
        self.address = (address, port)
        self.timeout = timeout

        self.connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.connection.settimeout(timeout)

    def receive(self):
        """
        Receives the packet that comes in.
        This is separated because of split packets.

        This will automatically handle and combine split packets.
        This will also return the whole packet (including the header / split))
        """
        data = self.connection.recv(PACKET_SIZE)
        data = SourcePacket(data)

        header = data.get_long()
        if header == WHOLE:
            data.seek(0, 0)
            return data
        else:
            packets = {}  # all the split packets received
            data.seek(0, 0)  # going back to the beginning of the packet
            old_packet_id = None

            # grabbing all the split packets
            while True:
                header = data.get_long()
                packet_id = data.get_long()
                if packet_id != old_packet_id and old_packet_id is not None:
                    raise QueryError(f'Received a different split packet with the ID {packet_id}'
                                     f' expected {old_packet_id}')
                total = data.get_byte()
                number = data.get_byte()
                size = data.get_short()
                packets[number] = data.read()
                # making sure we're not at the end
                if len(packets) > total - 1:
                    break
                # Receiving another packet
                data = SourcePacket(self.connection.recv(PACKET_SIZE))

            # combining the packets, making sure they're in order
            packet = b""
            for x in range(len(packets)):
                packet += packets[x]

            return SourcePacket(packet)

    def challenge_receive(self, header):
        """
        Sends a challenge request and grabs the information with the challenge number
        It'll send the request with the challenge number and returns the packet that was received
        """
        # sending challenge request
        packet = SourcePacket()
        packet.write_long(WHOLE)
        packet.write_byte(header)
        packet.write_long(REQUEST_CHALLENGE_NUMBER)
        self.connection.sendto(packet.getvalue(), self.address)

        # receiving challenge number
        packet = self.receive()
        rec_split = packet.get_long()
        rec_header = packet.get_byte()
        if rec_header == "E":
            # if the server isn't sending us the number
            packet.seek(0, 0)  # setting the position back to the beginning
            return packet

        # sending request with the challenge number
        challenge = packet.get_long()
        packet = SourcePacket()
        packet.write_long(WHOLE)
        packet.write_byte(header)
        packet.write_long(challenge)
        self.connection.sendto(packet.getvalue(), self.address)

        return self.receive()  # returning the packet received by the server

    def info(self):
        """
        This will send a A2S_INFO request to the server
        This method will get the info and return:

        {header, protocol, name, map, folder, game, id, players, max_players, bots,
        server_type, environment, visibility, vac, version, edf}

        If there is a edf field, possible additions would be:
        {port, steamid, sourcetv_port, sourcetv_name, keywords, gameid}

        For more information about these values, go here - https://developer.valvesoftware.com/wiki/Server_queries

        Note: This method does change the values a tiny bit.
            - For example, if you got server_type = 'd'. This method will set this to "Dedicated Server"
        """
        packet = SourcePacket()
        packet.write_long(WHOLE)
        packet.write_byte(A2S_INFO_HEADER)
        packet.write_string(A2S_INFO_PAYLOAD)

        self.connection.sendto(packet.getvalue(), self.address)
        packet = self.receive()
        data = {
            'split': packet.get_long(),
            'header': chr(packet.get_byte()),
            'protocol': packet.get_byte(),
            'name': packet.get_string(),
            'map': packet.get_string(),
            'folder': packet.get_string(),
            'game': packet.get_string(),
            'id': packet.get_short(),
            'players': packet.get_byte(),
            'max_players': packet.get_byte(),
            'bots': packet.get_byte()
        }
        server_type = chr(packet.get_byte())
        if server_type == 'd':
            server_type = 'Dedicated Server'
        elif server_type == 'l':
            server_type = 'Non-dedicated Server'
        elif server_type == 'p':
            server_type = 'SourceTV relay'

        data['server_type'] = server_type

        environment = chr(packet.get_byte())
        if environment == 'l':
            environment = 'Linux'
        elif environment == 'w':
            environment = 'Windows'
        elif environment == 'm' or environment == 'o':
            environment = 'Mac'

        data['environment'] = environment

        visibility = packet.get_byte()
        if visibility == 1:
            visibility = 'Private'
        elif visibility == 0:
            visibility = 'Public'

        data['visibility'] = visibility

        vac = packet.get_byte()
        if vac == 1:
            vac = 'Secured'
        elif vac == 0:
            vac = 'Unsecured'

        data['vac'] = vac

        # TODO: insert the ship fields here

        data['version'] = packet.get_string()

        edf = packet.get_byte()
        data['edf'] = edf
        # getting the extra data fields (EDF)
        if edf:
            if edf & 0x80:
                data['port'] = packet.get_short()
            if edf & 0x10:
                data['steamid'] = packet.get_long_long()
            if edf & 0x40:
                data['sourcetv_port'] = packet.get_short()
                data['sourcetv_name'] = packet.get_string()
            if edf & 0x20:
                data['keywords'] = packet.get_string()
            if edf & 0x01:
                data['gameid'] = packet.get_long_long()

        return data

    def rules(self):
        packet = self.challenge_receive(A2S_RULES_HEADER)

        split = packet.get_long()
        header = packet.get_byte()
        total_rules = packet.get_short()

        rules = {}
        for _ in range(total_rules):
            name = packet.get_string()
            value = packet.get_string()

            rules[name] = value

        return rules
