"""
Made by catzoo

This is a query rewrite of https://github.com/serverstf/python-valve
"""

from io import BytesIO
import struct
import socket
import time

"""Constant values from https://developer.valvesoftware.com/wiki/Server_queries"""

PACKET_SIZE = 1400
WHOLE = -1
SPLIT = -2

A2S_INFO_HEADER = ord('T')
A2S_INFO_PAYLOAD = "Source Engine Query"

A2S_RULES_HEADER = ord('V')

A2S_PLAYERS_HEADER = ord('U')

CHALLENGE_NUMBER_REQUEST = -1
CHALLENGE_NUMBER_HEADER = ord('A')


class QueryError(Exception):
    pass


class ChallengeError(Exception):
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
        self.connection.settimeout(self.timeout)

    def receive(self, send_time=False):
        """
        Receives the packet that comes in.
        This is separated because of split packets.

        This will automatically handle and combine split packets.
        This will also return the whole packet (including the header / split))

        This can also return the time after receiving the first packet. Useful for pings
        (used in self.send())
        """
        data = self.connection.recv(PACKET_SIZE)
        ping = time.time()

        data = SourcePacket(data)

        header = data.get_long()
        if header == WHOLE:
            data.seek(0, 0)
            if send_time:
                return data, ping
            else:
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
            try:
                packet = b""
                for x in range(len(packets)):
                    packet += packets[x]
            except KeyError:
                raise QueryError('Missing a split packet')

            if send_time:
                return SourcePacket(packet), ping
            else:
                return SourcePacket(packet)

    def send(self, header, payload=None, ping=False):
        """
        This is used to send requests to servers
        Reason why this is in a separate method is because it was repeated a lot.

        This also can return the time it took to send / receive. (Useful for pings)
        """
        packet = SourcePacket()
        packet.write_long(WHOLE)
        packet.write_byte(header)
        if payload:
            if isinstance(payload, str):
                # used by A2S_INFO
                packet.write_string(payload)
            elif isinstance(payload, int):
                # used by challenge
                packet.write_long(payload)

        self.connection.sendto(packet.getvalue(), self.address)

        past = time.time()
        packet, now = self.receive(send_time=True)
        timing = now - past

        if ping:
            return packet, timing
        else:
            return packet

    def receive_challenge(self, header):
        """
        This will send a challenge request and grab the challenge number.
        Then it will send another request with the challenge number to get the packet.

        This is mostly used by A2S_PLAYERS and A2S_RULES
        """
        # grabbing the challenge number
        packet = self.send(header, CHALLENGE_NUMBER_REQUEST)
        packet.get_long()  # split

        rec_header = packet.get_byte()
        if chr(rec_header) == 'E':
            # server didn't send a challenge number, but sent the packet we're looking for
            # basically, the server sent the rules or players packet rather than the challenge number
            packet.seek(0, 0)
            return packet

        # requesting with the challenge
        challenge = packet.get_long()
        packet = self.send(header, challenge)

        packet.get_long()  # split
        rec_header = packet.get_byte()
        if rec_header == CHALLENGE_NUMBER_HEADER:
            raise ChallengeError(f'Sent {challenge} and got back challenge number')

        packet.seek(0, 0)
        return packet

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
        packet, ping = self.send(A2S_INFO_HEADER, A2S_INFO_PAYLOAD, True)
        data = {
            'ping': ping,
            'raw': packet.getvalue(),
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
        """
        This will send a A2S_RULES request to the server using receive_challenge.
        This will return for every rule:
            { "name": "value" }

        NOTE: Some servers may return part of a packet.
        When this happens, one of the rules may be either:
            - cut off
            - not exist

        This is determined by the string is not complete (does not end with 0x00)

        For more information go here:
            https://developer.valvesoftware.com/wiki/Server_queries
        """
        packet = self.receive_challenge(A2S_RULES_HEADER)

        packet.get_long()  # split
        packet.get_byte()  # header
        total_rules = packet.get_short()

        rules = {}
        for _ in range(total_rules):
            # sometimes the packet is cut off. So we will do some try statements
            # if the header is cut off, we'll ignore it
            # if the value is cut off, we'll put in the header and error message
            try:
                name = packet.get_string()
            except ValueError:
                pass
            else:
                try:
                    value = packet.get_string()
                except ValueError:
                    value = "N/A - packet cut off"
                rules[name] = value

        return rules

    def players(self):
        """
        This will send a A2S_PLAYERS request to the server using receive_challenge.
        This will return for each player:
            [ { 'index', 'name', 'score', 'duration' } ]

        NOTE: Sometimes the server may not send all the players and packet cut off.
        If the packet is cut off, the player information may not be here.

        When this happens there will only be a number in the list.
        For example:
            [ {'index': 0, 'name': 'testing', 'score': 0, 'duration': 2.0},
              36,
              37,
              38
            ]

        For more information about these values go here:
            https://developer.valvesoftware.com/wiki/Server_queries
        """
        packet = self.receive_challenge(A2S_PLAYERS_HEADER)
        packet.get_long()  # split
        packet.get_byte()  # header

        number_of_players = packet.get_byte()
        players = list(range(number_of_players))
        for x in range(number_of_players):
            try:
                players[x] = {
                    'index': packet.get_byte(),
                    'name': packet.get_string(),
                    'score': packet.get_long(),
                    'duration': packet.get_float()
                }
            except (ValueError, struct.error):
                #  sometimes we don't get the whole packet
                pass

        return players
