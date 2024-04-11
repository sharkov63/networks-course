import logging
import io
import random
from checksum import getchecksum, validatechecksum

DEFAULT_SERVER_PORT = 5959
PACKET_SIZE = 20
PACKET_HEADER_SIZE = 12
PACKET_PAYLOAD_SIZE = PACKET_SIZE - PACKET_HEADER_SIZE
LOSS_PROBABILITY = 0.3
CORRUPT_PROBABILITY = 0.1
DEFAULT_ATTEMPTS_NO = 10
DEFAULT_TIMEOUT_S = 0.05



def send_packet(socket, packet: bytes, addr):
    if random.random() < LOSS_PROBABILITY:
        return  # emulate packet loss
    if random.random() < CORRUPT_PROBABILITY:
        i = random.randint(0, len(packet) - 1)
        packet = packet[:i] + (packet[i] ^ 1).to_bytes() + packet[i+1:]
    socket.sendto(packet, addr)

def augument_checksum(data: bytes):
    complement = 2**32 - 1 - getchecksum(data)
    return complement.to_bytes(length=4, byteorder='little') + data

def send_bytes(socket, data: bytes, addr, timeout=DEFAULT_TIMEOUT_S):
    socket.settimeout(timeout)
    for offset in range(0, len(data), PACKET_PAYLOAD_SIZE):
        payload = data[offset:min(len(data), offset+PACKET_PAYLOAD_SIZE)]
        next_offset = offset + len(payload)
        packet = augument_checksum(
            offset.to_bytes(4) + len(data).to_bytes(4) + payload
        )
        for _ in range(DEFAULT_ATTEMPTS_NO):
            logging.info("Sending packet {}:{}".format(
                offset, next_offset))
            send_packet(socket, packet, addr)
            try:
                ack_data = socket.recv(PACKET_SIZE)
                if int.from_bytes(ack_data[:4]) >= next_offset:
                    break
            except TimeoutError:
                logging.warning(
                    "Packet {}:{} lost, sending again...".format(offset, next_offset))
        else:
            logging.error("Failed to send message to {} after {} attempts".format(addr,
                                                                                  DEFAULT_ATTEMPTS_NO))
            raise RuntimeError("Failed to send message")


def recv_bytes(socket):
    socket.settimeout(None)
    messagestream = io.BytesIO()
    next_offset = 0
    while True:
        packet, sender_addr = socket.recvfrom(PACKET_SIZE)
        if len(packet) <= PACKET_HEADER_SIZE:
            logging.warning(
                "Received packet with too short length {}".format(len(packet)))
            continue
        if not validatechecksum(packet):
            logging.warning("Received corrupted packet")
            continue
        packet = packet[4:]
        offset = int.from_bytes(packet[:4])
        messagesize = int.from_bytes(packet[4:8])
        payload = packet[8:]
        if offset > next_offset:
            logging.warning("Received packet {}:{}, but expected offset {}".format(
                offset, offset + len(payload), next_offset))
            continue
        if offset == next_offset:
            logging.info("Received valid packet {}:{}".format(
                offset, offset + len(payload)))
            messagestream.write(payload)
            next_offset += len(payload)
        else:
            logging.warning("Received duplicate packet {}:{}".format(
                offset, offset + len(payload)))
        logging.info("Sending ACK packet for {}:{}".format(
            offset, offset + len(payload)))
        send_packet(socket, augument_checksum(next_offset.to_bytes(4)), sender_addr)
        if next_offset >= messagesize:
            logging.info("Received full message of {} bytes".format(
                next_offset))
            return messagestream.getvalue(), sender_addr
