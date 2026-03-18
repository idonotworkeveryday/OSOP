# Receiver.py
import socket
import struct
import random
from OSOP import decompress_data, decrypt_batch

PACKET_LOSS_SIM = 0.1

class OSOPReceiver:
    def __init__(self, key, bind_addr, sender):
        self.key = key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(bind_addr)
        self.sender = sender
        self.received_batches = {}  # batch_id -> set(seq)

    def receive_batch(self):
        data, addr = self.sock.recvfrom(4096)
        if random.random() < PACKET_LOSS_SIM:
            print("Simulated packet loss!")
            return
        ciphertext, tag = data[:-16], data[-16:]
        try:
            plaintext = decrypt_batch(self.key, ciphertext, tag)
        except Exception as e:
            print("Verification failed:", e)
            return
        batch_id, client_id, reserved = struct.unpack('!HH14s', plaintext[:18])
        payload = decompress_data(plaintext[18:])
        offset = 0
        packets = []
        received_seq = set()
        while offset < len(payload):
            seq, length = struct.unpack('!HH', payload[offset:offset+4])
            offset += 4
            s = payload[offset:offset+length].decode('utf-8')
            offset += length
            packets.append((seq, s))
            received_seq.add(seq)
        if batch_id not in self.received_batches:
            self.received_batches[batch_id] = set()
        self.received_batches[batch_id].update(received_seq)
        missing_seq = set(range(len(packets))) - self.received_batches[batch_id]
        # Send ACK of received packets
        self.sender.handle_ack(batch_id, list(received_seq))
        print(f"Received batch {batch_id}, {len(packets)} packets:")
        for seq, s in packets:
            print(f"  Packet {seq}: {s}")
