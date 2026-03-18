# Sender.py
import socket
import struct
import threading
import time
from collections import deque
from OSOP import compress_data, encrypt_batch, HEADER_SIZE

PRIORITY_HIGH = 0
PRIORITY_MEDIUM = 1
PRIORITY_LOW = 2
BATCH_TIMEOUT = 0.005
RESEND_TIMEOUT = 0.1
MTU_MIN = 1130
MTU_MAX = 1500
BATCH_STEP = 20

class OSOPSender:
    def __init__(self, key, addr, client_id=1):
        self.key = key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addr = addr
        self.client_id = client_id
        self.batch_id = 0
        self.queues = {PRIORITY_HIGH: deque(), PRIORITY_MEDIUM: deque(), PRIORITY_LOW: deque()}
        self.sent_batches = {}  # batch_id -> packets
        self.batch_times = {}
        self.current_mtu = MTU_MIN
        self.lock = threading.Lock()
        self.acks = {}  # batch_id -> set of acked packets

    def enqueue_packet(self, data, priority=PRIORITY_MEDIUM):
        self.queues[priority].append(data)

    def send_batches(self):
        while True:
            for priority in [PRIORITY_HIGH, PRIORITY_MEDIUM, PRIORITY_LOW]:
                if self.queues[priority]:
                    self._send_batch_from_queue(priority)
            self._check_retransmissions()
            time.sleep(BATCH_TIMEOUT)

    def _send_batch_from_queue(self, priority):
        packets = []
        size_accum = 0
        while self.queues[priority] and size_accum < self.current_mtu - HEADER_SIZE:
            s = self.queues[priority].popleft()
            s_bytes = s.encode('utf-8')
            if size_accum + len(s_bytes) + 4 > self.current_mtu - HEADER_SIZE:
                self.queues[priority].appendleft(s)
                break
            packets.append(s)
            size_accum += len(s_bytes) + 4
        if packets:
            self._send_batch(packets)

    def _send_batch(self, packets, batch_id=None):
        if batch_id is None:
            batch_id = self.batch_id
            self.batch_id += 1
        batch_payload = b''
        for seq, s in enumerate(packets):
            s_bytes = s.encode('utf-8')
            batch_payload += struct.pack('!HH', seq, len(s_bytes)) + s_bytes
        batch_payload = compress_data(batch_payload)
        header = struct.pack('!HH14s', batch_id, self.client_id, b'\x00'*14)
        full_batch = header + batch_payload
        ciphertext, tag = encrypt_batch(self.key, full_batch)
        self.sock.sendto(ciphertext + tag, self.addr)
        with self.lock:
            self.sent_batches[batch_id] = packets
            self.batch_times[batch_id] = time.time()
            self.acks[batch_id] = set()
        print(f"Sent batch {batch_id}, {len(packets)} packets, MTU={self.current_mtu}")

    def handle_ack(self, batch_id, acked_seq):
        with self.lock:
            if batch_id in self.acks:
                self.acks[batch_id].update(acked_seq)
                if len(self.acks[batch_id]) == len(self.sent_batches[batch_id]):
                    del self.sent_batches[batch_id]
                    del self.batch_times[batch_id]
                    del self.acks[batch_id]
                    # Increase MTU if all packets acked
                    self.current_mtu = min(MTU_MAX, self.current_mtu + BATCH_STEP)

    def _check_retransmissions(self):
        now = time.time()
        with self.lock:
            for batch_id, ts in list(self.batch_times.items()):
                if now - ts > RESEND_TIMEOUT:
                    missing_packets = [
                        self.sent_batches[batch_id][i] for i in range(len(self.sent_batches[batch_id]))
                        if i not in self.acks[batch_id]
                    ]
                    if missing_packets:
                        self._send_batch(missing_packets, batch_id)
                        print(f"Retransmitting batch {batch_id}")
                        self.current_mtu = max(MTU_MIN, self.current_mtu - BATCH_STEP)
