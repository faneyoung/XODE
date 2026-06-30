# XODE CLIENT v3.0 - ECDSA secp256k1
# Compatible with: node_v3_ecdsa.py server
# Features: Web UI, P2P sync, local chain storage, incremental balances

import socket
import threading
import json
import time
import os
import hashlib
import struct
import random
import select
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

# ============ Constants ============
MAGIC = b'XODE'
HEADER_SIZE = 8
MAX_PAYLOAD_SIZE = 10_000_000
TOTAL_SUPPLY = 2100000000
BLOCK_TIME = 120
BLOCK_REWARD = 1000
TRANSFER_FEE = 1
BLOCKS_BEFORE_REWARD = 15

# ============ File Paths ============
WALLET_FILE = os.path.join(os.path.expanduser("~"), "wallet.dat")
CHAIN_FILE = os.path.join(os.path.expanduser("~"), "xode_chain.json")
BALANCES_FILE = os.path.join(os.path.expanduser("~"), "xode_balances.json")
MYTX_FILE = os.path.join(os.path.expanduser("~"), "xode_mytx.json")
PEERS_FILE = os.path.join(os.path.expanduser("~"), "xode_peers.json")

# ============ Crypto Utils ============
def sha256(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def sha256_bytes(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()

def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256K1())
    private_bytes = private_key.private_numbers().private_value.to_bytes(32, 'big')
    private_key_hex = private_bytes.hex()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    public_key_hex = public_bytes.hex()
    return private_key_hex, public_key_hex

def public_key_to_address(public_key_hex):
    public_bytes = bytes.fromhex(public_key_hex)
    h1 = hashlib.sha256(public_bytes).digest()
    try:
        h2_obj = hashlib.new('ripemd160')
    except ValueError:
        h2_obj = _get_pure_ripemd160()
    h2_obj.update(h1)
    hash160 = h2_obj.digest()
    num = int.from_bytes(hash160, 'big')
    extra = int(hashlib.sha256(hash160).hexdigest(), 16)
    mixed = (num ^ extra) & ((1 << 128) - 1)
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    result = ''
    n = mixed
    while n > 0:
        n, rem = divmod(n, 58)
        result = alphabet[rem] + result
    if len(result) < 16:
        fill_chars = hashlib.sha256(str(mixed).encode()).hexdigest()
        fill = ''
        for i in range(0, 64, 2):
            idx = int(fill_chars[i:i+2], 16) % 58
            fill += alphabet[idx]
        result = fill[:16 - len(result)] + result
    result = result[:16]
    return 'XODE' + result

def sign_message(private_key_hex, message):
    private_value = int(private_key_hex, 16)
    private_key = ec.derive_private_key(private_value, ec.SECP256K1())
    if isinstance(message, str):
        message = message.encode('utf-8')
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature.hex()

def verify_signature(public_key_hex, message, signature_hex, timestamp=None):
    if not public_key_hex or not signature_hex or not message:
        return False
    try:
        if timestamp is not None:
            current_time = time.time()
            if abs(current_time - timestamp) > 120:
                return False
        public_bytes = bytes.fromhex(public_key_hex)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_bytes)
        signature = bytes.fromhex(signature_hex)
        if isinstance(message, str):
            message = message.encode('utf-8')
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False

def verify_public_key_address(public_key_hex, address):
    if not public_key_hex or not address:
        return False
    try:
        expected = public_key_to_address(public_key_hex)
        return expected == address
    except Exception:
        return False

def build_sign_message(from_addr, to_addr, amount, nonce, timestamp=None):
    data = {
        "from": from_addr,
        "to": to_addr,
        "amount": float(amount),
        "nonce": int(nonce)
    }
    if timestamp is not None:
        data["timestamp"] = float(timestamp)
    return json.dumps(data, sort_keys=True, separators=(',', ':'))

# ============ Pure Python RIPEMD160 Fallback ============
class PureRIPEMD160:
    def __init__(self):
        self.buf = b''
        self.count = 0
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    def _rol(self, n, k):
        return ((n << k) | (n >> (32 - k))) & 0xFFFFFFFF
    def _compress(self, chunk):
        X = [int.from_bytes(chunk[i*4:(i+1)*4], 'little') for i in range(16)]
        h = self.h[:]
        A, B, C, D, E = h
        for j in range(16):
            T = (self._rol(A + ((B ^ C ^ D) + X[j] + 0x00000000) & 0xFFFFFFFF, self._r1[j]) + E) & 0xFFFFFFFF
            A, B, C, D, E = E, T, B, self._rol(C, 10), D
        for j in range(16):
            T = (self._rol(A + (((C ^ D) & B) ^ D) + X[self._r2[j]] + 0x5A827999, self._s1[j]) + E) & 0xFFFFFFFF
            A, B, C, D, E = E, T, B, self._rol(C, 10), D
        for j in range(16):
            T = (self._rol(A + ((B | ~C) ^ D) + X[self._r3[j]] + 0x6ED9EBA1, self._s2[j]) + E) & 0xFFFFFFFF
            A, B, C, D, E = E, T, B, self._rol(C, 10), D
        for j in range(16):
            T = (self._rol(A + (((B ^ C) & D) ^ C) + X[self._r4[j]] + 0x8F1BBCDC, self._s3[j]) + E) & 0xFFFFFFFF
            A, B, C, D, E = E, T, B, self._rol(C, 10), D
        for j in range(16):
            T = (self._rol(A + (B ^ (C | ~D)) + X[self._r5[j]] + 0xA953FD4E, self._s4[j]) + E) & 0xFFFFFFFF
            A, B, C, D, E = E, T, B, self._rol(C, 10), D
        AA, BB, CC, DD, EE = h[0], h[1], h[2], h[3], h[4]
        for j in range(16):
            T = (self._rol(AA + (BB ^ (CC | ~DD)) + X[self._r5[j]] + 0x50A28BE6, self._t1[j]) + EE) & 0xFFFFFFFF
            AA, BB, CC, DD, EE = EE, T, BB, self._rol(CC, 10), DD
        for j in range(16):
            T = (self._rol(AA + (((BB ^ CC) & DD) ^ CC) + X[self._r4[j]] + 0x5C4DD124, self._t2[j]) + EE) & 0xFFFFFFFF
            AA, BB, CC, DD, EE = EE, T, BB, self._rol(CC, 10), DD
        for j in range(16):
            T = (self._rol(AA + ((BB | ~CC) ^ DD) + X[self._r3[j]] + 0x6D703EF3, self._t3[j]) + EE) & 0xFFFFFFFF
            AA, BB, CC, DD, EE = EE, T, BB, self._rol(CC, 10), DD
        for j in range(16):
            T = (self._rol(AA + (((CC ^ DD) & BB) ^ DD) + X[self._r2[j]] + 0x7A6D76E9, self._t4[j]) + EE) & 0xFFFFFFFF
            AA, BB, CC, DD, EE = EE, T, BB, self._rol(CC, 10), DD
        for j in range(16):
            T = (self._rol(AA + (BB ^ CC ^ DD) + X[j] + 0x00000000, self._t5[j]) + EE) & 0xFFFFFFFF
            AA, BB, CC, DD, EE = EE, T, BB, self._rol(CC, 10), DD
        T = (h[1] + C + DD) & 0xFFFFFFFF
        self.h = [
            (h[0] + A + EE) & 0xFFFFFFFF,
            T,
            (h[2] + E + AA) & 0xFFFFFFFF,
            (h[3] + B + CC) & 0xFFFFFFFF,
            (h[4] + D + BB) & 0xFFFFFFFF
        ]
    _r1 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
    _r2 = [7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8]
    _r3 = [3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12]
    _r4 = [1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2]
    _r5 = [4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    _s1 = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8]
    _s2 = [7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12]
    _s3 = [11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5]
    _s4 = [11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12]
    _t1 = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6]
    _t2 = [9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11]
    _t3 = [9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5]
    _t4 = [15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8]
    _t5 = [8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    def update(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.buf += data
        self.count += len(data)
        while len(self.buf) >= 64:
            self._compress(self.buf[:64])
            self.buf = self.buf[64:]
        return self
    def digest(self):
        count = (self.count * 8) & 0xFFFFFFFFFFFFFFFF
        pad = b'\x80' + b'\x00' * ((55 - self.count) % 64)
        pad += count.to_bytes(8, 'little')
        self.update(pad)
        result = b''.join(h.to_bytes(4, 'little') for h in self.h)
        return result
    def hexdigest(self):
        return self.digest().hex()

def _get_pure_ripemd160():
    return PureRIPEMD160()

# ============ Network Protocol ============
def encode_message(payload_dict):
    payload = json.dumps(payload_dict, ensure_ascii=False).encode('utf-8')
    length = len(payload)
    if length > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Payload too large: {length} bytes")
    return MAGIC + struct.pack('>I', length) + payload

def decode_messages(buffer):
    messages = []
    while True:
        idx = buffer.find(MAGIC)
        if idx == -1:
            return messages, b""
        buffer = buffer[idx:]
        if len(buffer) < HEADER_SIZE:
            return messages, buffer
        length = struct.unpack('>I', buffer[4:8])[0]
        if length > MAX_PAYLOAD_SIZE or length < 0:
            buffer = buffer[4:]
            continue
        if len(buffer) < HEADER_SIZE + length:
            return messages, buffer
        payload = buffer[HEADER_SIZE:HEADER_SIZE + length]
        buffer = buffer[HEADER_SIZE + length:]
        try:
            msg = json.loads(payload.decode('utf-8'))
            messages.append(msg)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    return messages, buffer

# ============ Wallet ============
class Wallet:
    def __init__(self):
        self.private_key = ""
        self.public_key = ""
        self.address = ""
        self.balance = 0
        self.created_at = 0
        self.nonce = 0
        self.version = 2
        self.load_or_create()

    def load_or_create(self):
        if os.path.exists(WALLET_FILE):
            try:
                with open(WALLET_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.public_key = data.get("public_key", "")
                self.address = data.get("address", "")
                self.balance = data.get("balance", 0)
                self.created_at = data.get("created_at", 0)
                self.nonce = data.get("nonce", 0)
                self.version = data.get("version", 2)
                if "private_key" in data:
                    self.private_key = data.get("private_key", "")
                else:
                    print("[Wallet] No private key found, creating new...")
                    self.create_new()
                    return
                if not verify_public_key_address(self.public_key, self.address):
                    print("[Wallet] Address mismatch, regenerating...")
                    self.create_new()
                    return
                print(f"[Wallet] Loaded: {self.address}")
                return
            except Exception as e:
                print(f"[Wallet] Load failed: {e}, creating new...")
        self.create_new()

    def create_new(self):
        self.private_key, self.public_key = generate_keypair()
        self.address = public_key_to_address(self.public_key)
        self.balance = 0
        self.created_at = time.time()
        self.nonce = 0
        self.version = 2
        self.save()
        print(f"[Wallet] Created new: {self.address}")

    def save(self):
        data = {
            "public_key": self.public_key,
            "address": self.address,
            "balance": self.balance,
            "created_at": self.created_at,
            "saved_at": time.time(),
            "nonce": self.nonce,
            "private_key": self.private_key,
            "version": self.version,
            "algorithm": "ECDSA-secp256k1"
        }
        try:
            with open(WALLET_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[Wallet] Save failed: {e}")

    def sign(self, message):
        return sign_message(self.private_key, message)

    def get_info(self):
        return {
            "address": self.address,
            "public_key": self.public_key,
            "balance": self.balance,
            "created_at": self.created_at,
            "version": self.version,
            "algorithm": "ECDSA-secp256k1"
        }

# ============ Chain Store ============
class ChainStore:
    def __init__(self):
        self.chain = []
        self.block_height = 0
        self.total_issued = 0
        self.balances = {}
        self.my_transactions = []
        self.my_address = ""
        self._incremental_height = -1
        self.load()
        self._load_balances()
        self._load_mytx()

    def _load_balances(self):
        if os.path.exists(BALANCES_FILE):
            try:
                with open(BALANCES_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.balances = data.get("balances", {})
                self._incremental_height = data.get("block_height", -1)
                print(f"[Balances] Loaded {len(self.balances)} addresses @ height #{self._incremental_height}")
            except Exception as e:
                print(f"[Balances] Load failed: {e}")
                self.balances = {}
                self._incremental_height = -1
        else:
            self.balances = {}
            self._incremental_height = -1

    def _save_balances(self):
        try:
            data = {
                "balances": self.balances,
                "block_height": self._incremental_height,
                "saved_at": time.time()
            }
            temp = BALANCES_FILE + ".tmp"
            with open(temp, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(temp, BALANCES_FILE)
        except Exception as e:
            print(f"[Balances] Save failed: {e}")

    def _load_mytx(self):
        if os.path.exists(MYTX_FILE):
            try:
                with open(MYTX_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.my_transactions = data.get("transactions", [])
                saved_height = data.get("block_height", -1)
                self._incremental_height = max(self._incremental_height, saved_height)
                print(f"[MyTx] Loaded {len(self.my_transactions)} transactions @ height #{saved_height}")
            except Exception as e:
                print(f"[MyTx] Load failed: {e}")
                self.my_transactions = []
        else:
            self.my_transactions = []

    def _save_mytx(self):
        try:
            data = {
                "transactions": self.my_transactions,
                "block_height": self._incremental_height,
                "saved_at": time.time()
            }
            temp = MYTX_FILE + ".tmp"
            with open(temp, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(temp, MYTX_FILE)
        except Exception as e:
            print(f"[MyTx] Save failed: {e}")

    def apply_blocks_incremental(self, blocks, my_address=""):
        if my_address:
            self.my_address = my_address
        changed = False
        for block in blocks:
            idx = block.get("index")
            if idx is None or idx <= self._incremental_height:
                continue
            for tx in block.get("transactions", []):
                self._apply_tx(tx)
                changed = True
                if self.my_address and (tx.get("from") == self.my_address or tx.get("to") == self.my_address):
                    if tx not in self.my_transactions:
                        self.my_transactions.append(tx)
            reward = block.get("reward", block.get("reward_tx", {}))
            recipients = reward.get("recipients", [])
            for r in recipients:
                if isinstance(r, dict):
                    addr = r.get("address")
                    amt = float(r.get("amount", 0))
                else:
                    addr = r
                    amt = float(reward.get("per_user", reward.get("reward_per_user", 0)))
                if addr and amt > 0:
                    self.balances[addr] = self.balances.get(addr, 0) + amt
                    changed = True
                    if addr == self.my_address:
                        reward_tx = {
                            "type": "reward",
                            "from": "BLOCK_REWARD",
                            "to": addr,
                            "amount": amt,
                            "fee": 0,
                            "timestamp": block.get("timestamp"),
                            "block_index": idx,
                            "status": "confirmed"
                        }
                        if reward_tx not in self.my_transactions:
                            self.my_transactions.append(reward_tx)
            burned = float(reward.get("burned", 0))
            if burned > 0:
                burn_addr = reward.get("burn_address", "XODE0000000000000000")
                self.balances[burn_addr] = self.balances.get(burn_addr, 0) + burned
                changed = True
            self._incremental_height = idx
        if changed:
            self._save_balances()
            self._save_mytx()
        return changed

    def _apply_tx(self, tx):
        tx_type = tx.get("type")
        if tx_type == "transfer":
            from_addr = tx.get("from")
            to_addr = tx.get("to")
            amount = float(tx.get("amount", 0))
            fee = float(tx.get("fee", 0))
            if from_addr and from_addr != "GENESIS":
                self.balances[from_addr] = self.balances.get(from_addr, 0) - amount - fee
            if to_addr:
                self.balances[to_addr] = self.balances.get(to_addr, 0) + amount
            if fee > 0:
                burn_addr = "XODE0000000000000000"
                self.balances[burn_addr] = self.balances.get(burn_addr, 0) + fee
        elif tx_type == "snapshot":
            to_addr = tx.get("to")
            amount = float(tx.get("amount", 0))
            if to_addr and amount > 0:
                self.balances[to_addr] = self.balances.get(to_addr, 0) + amount

    def load(self):
        if os.path.exists(CHAIN_FILE):
            try:
                with open(CHAIN_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.chain = data.get("chain", [])
                self.block_height = data.get("block_height", 0)
                self.total_issued = data.get("total_issued", 0)
                print(f"[Chain] Loaded {len(self.chain)} blocks")
            except Exception as e:
                print(f"[Chain] Load failed: {e}")
                self.chain = []
        else:
            self.chain = []

    def save(self):
        data = {
            "chain": self.chain,
            "block_height": self.block_height,
            "total_issued": self.total_issued,
            "saved_at": time.time()
        }
        try:
            temp = CHAIN_FILE + ".tmp"
            with open(temp, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(temp, CHAIN_FILE)
        except Exception as e:
            print(f"[Chain] Save failed: {e}")
        self._save_balances()
        self._save_mytx()

    def add_blocks(self, blocks):
        added = 0
        sorted_blocks = sorted(blocks, key=lambda x: x.get("index", 0))
        for block in sorted_blocks:
            idx = block.get("index")
            if idx is None:
                continue
            existing = [b for b in self.chain if b["index"] == idx]
            if existing:
                continue
            if idx == 0:
                if block.get("previous_hash", "") != "0" * 64:
                    continue
            else:
                prev_blocks = [b for b in self.chain if b["index"] == idx - 1]
                if not prev_blocks:
                    continue
                if block.get("previous_hash", "") != prev_blocks[0].get("hash", ""):
                    continue
            self.chain.append(block)
            added += 1
            supply = block.get("supply", {})
            if supply and "issued" in supply and supply["issued"] is not None:
                try:
                    issued_val = float(supply["issued"])
                    if issued_val > self.total_issued:
                        self.total_issued = issued_val
                except (ValueError, TypeError):
                    pass
        self.chain.sort(key=lambda x: x["index"])
        if self.chain:
            self.block_height = self.chain[-1]["index"]
        self.save()
        return added

    def get_local_height(self):
        if not self.chain:
            return -1
        self.chain.sort(key=lambda x: x["index"])
        return self.chain[-1]["index"]

# ============ Node Connection ============
class XodeNode:
    _node_id_counter = 0
    _counter_lock = threading.Lock()

    def __init__(self, host, port, wallet, is_outbound=True):
        with XodeNode._counter_lock:
            XodeNode._node_id_counter += 1
            self.node_id = XodeNode._node_id_counter
        self.host = host
        self.port = port
        self.wallet = wallet
        self.is_outbound = is_outbound
        self.socket = None
        self.connected = False
        self.running = False
        self.last_pong_time = 0
        self.last_ping_time = 0
        self.connect_time = 0
        self.version_handshake_done = False
        self.peer_height = 0
        self.peer_address = ""
        self.on_message = None
        self.on_disconnect = None
        self._receive_thread = None
        self._heartbeat_thread = None
        self._send_lock = threading.Lock()
        self.bytes_received = 0
        self.bytes_sent = 0
        self.messages_received = 0
        self.messages_sent = 0

    def connect(self, timeout=5.0):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(timeout)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.socket.connect((self.host, self.port))
            self.socket.settimeout(None)
            self.connected = True
            self.running = True
            self.connect_time = time.time()
            self.last_pong_time = time.time()

            init_msg = {
                "address": self.wallet.address,
                "public_key": self.wallet.public_key
            }
            self.send_message(init_msg)

            self._receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self._receive_thread.start()

            self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
            self._heartbeat_thread.start()

            print(f"[XodeNode] Connected to {self.host}:{self.port} (id={self.node_id})")
            return True
        except Exception as e:
            print(f"[XodeNode] Connection failed: {e}")
            self._cleanup()
            return False

    def disconnect(self):
        if not self.running and not self.connected:
            return
        self.running = False
        self.connected = False
        self._cleanup()
        if self.on_disconnect:
            try:
                self.on_disconnect(self)
            except Exception:
                pass

    def _cleanup(self):
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None

    def send_message(self, msg_dict):
        with self._send_lock:
            try:
                if not self.socket or not self.connected or self.socket.fileno() == -1:
                    return False
                data = encode_message(msg_dict)
                self.socket.sendall(data)
                self.bytes_sent += len(data)
                self.messages_sent += 1
                return True
            except (OSError, ValueError):
                return False
            except Exception as e:
                if self.running:
                    print(f"[XodeNode] Send failed: {e}")
                self.disconnect()
                return False

    def _receive_loop(self):
        buffer = b""
        while self.running:
            try:
                if not self.socket or self.socket.fileno() == -1:
                    break
                ready, _, _ = select.select([self.socket], [], [], 1.0)
                if not ready:
                    continue
                data = self.socket.recv(8192)
                if not data:
                    break
                buffer += data
                self.bytes_received += len(data)
                messages, buffer = decode_messages(buffer)
                for msg in messages:
                    self.messages_received += 1
                    if self.on_message:
                        try:
                            self.on_message(self, msg)
                        except Exception as e:
                            print(f"[XodeNode] Handler error: {e}")
            except (OSError, ValueError):
                break
            except Exception as e:
                if self.running:
                    print(f"[XodeNode] Receive error: {e}")
                break
        self.connected = False
        self.running = False
        self._cleanup()

    def _heartbeat_loop(self):
        time.sleep(2)
        while self.running:
            try:
                time.sleep(25)
                if not self.running or not self.socket or self.socket.fileno() == -1:
                    break
                elapsed = time.time() - self.last_pong_time
                if elapsed > 90 and self.last_pong_time > 0:
                    print(f"[XodeNode] Heartbeat timeout on node {self.node_id}")
                    self.disconnect()
                    break
                ping_msg = {"type": "ping", "timestamp": int(time.time())}
                self.send_message(ping_msg)
                self.last_ping_time = time.time()
            except (OSError, ValueError):
                break
            except Exception as e:
                if self.running:
                    print(f"[XodeNode] Heartbeat error: {e}")
                break

    def get_info(self):
        return {
            "node_id": self.node_id,
            "host": self.host,
            "port": self.port,
            "connected": self.connected,
            "connect_time": self.connect_time,
            "bytes_received": self.bytes_received,
            "bytes_sent": self.bytes_sent,
            "messages_received": self.messages_received,
            "messages_sent": self.messages_sent,
            "peer_height": self.peer_height
        }

# ============ Connection Manager ============
class XodeConnman:
    def __init__(self, wallet):
        self.wallet = wallet
        self.nodes = {}
        self._nodes_lock = threading.Lock()
        self.running = False
        self._connect_thread = None
        self.manual_disconnect = False
        self.max_outbound = 8
        self.min_outbound = 1
        self.connect_interval = 30
        self._message_handlers = []
        self.syncing = False
        self.sync_progress = 0
        self.sync_total = 0
        self._sync_lock = threading.Lock()
        self.best_height = 0
        self.total_supply = TOTAL_SUPPLY
        self.block_time = BLOCK_TIME
        self.block_reward = BLOCK_REWARD
        self.transfer_fee = TRANSFER_FEE
        self.online_users = 0
        self.pending_tx = 0
        self.burned_total = 0
        self.burn_address = ""
        self.cooldown_users = 0
        self.eligible_users = 0

    def add_message_handler(self, handler):
        self._message_handlers.append(handler)

    def start(self):
        self.running = True
        self.manual_disconnect = False
        print("[Connman] Started")

    def stop(self):
        self.running = False
        self.manual_disconnect = True
        with self._nodes_lock:
            for node in list(self.nodes.values()):
                node.disconnect()
            self.nodes.clear()
        print("[Connman] Stopped")

    def connect_to(self, host, port):
        with self._nodes_lock:
            for node in self.nodes.values():
                if node.host == host and node.port == port and node.connected:
                    return False, "Already connected"
        node = XodeNode(host, port, self.wallet, is_outbound=True)
        node.on_message = self._on_node_message
        node.on_disconnect = self._on_node_disconnect
        if node.connect():
            with self._nodes_lock:
                self.nodes[node.node_id] = node
            return True, f"Connected to {host}:{port}"
        else:
            return False, f"Failed to connect to {host}:{port}"

    def disconnect_node(self, node_id):
        with self._nodes_lock:
            if node_id in self.nodes:
                self.nodes[node_id].disconnect()
                return True
        return False

    def disconnect_all(self):
        with self._nodes_lock:
            for node in list(self.nodes.values()):
                node.disconnect()

    def get_connected_nodes(self):
        with self._nodes_lock:
            return [n for n in self.nodes.values() if n.connected]

    def get_best_sync_node(self):
        connected = self.get_connected_nodes()
        if not connected:
            return None
        connected.sort(key=lambda n: (-n.peer_height, n._estimate_latency() if hasattr(n, '_estimate_latency') else 0))
        return connected[0] if connected else None

    def broadcast(self, msg_dict, exclude_node_id=None):
        results = {}
        with self._nodes_lock:
            nodes = list(self.nodes.values())
        for node in nodes:
            if not node.connected:
                continue
            if exclude_node_id and node.node_id == exclude_node_id:
                continue
            success = node.send_message(msg_dict)
            results[node.node_id] = {"host": node.host, "port": node.port, "success": success}
        return results

    def send_to_best(self, msg_dict):
        best = self.get_best_sync_node()
        if not best:
            return False, "No connected nodes"
        success = best.send_message(msg_dict)
        return success, f"Sent to best node {best.host}:{best.port}"

    def _on_node_message(self, node, msg):
        msg_type = msg.get("type", "")
        if msg_type == "pong":
            node.last_pong_time = time.time()
        elif msg_type == "connected":
            node.peer_height = msg.get("block_height", 0)
        elif msg_type == "stats":
            node.peer_height = msg.get("block_height", node.peer_height)
        elif msg_type == "new_block":
            node.peer_height = msg.get("index", node.peer_height)
        for handler in self._message_handlers:
            try:
                handler(node, msg)
            except Exception as e:
                print(f"[Connman] Handler error: {e}")

    def _on_node_disconnect(self, node):
        print(f"[Connman] Node {node.node_id} disconnected")
        with self._nodes_lock:
            if node.node_id in self.nodes:
                del self.nodes[node.node_id]

    def get_network_info(self):
        connected = self.get_connected_nodes()
        return {
            "connected_nodes": len(connected),
            "total_nodes": len(self.nodes),
            "best_height": self.best_height,
            "nodes": [n.get_info() for n in connected]
        }

# ============ Main Client ============
class XodeClient:
    def __init__(self):
        self.wallet = Wallet()
        self.chain_store = ChainStore()
        self.chain_store.my_address = self.wallet.address
        local_height = self.chain_store.get_local_height()
        incr_height = self.chain_store._incremental_height
        if self.chain_store.chain and incr_height < local_height:
            print(f"[Init] Rebuilding balances...")
            self._rebuild_balances_silent()
        self.connman = XodeConnman(self.wallet)
        self.connman.add_message_handler(self._handle_node_message)
        self.total_supply = TOTAL_SUPPLY
        self.block_time = BLOCK_TIME
        self.block_reward = BLOCK_REWARD
        self.transfer_fee = TRANSFER_FEE
        self.online_users = 0
        self.pending_tx = 0
        self.burned_total = 0
        self.balance_rank = 0
        self.total_addresses = 0
        self.block_height = 0
        self.first_connect_block = None
        self.cooldown_blocks = BLOCKS_BEFORE_REWARD
        self.cooldown_remaining = 0
        self.is_eligible = False
        self.cooldown_users = 0
        self.eligible_users = 0
        self.total_issued = 0
        self.transaction_history = []
        self.local_balances = {}
        self.current_block_reward_addrs = []
        self.logs = []
        self.transfer_result = None
        self.balance_update = None
        self.lock = threading.Lock()
        self._add_default_peers()

    def _add_default_peers(self):
        pass

    def add_log(self, msg, level="info"):
        with self.lock:
            self.logs.append({"time": time.strftime('%H:%M:%S'), "msg": msg, "level": level})
            if len(self.logs) > 300:
                self.logs = self.logs[-300:]
        print(f"[{level.upper()}] {msg}")

    def connect(self, host=None, port=None):
        if host and port:
            self.add_log(f"Connecting to {host}:{port}...")
            success, message = self.connman.connect_to(host, port)
            if success:
                self.connman.start()
            return success, message
        return False, "No host specified"

    def disconnect(self):
        self.connman.stop()
        self.add_log("Disconnected from all nodes")

    def reconnect(self):
        self.disconnect()
        time.sleep(1)
        return self.connect()

    def _handle_node_message(self, node, msg):
        msg_type = msg.get("type", "")
        if msg_type == "pong":
            pass
        elif msg_type == "connected":
            self.wallet.balance = msg.get("balance", self.wallet.balance)
            self.block_height = msg.get("block_height", self.block_height)
            self.total_issued = msg.get("issued", self.total_issued)
            self.block_time = msg.get("block_time", BLOCK_TIME)
            self.block_reward = msg.get("block_reward", BLOCK_REWARD)
            self.transfer_fee = msg.get("transfer_fee", TRANSFER_FEE)
            self.burned_total = msg.get("burned_total", self.burned_total)
            self.cooldown_remaining = msg.get("blocks_remaining", 0)
            self.is_eligible = msg.get("reward_eligible", False)
            self.first_connect_block = msg.get("first_seen_block", self.block_height)
            self.chain_store.first_connect_block = self.first_connect_block
            self.add_log(f"Connected! Balance: {self.wallet.balance} | Height: #{self.block_height}")
            self.wallet.save()
            local_height = self.chain_store.get_local_height()
            if local_height < 0 or local_height < self.block_height:
                if not self.connman.syncing:
                    self.add_log(f"Sync needed: local #{local_height} / network #{self.block_height}")
                    threading.Thread(target=self.request_sync, daemon=True).start()
        elif msg_type == "new_block":
            self._handle_new_block(msg)
        elif msg_type == "balance_update":
            self.wallet.balance = msg["balance"]
            self.wallet.save()
            self.balance_update = msg
            if self.wallet.address in self.chain_store.balances:
                self.chain_store.balances[self.wallet.address] = msg["balance"]
                self.chain_store._save_balances()
            self.add_log(f"Reward! +{msg['reward']} XODE | Balance: {msg['balance']} XODE")
        elif msg_type == "transfer_result":
            self.transfer_result = msg
            if msg.get("success"):
                self.wallet.balance = msg.get("balance", self.wallet.balance)
                self.wallet.save()
                if self.wallet.address in self.chain_store.balances:
                    self.chain_store.balances[self.wallet.address] = msg["balance"]
                    self.chain_store._save_balances()
                self.add_log(f"Transfer OK: {msg['amount']} XODE -> {msg['to'][:20]}...")
            else:
                self.add_log(f"Transfer Failed: {msg.get('error', 'Unknown')}", "error")
        elif msg_type == "chain_data":
            if msg.get("blocks"):
                self._process_blocks(msg["blocks"])
        elif msg_type == "blocks_range":
            blocks = msg.get("blocks", [])
            if blocks:
                self._process_blocks(blocks)
        elif msg_type == "stats":
            self.cooldown_users = msg.get("ineligible_users", 0)
            self.eligible_users = msg.get("eligible_users", 0)
            self.pending_tx = msg.get("pending_tx", 0)
            self.burn_address = msg.get("burn_address", "")
            server_height = msg.get("block_height", self.block_height)
            local_height = self.chain_store.get_local_height()
            self.block_height = max(server_height, local_height)
            self.total_issued = msg.get("total_issued", self.total_issued)
            if server_height > local_height and not self.connman.syncing:
                if local_height < 0:
                    threading.Thread(target=self.request_sync, daemon=True).start()
                elif server_height - local_height <= 10:
                    threading.Thread(target=self._sync_missing_blocks, args=(local_height + 1, server_height + 1), daemon=True).start()
                else:
                    threading.Thread(target=self.request_sync, daemon=True).start()
        elif msg_type == "reward_pending":
            self.cooldown_remaining = msg.get("blocks_remaining", self.cooldown_remaining)
            self.is_eligible = self.cooldown_remaining <= 0

    def _handle_new_block(self, msg):
        new_index = msg["index"]
        self.block_height = new_index
        reward = msg.get("reward", msg.get("reward_tx", {}))
        supply = msg.get("supply", {})
        block = {
            "index": new_index,
            "hash": msg["hash"],
            "previous_hash": msg["previous_hash"],
            "timestamp": msg["timestamp"],
            "reward": reward,
            "supply": supply,
            "transactions": msg.get("transactions", [])
        }
        local_height = self.chain_store.get_local_height()
        if new_index > local_height + 1:
            if not self.connman.syncing:
                threading.Thread(target=self._sync_missing_blocks, args=(local_height + 1, new_index), daemon=True).start()
        self.chain_store.apply_blocks_incremental([block], my_address=self.wallet.address)
        self.local_balances = self.chain_store.balances
        self.transaction_history = self.chain_store.my_transactions
        added = self.chain_store.add_blocks([block])
        # 从新区块消息直接读取 supply（issued / burned 累计总量）
        if supply:
            if "issued" in supply and supply["issued"] is not None:
                try:
                    self.total_issued = float(supply["issued"])
                    self.chain_store.total_issued = self.total_issued
                except (ValueError, TypeError):
                    pass
            if "burned" in supply and supply["burned"] is not None:
                try:
                    self.burned_total = float(supply["burned"])
                except (ValueError, TypeError):
                    pass
        self.current_block_reward_addrs = reward.get("recipients", [])
        self.online_users = reward.get("online_count", 0)
        self.cooldown_users = reward.get("ineligible_count", 0)
        self.eligible_users = reward.get("online_count", 0) - reward.get("ineligible_count", 0)
        if reward.get("online_count", 0) > 0:
            self.add_log(f"New Block #{new_index} | Online: {reward['online_count']} | Per User: {reward.get('per_user', reward.get('reward_per_user', 0))} XODE")
        elif reward.get("burned", 0) > 0:
            self.add_log(f"New Block #{new_index} | Burned: {reward['burned']} XODE")
        else:
            self.add_log(f"New Block #{new_index} | Reward: {reward.get('total', 0)} XODE")

    def _process_blocks(self, blocks):
        formatted = []
        for b in blocks:
            formatted.append({
                "index": b["index"],
                "hash": b["hash"],
                "previous_hash": b["previous_hash"],
                "timestamp": b["timestamp"],
                "reward": b.get("reward", b.get("reward_tx", {})),
                "supply": b.get("supply", {}),
                "transactions": b.get("transactions", [])
            })
        self.chain_store.apply_blocks_incremental(formatted, my_address=self.wallet.address)
        self.local_balances = self.chain_store.balances
        self.transaction_history = self.chain_store.my_transactions
        added = self.chain_store.add_blocks(formatted)
        # 从最后一个区块读取 supply（issued / burned 累计总量）
        if blocks:
            last = blocks[-1]
            supply = last.get("supply", {})
            if supply:
                if "issued" in supply and supply["issued"] is not None:
                    try:
                        self.total_issued = float(supply["issued"])
                        self.chain_store.total_issued = self.total_issued
                    except (ValueError, TypeError):
                        pass
                if "burned" in supply and supply["burned"] is not None:
                    try:
                        self.burned_total = float(supply["burned"])
                    except (ValueError, TypeError):
                        pass
        local_height = self.chain_store.get_local_height()
        self.add_log(f"Added {added} blocks, local height: #{local_height}")

    def request_sync(self):
        if not self.connman.get_connected_nodes():
            return
        if not self.connman._sync_lock.acquire(blocking=False):
            return
        try:
            local_height = self.chain_store.get_local_height()
            target_height = max(self.block_height, local_height, self.connman.best_height)
            if target_height <= 0:
                target_height = max(self.block_height, self.connman.best_height)
            if local_height < 0:
                self.add_log(f"Full sync from genesis to #{target_height}...")
                self.connman.syncing = True
                self.connman.sync_total = max(target_height + 1, 1)
                self.connman.sync_progress = 0
                self._do_sync_batches(0, target_height)
                self.connman.syncing = False
                self.connman.sync_progress = 100
                self.add_log(f"Full sync complete, height: #{self.chain_store.get_local_height()}")
                return
            if local_height < target_height:
                self.connman.syncing = True
                missing = target_height - local_height
                self.connman.sync_total = missing
                self.connman.sync_progress = 0
                self.add_log(f"Behind by {missing} blocks, syncing...")
                self._do_sync_batches(local_height + 1, target_height)
                self.connman.syncing = False
                self.connman.sync_progress = 100
                new_height = self.chain_store.get_local_height()
                self.add_log(f"Sync complete, height: #{new_height}")
            else:
                self.add_log(f"Already up to date: #{local_height}")
        finally:
            self.connman._sync_lock.release()

    def _do_sync_batches(self, start_height, target_height):
        batch_size = 50
        base_interval = 1.0
        max_wait_per_batch = 15.0
        start = start_height
        initial_local = self.chain_store.get_local_height()
        retry_count = 0
        max_retries_per_batch = 5
        consecutive_no_progress = 0
        while start <= target_height and self.connman.running:
            end = min(start + batch_size, target_height + 1)
            best = self.connman.get_best_sync_node()
            if best:
                best.send_message({"type": "get_blocks", "start": start, "end": end})
            else:
                self.connman.broadcast({"type": "get_blocks", "start": start, "end": end})
            wait_start = time.time()
            last_received = self.chain_store.get_local_height()
            received_any = False
            while (time.time() - wait_start < max_wait_per_batch and self.connman.running):
                time.sleep(0.3)
                current_local = self.chain_store.get_local_height()
                if current_local > last_received:
                    last_received = current_local
                    received_any = True
                    wait_start = time.time()
                    consecutive_no_progress = 0
                    if last_received >= end - 1:
                        break
            received = self.chain_store.get_local_height() - initial_local
            if self.connman.sync_total > 0:
                self.connman.sync_progress = min(100, int((received / self.connman.sync_total) * 100))
            actual_local = self.chain_store.get_local_height()
            if actual_local < end - 1:
                if not received_any:
                    retry_count += 1
                    if retry_count >= max_retries_per_batch:
                        if batch_size <= 3:
                            break
                        retry_count = 0
                batch_size = max(1, batch_size // 2)
                base_interval = min(5.0, base_interval * 1.3)
                consecutive_no_progress += 1
                start = actual_local + 1
            else:
                batch_size = min(100, batch_size + 10)
                base_interval = max(0.3, base_interval * 0.85)
                start = end
                retry_count = 0
                consecutive_no_progress = 0
            if start <= target_height and self.connman.running:
                time.sleep(base_interval)

    def _sync_missing_blocks(self, start, end):
        if not self.connman.get_connected_nodes():
            return
        if not self.connman._sync_lock.acquire(blocking=False):
            return
        try:
            self.add_log(f"Syncing missing blocks #{start} to #{end-1}...")
            current = start
            batch_size = min(20, end - current)
            retry_count = 0
            max_retries = 5
            while current < end and self.connman.running and retry_count < max_retries:
                batch_end = min(current + batch_size, end)
                best = self.connman.get_best_sync_node()
                if best:
                    best.send_message({"type": "get_blocks", "start": current, "end": batch_end})
                else:
                    self.connman.broadcast({"type": "get_blocks", "start": current, "end": batch_end})
                wait_start = time.time()
                last_local = self.chain_store.get_local_height()
                received_any = False
                while (time.time() - wait_start < 15.0 and self.connman.running):
                    time.sleep(0.3)
                    new_local = self.chain_store.get_local_height()
                    if new_local > last_local:
                        received_any = True
                        last_local = new_local
                        if last_local >= batch_end - 1:
                            break
                        wait_start = time.time()
                actual_local = self.chain_store.get_local_height()
                if actual_local >= batch_end - 1:
                    current = batch_end
                    batch_size = min(50, batch_size + 10)
                    retry_count = 0
                elif actual_local > current - 1:
                    current = actual_local + 1
                    batch_size = max(1, batch_size // 2)
                    retry_count += 1
                else:
                    batch_size = max(1, batch_size // 2)
                    retry_count += 1
                if current < end and self.connman.running:
                    time.sleep(0.5)
        finally:
            self.connman._sync_lock.release()

    def transfer(self, to_addr, amount):
        if not self.connman.get_connected_nodes():
            return False, "Not connected to any node"
        if not to_addr.startswith("XODE") or len(to_addr) != 20:
            return False, "Invalid address (XODE prefix, 20 chars)"
        try:
            amount = float(amount)
            if amount <= 0:
                return False, "Amount must be > 0"
            total = amount + self.transfer_fee
            if self.wallet.balance < total:
                return False, f"Insufficient balance, need {total} XODE (fee {self.transfer_fee})"
            self.wallet.nonce += 1
            tx_nonce = self.wallet.nonce
            tx_timestamp = int(time.time())
            tx_data = build_sign_message(self.wallet.address, to_addr, amount, tx_nonce, tx_timestamp)
            signature = self.wallet.sign(tx_data)
            self.transfer_result = None
            msg = {
                "type": "transfer",
                "to": to_addr,
                "amount": amount,
                "signature": signature,
                "public_key": self.wallet.public_key,
                "timestamp": tx_timestamp,
                "nonce": tx_nonce
            }
            results = self.connman.broadcast(msg)
            success_count = sum(1 for r in results.values() if r["success"])
            self.add_log(f"Broadcast transfer to {len(results)} nodes, {success_count} succeeded")
            self.wallet.save()
            return True, f"Transfer broadcast to {success_count}/{len(results)} nodes"
        except ValueError:
            return False, "Amount must be a number"
        except Exception as e:
            return False, str(e)

    def _rebuild_balances_silent(self):
        balances = {}
        my_txs = []
        for block in self.chain_store.chain:
            for tx in block.get("transactions", []):
                from_addr = tx.get("from")
                to_addr = tx.get("to")
                amount = float(tx.get("amount", 0) or 0)
                fee = float(tx.get("fee", 0) or 0)
                if from_addr:
                    balances[from_addr] = balances.get(from_addr, 0) - amount - fee
                if to_addr:
                    balances[to_addr] = balances.get(to_addr, 0) + amount
                if fee > 0:
                    balances["XODE0000000000000000"] = balances.get("XODE0000000000000000", 0) + fee
                if self.wallet.address and (from_addr == self.wallet.address or to_addr == self.wallet.address):
                    if tx not in my_txs:
                        my_txs.append(tx)
            reward = block.get("reward", block.get("reward_tx", {}))
            recipients = reward.get("recipients", [])
            for r in recipients:
                if isinstance(r, dict):
                    addr = r.get("address")
                    amt = float(r.get("amount", 0))
                else:
                    addr = r
                    amt = float(reward.get("per_user", reward.get("reward_per_user", 0)))
                if addr:
                    balances[addr] = balances.get(addr, 0) + amt
                    if addr == self.wallet.address and amt > 0:
                        reward_tx = {
                            "type": "reward",
                            "from": "BLOCK_REWARD",
                            "to": addr,
                            "amount": amt,
                            "fee": 0,
                            "timestamp": block.get("timestamp"),
                            "block_index": block.get("index"),
                            "status": "confirmed"
                        }
                        if reward_tx not in my_txs:
                            my_txs.append(reward_tx)
            burned = reward.get("burned", 0)
            if burned > 0:
                burn_addr = reward.get("burn_address", "XODE0000000000000000")
                balances[burn_addr] = balances.get(burn_addr, 0) + float(burned)
        self.chain_store.balances = balances
        self.chain_store.my_transactions = my_txs
        if self.chain_store.chain:
            self.chain_store._incremental_height = self.chain_store.chain[-1].get("index", -1)
        self.chain_store._save_balances()
        self.chain_store._save_mytx()
        self.local_balances = balances
        self.transaction_history = my_txs

    def _recalc_total_issued_from_balances(self):
        burn_addr = "XODE0000000000000000"
        total = 0.0
        for addr, bal in self.chain_store.balances.items():
            if addr != burn_addr and bal > 0:
                total += bal
        total += self.chain_store.balances.get(burn_addr, 0)
        self.total_issued = round(total, 8)
        self.chain_store.total_issued = self.total_issued

    def get_state(self):
        with self.lock:
            tr = self.transfer_result
            bu = self.balance_update
            self.transfer_result = None
            self.balance_update = None
        self.local_balances = self.chain_store.balances
        self.transaction_history = self.chain_store.my_transactions
        # total_issued 和 burned_total 已从区块消息中更新
        burned_total = self.burned_total
        network_info = self.connman.get_network_info()
        balance_rank = 0
        total_addresses = 0
        return {
            "connected": len(self.connman.get_connected_nodes()) > 0,
            "running": self.connman.running,
            "address": self.wallet.address,
            "public_key": self.wallet.public_key,
            "balance": self.wallet.balance,
            "block_height": self.block_height,
            "total_issued": self.chain_store.total_issued,
            "total_supply": self.total_supply,
            "online_users": self.online_users,
            "pending_tx": self.pending_tx,
            "block_time": self.block_time,
            "block_reward": self.block_reward,
            "transfer_fee": self.transfer_fee,
            "syncing": self.connman.syncing,
            "sync_progress": self.connman.sync_progress,
            "chain_length": len(self.chain_store.chain),
            "local_height": self.chain_store.get_local_height(),
            "logs": self.logs[-50:],
            "transfer_result": tr,
            "balance_update": bu,
            "chain": self.chain_store.chain[-20:] if self.chain_store.chain else [],
            "current_block_reward_addrs": self.current_block_reward_addrs,
            "transaction_history": self.chain_store.my_transactions[-20:] if self.chain_store.my_transactions else [],
            "wallet_file": WALLET_FILE,
            "chain_file": CHAIN_FILE,
            "wallet_created": self.wallet.created_at,
            "balance_rank": 0,
            "total_addresses": 0,
            
            "burned_total": burned_total,
            "first_connect_block": self.first_connect_block,
            "cooldown_blocks": self.cooldown_blocks,
            "cooldown_remaining": self.cooldown_remaining,
            "is_eligible": self.is_eligible,
            "cooldown_users": self.cooldown_users,
            "eligible_users": self.eligible_users,
            "nonce": self.wallet.nonce,
            "network_info": network_info,
            "connected_nodes": network_info.get("connected_nodes", 0)
        }


client = XodeClient()


# ============ HTML Page ============
HTML_PAGE = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>XODE Wallet v3.0 — Glass</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);color:#e0e6ed;min-height:100vh;overflow-x:hidden}
.bg-particles{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0}
.particle{position:absolute;border-radius:50%;background:rgba(0,212,255,0.06);animation:float 20s infinite}
@keyframes float{0%,100%{transform:translateY(0) rotate(0deg)}50%{transform:translateY(-100px) rotate(180deg)}}
.nav-bar{position:sticky;top:0;z-index:100;background:rgba(15,15,35,0.7);backdrop-filter:blur(20px);border-bottom:1px solid rgba(255,255,255,0.08);padding:0 30px;height:64px;display:flex;align-items:center;justify-content:space-between}
.nav-brand{display:flex;align-items:center;gap:12px}
.nav-brand .logo{width:36px;height:36px;background:linear-gradient(135deg,#00d4ff,#7b2cbf);border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:16px;color:#fff}
.nav-brand h1{font-size:18px;font-weight:700;background:linear-gradient(90deg,#00d4ff,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.nav-brand .tag{font-size:11px;color:#6b7a8f;margin-left:8px;padding:2px 8px;background:rgba(255,255,255,0.05);border-radius:6px}
.status-pill{padding:6px 14px;border-radius:20px;font-size:12px;font-weight:600;display:inline-flex;align-items:center;gap:6px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1)}
.status-pill.connected{background:rgba(34,197,94,0.15);border-color:rgba(34,197,94,0.3);color:#22c55e}
.status-pill.disconnected{background:rgba(239,68,68,0.15);border-color:rgba(239,68,68,0.3);color:#ef4444}
.pulse-dot{width:8px;height:8px;border-radius:50%;animation:pulse 2s infinite}
.connected .pulse-dot{background:#22c55e}
.disconnected .pulse-dot{background:#ef4444;animation:none}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(34,197,94,0.4)}50%{opacity:.7;box-shadow:0 0 0 6px rgba(34,197,94,0)}}
.main-layout{display:grid;grid-template-columns:260px 1fr;gap:24px;padding:24px;max-width:1600px;margin:0 auto;position:relative;z-index:1}
@media(max-width:1024px){.main-layout{grid-template-columns:1fr}}
.sidebar{display:flex;flex-direction:column;gap:12px}
.sidebar-card{background:rgba(255,255,255,0.03);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,0.08);border-radius:20px;padding:24px}
.wallet-card{text-align:center;padding:28px 24px}
.wallet-avatar{width:64px;height:64px;background:linear-gradient(135deg,#00d4ff,#7b2cbf);border-radius:50%;margin:0 auto 16px;display:flex;align-items:center;justify-content:center;font-size:24px}
.balance-amount{font-size:36px;font-weight:800;background:linear-gradient(90deg,#00d4ff,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;line-height:1.2}
.balance-label{font-size:12px;color:#6b7a8f;margin-top:4px;text-transform:uppercase;letter-spacing:2px}
.address-box{margin-top:16px;padding:12px;background:rgba(0,0,0,0.2);border-radius:12px;font-family:monospace;font-size:11px;color:#00d4ff;word-break:break-all;border:1px solid rgba(0,212,255,0.15)}
.nav-menu{display:flex;flex-direction:column;gap:4px}
.nav-item{padding:12px 16px;border-radius:12px;font-size:14px;font-weight:500;color:#8b95a5;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:10px;border:none;background:transparent;width:100%;text-align:left}
.nav-item:hover{background:rgba(255,255,255,0.05);color:#e0e6ed}
.nav-item.active{background:linear-gradient(135deg,rgba(0,212,255,0.15),rgba(123,44,191,0.1));color:#00d4ff;border:1px solid rgba(0,212,255,0.2)}
.nav-icon{width:20px;height:20px;display:flex;align-items:center;justify-content:center;font-size:14px}
.content-area{display:flex;flex-direction:column;gap:20px}
.glass-card{background:rgba(255,255,255,0.03);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,0.08);border-radius:20px;padding:24px;transition:all .3s}
.glass-card:hover{border-color:rgba(255,255,255,0.12)}
.section-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.section-title{font-size:16px;font-weight:700;display:flex;align-items:center;gap:10px}
.section-title::before{content:'';width:4px;height:20px;background:linear-gradient(180deg,#00d4ff,#7b2cbf);border-radius:2px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:20px}
.stat-card{background:rgba(255,255,255,0.03);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:20px;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,#00d4ff,#7b2cbf);opacity:0;transition:opacity .3s}
.stat-card:hover::before{opacity:1}
.stat-card:hover{transform:translateY(-2px);border-color:rgba(255,255,255,0.15)}
.stat-icon{position:absolute;top:16px;right:16px;width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:16px;background:rgba(0,212,255,0.1);color:#00d4ff}
.stat-icon.purple{background:rgba(168,85,247,0.1);color:#a855f7}
.stat-icon.green{background:rgba(34,197,94,0.1);color:#22c55e}
.stat-icon.orange{background:rgba(249,115,22,0.1);color:#f97316}
.stat-icon.red{background:rgba(239,68,68,0.1);color:#ef4444}
.stat-label{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:#6b7a8f;margin-bottom:8px}
.stat-value{font-size:26px;font-weight:800;color:#f0f4f8;line-height:1}
.stat-sub{font-size:12px;color:#4a5568;margin-top:6px}
.progress-track{width:100%;height:8px;background:rgba(0,0,0,0.3);border-radius:4px;overflow:hidden;margin-top:12px}
.progress-fill{height:100%;background:linear-gradient(90deg,#00d4ff,#7b2cbf);border-radius:4px;transition:width .6s ease;position:relative}
.progress-fill::after{content:'';position:absolute;top:0;left:0;right:0;bottom:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.3),transparent);animation:shimmer 2s infinite}
@keyframes shimmer{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}
.form-grid{display:grid;grid-template-columns:2fr 1fr 1fr;gap:16px}
@media(max-width:768px){.form-grid{grid-template-columns:1fr}}
.form-group label{display:block;font-size:12px;color:#6b7a8f;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px}
.form-group input,.form-group select{width:100%;padding:14px 16px;background:rgba(0,0,0,0.25);border:1px solid rgba(255,255,255,0.1);border-radius:12px;color:#e0e6ed;font-size:14px;outline:none;transition:all .2s}
.form-group input:focus,.form-group select:focus{border-color:#00d4ff;box-shadow:0 0 0 3px rgba(0,212,255,0.1)}
.form-group input::placeholder{color:#4a5568}
.btn{padding:14px 28px;border:none;border-radius:12px;font-size:14px;font-weight:600;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:8px}
.btn-primary{background:linear-gradient(135deg,#00d4ff,#0099cc);color:#000;box-shadow:0 4px 20px rgba(0,212,255,0.25)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(0,212,255,0.35)}
.btn-danger{background:linear-gradient(135deg,#ef4444,#dc2626);color:#fff;box-shadow:0 4px 20px rgba(239,68,68,0.25)}
.btn-danger:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(239,68,68,0.35)}
.btn-secondary{background:rgba(255,255,255,0.05);color:#e0e6ed;border:1px solid rgba(255,255,255,0.1)}
.btn-secondary:hover{background:rgba(255,255,255,0.1)}
.btn:disabled{opacity:.4;cursor:not-allowed;transform:none!important}
.tab-content{display:none}
.tab-content.active{display:block}
.block-card{background:rgba(0,0,0,0.2);border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:18px;margin-bottom:12px;transition:all .2s}
.block-card:hover{border-color:rgba(0,212,255,0.2);transform:translateX(4px)}
.block-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.block-num{font-size:20px;font-weight:800;color:#00d4ff}
.block-hash{font-family:monospace;font-size:11px;color:#4a5568;background:rgba(0,0,0,0.3);padding:4px 10px;border-radius:6px}
.block-meta{display:flex;gap:20px;font-size:12px;color:#6b7a8f;flex-wrap:wrap}
.block-meta span{display:flex;align-items:center;gap:4px}
.tx-item{background:rgba(0,0,0,0.2);border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:16px;margin-bottom:10px;display:grid;grid-template-columns:auto 1fr auto;gap:16px;align-items:center;transition:all .2s}
.tx-item:hover{border-color:rgba(255,255,255,0.12)}
.tx-icon{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:18px}
.tx-icon.sent{background:rgba(239,68,68,0.1);color:#ef4444}
.tx-icon.received{background:rgba(34,197,94,0.1);color:#22c55e}
.tx-icon.reward{background:rgba(0,212,255,0.1);color:#00d4ff}
.tx-details{min-width:0}
.tx-type{font-size:14px;font-weight:600;color:#f0f4f8}
.tx-addr{font-size:11px;color:#4a5568;font-family:monospace;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tx-amount{text-align:right}
.tx-amount-value{font-size:16px;font-weight:700;color:#00d4ff}
.tx-amount-fee{font-size:11px;color:#f97316;margin-top:2px}
.log-container{background:rgba(0,0,0,0.25);border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:16px;height:400px;overflow-y:auto;font-family:'JetBrains Mono',monospace;font-size:12px;line-height:1.8}
.log-entry{padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.03);display:flex;gap:12px}
.log-time{color:#4a5568;flex-shrink:0}
.log-info{color:#00d4ff}.log-success{color:#22c55e}.log-error{color:#ef4444}.log-warning{color:#f97316}
.toast-container{position:fixed;top:20px;right:20px;z-index:1000;display:flex;flex-direction:column;gap:10px}
.toast{padding:16px 24px;border-radius:14px;font-size:14px;font-weight:500;animation:slideIn .4s cubic-bezier(0.16,1,0.3,1);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,0.1)}
.toast-success{background:rgba(34,197,94,0.15);color:#22c55e;border-color:rgba(34,197,94,0.3)}
.toast-error{background:rgba(239,68,68,0.15);color:#ef4444;border-color:rgba(239,68,68,0.3)}
.toast-info{background:rgba(0,212,255,0.15);color:#00d4ff;border-color:rgba(0,212,255,0.3)}
@keyframes slideIn{from{transform:translateX(120%);opacity:0}to{transform:translateX(0);opacity:1}}
.sync-badge{display:inline-flex;align-items:center;gap:8px;padding:6px 14px;background:rgba(249,115,22,0.1);border:1px solid rgba(249,115,22,0.2);border-radius:20px;color:#f97316;font-size:12px;font-weight:600}
.spinner{width:14px;height:14px;border:2px solid #f97316;border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.danger-zone{background:rgba(239,68,68,0.05);border:1px solid rgba(239,68,68,0.2);border-radius:16px;padding:20px;margin-top:20px}
.danger-title{color:#ef4444;font-weight:700;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.empty-state{text-align:center;padding:60px 20px;color:#4a5568}
.empty-state-icon{font-size:48px;margin-bottom:16px;opacity:.5}
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.1);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,0.2)}
@media(max-width:768px){
.main-layout{padding:12px;gap:16px}
.stats-grid{grid-template-columns:1fr 1fr}
.stat-value{font-size:20px}
.tx-item{grid-template-columns:1fr;gap:8px;text-align:center}
.tx-amount{text-align:center}
}
</style>
</head>
<body>
<div class="bg-particles" id="particles"></div>
<div class="nav-bar">
  <div class="nav-brand">
    <div class="logo">X</div>
    <h1>XODE Wallet</h1>
    <span class="tag">v3.0 · ECDSA secp256k1</span>
  </div>
  <div id="connectionStatus" class="status-pill disconnected">
    <span class="pulse-dot"></span>
    <span id="statusText">Disconnected</span>
  </div>
</div>
<div class="main-layout">
  <aside class="sidebar">
    <div class="sidebar-card wallet-card">
      <div class="wallet-avatar"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg></div>
      <div class="balance-amount" id="balanceDisplay">0</div>
      <div class="balance-label">XODE Balance</div>
      <div class="address-box" id="addressDisplay">Loading...</div>
    </div>
    <div class="sidebar-card" style="padding:12px">
      <div class="nav-menu">
        <button class="nav-item active" onclick="switchTab('connect',this)"><span class="nav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></span> Connect</button>
        <button class="nav-item" onclick="switchTab('transfer',this)"><span class="nav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="1" x2="12" y2="23"></line><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path></svg></span> Transfer</button>
        <button class="nav-item" onclick="switchTab('blocks',this)"><span class="nav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg></span> Blocks</button>
        <button class="nav-item" onclick="switchTab('history',this)"><span class="nav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg></span> History</button>
        <button class="nav-item" onclick="switchTab('wallet',this)"><span class="nav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg></span> Wallet</button>
        <button class="nav-item" onclick="switchTab('logs',this)"><span class="nav-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg></span> Logs</button>
      </div>
    </div>
    <div class="sidebar-card">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:#6b7a8f;margin-bottom:12px">Network</div>
      <div style="display:flex;flex-direction:column;gap:10px">
        <div style="display:flex;justify-content:space-between;font-size:13px"><span style="color:#4a5568">Block Time</span><span style="color:#00d4ff;font-weight:600" id="blockTime">120s</span></div>
        <div style="display:flex;justify-content:space-between;font-size:13px"><span style="color:#4a5568">Reward</span><span style="color:#a855f7;font-weight:600" id="blockReward">1000 XODE</span></div>
        <div style="display:flex;justify-content:space-between;font-size:13px"><span style="color:#4a5568">Fee</span><span style="color:#f97316;font-weight:600" id="transferFee">1 XODE</span></div>
        <div style="display:flex;justify-content:space-between;font-size:13px"><span style="color:#4a5568">Pending</span><span style="color:#e0e6ed;font-weight:600" id="pendingTx">0</span></div>
      </div>
    </div>
  </aside>
  <main class="content-area">
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg></div><div class="stat-label">Block Height</div><div class="stat-value" id="blockHeightDisplay">0</div><div class="stat-sub" id="syncStatus">Not synced</div></div>
      <div class="stat-card"><div class="stat-icon purple"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg></div><div class="stat-label">Online Users</div><div class="stat-value" id="onlineUsers">0</div><div class="stat-sub">active nodes</div></div>
      <div class="stat-card"><div class="stat-icon green"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></div><div class="stat-label">Peers</div><div class="stat-value" id="peerCount">0</div><div class="stat-sub" id="peerSub">connected</div></div>
      <div class="stat-card"><div class="stat-icon orange"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="7"></circle><polyline points="12 8 12 12 15 15"></polyline><path d="M2.5 18.5A5 5 0 0 1 8 22h8a5 5 0 0 0 5-5.5V12"></path></svg></div><div class="stat-label">Issued Supply</div><div class="stat-value" id="issuedDisplay">0</div><div class="stat-sub">/ 2.1B XODE</div><div class="progress-track"><div class="progress-fill" id="supplyProgress" style="width:0%"></div></div></div>
      <div class="stat-card"><div class="stat-icon red"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"></path></svg></div><div class="stat-label">Burned</div><div class="stat-value" id="burnedDisplay">0</div><div class="stat-sub">XODE destroyed</div></div>
      <div class="stat-card" id="cooldownCard"><div class="stat-icon orange"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg></div><div class="stat-label">Cooldown</div><div class="stat-value" id="cooldownDisplay">15</div><div class="stat-sub">blocks remaining</div></div>
      <div class="stat-card" id="eligibleCard" style="display:none"><div class="stat-icon green"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg></div><div class="stat-label">Eligible</div><div class="stat-value">YES</div><div class="stat-sub">Earn rewards now</div></div>
    </div>
    <div id="tab-connect" class="tab-content active">
      <div class="glass-card">
        <div class="section-header"><div class="section-title">Node Connection</div><div id="syncIndicator"></div></div>
        <div class="form-grid">
          <div class="form-group"><label>Node Address</label><input type="text" id="nodeHost" value="82.157.37.13" placeholder="IP or hostname"></div>
          <div class="form-group"><label>Port</label><input type="number" id="nodePort" value="5555"></div>
          <div class="form-group" style="display:flex;align-items:flex-end"><div style="color:#6b7a8f;font-size:13px;padding-bottom:14px">v3.0 Compatible</div></div>
        </div>
        <div style="display:flex;gap:12px;margin-top:20px;flex-wrap:wrap">
          <button class="btn btn-primary" id="connectBtn" onclick="connect()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg> Connect</button>
          <button class="btn btn-danger" id="disconnectBtn" onclick="disconnect()" disabled><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path><line x1="12" y1="2" x2="12" y2="12"></line></svg> Disconnect</button>
          <button class="btn btn-secondary" onclick="syncChain()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg> Sync</button>
          <button class="btn btn-secondary" onclick="getStats()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg> Stats</button>
        </div>
      </div>
      <div class="glass-card">
        <div class="section-title">Supply Progress</div>
        <div class="progress-track" style="height:12px;margin-top:16px"><div class="progress-fill" id="supplyProgress2" style="width:0%"></div></div>
        <div style="display:flex;justify-content:space-between;margin-top:10px;font-size:13px;color:#6b7a8f"><span>0 XODE</span><span id="supplyPercent">0%</span><span>2,100,000,000 XODE</span></div>
      </div>
    </div>
    <div id="tab-transfer" class="tab-content">
      <div class="glass-card">
        <div class="section-title">Transfer XODE</div>
        <div class="form-group" style="margin-bottom:16px"><label>Target Address</label><input type="text" id="transferTo" placeholder="XODE0000000000000000" maxlength="20"></div>
        <div class="form-grid">
          <div class="form-group"><label>Amount (XODE)</label><input type="number" id="transferAmount" placeholder="100" step="0.01" min="0"></div>
          <div class="form-group"><label>Fee</label><input type="text" id="displayFee" value="1 XODE" disabled style="opacity:.6"></div>
          <div class="form-group"><label>Total</label><input type="text" id="displayTotal" value="0 XODE" disabled style="opacity:.6"></div>
        </div>
        <button class="btn btn-primary" id="sendBtn" onclick="sendTransfer()" disabled style="margin-top:20px"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2L11 13"></path><path d="M22 2l-7 20-4-9-9-4 20-7z"></path></svg> Send Transfer</button>
        <div id="transferResult" style="margin-top:20px"></div>
      </div>
    </div>
    <div id="tab-blocks" class="tab-content">
      <div class="glass-card">
        <div class="section-header"><div class="section-title">Blockchain Explorer</div><div style="display:flex;gap:8px"><button class="btn btn-secondary" onclick="syncChain()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg> Sync from Network</button><button class="btn btn-secondary" onclick="showLocalChain()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path><polyline points="17 21 17 13 7 13 7 21"></polyline><polyline points="7 3 7 8 15 8"></polyline></svg> Show Local Chain</button></div></div>
        <div id="blocksContainer"><div class="empty-state"><div class="empty-state-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg></div><div>No blocks loaded yet</div><div style="font-size:13px;margin-top:8px;color:#4a5568">Connect and sync to view blocks</div></div></div>
      </div>
    </div>
    <div id="tab-history" class="tab-content">
      <div class="glass-card">
        <div class="section-header"><div class="section-title">Transaction History</div><div style="display:flex;gap:8px"><button class="btn btn-secondary" onclick="refreshHistory()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg> Refresh</button><button class="btn btn-secondary" onclick="clearHistory()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg> Clear</button></div></div>
        <div id="historyContainer"><div class="empty-state"><div class="empty-state-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg></div><div>No transactions yet</div></div></div>
      </div>
    </div>
    <div id="tab-wallet" class="tab-content">
      <div class="glass-card">
        <div class="section-title">Wallet Details</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px">
          <div class="form-group"><label>Address</label><input type="text" id="walletAddrDetail" readonly value="---"></div>
          <div class="form-group"><label>Public Key</label><input type="text" id="walletPubkeyDetail" readonly value="---"></div>
          <div class="form-group"><label>Balance</label><input type="text" id="walletBalanceDetail" readonly value="0 XODE"></div>
          <div class="form-group"><label>Nonce</label><input type="text" id="walletNonce" readonly value="0"></div>
          <div class="form-group"><label>Created</label><input type="text" id="walletCreated" readonly value="---"></div>
          <div class="form-group"><label>Wallet File</label><input type="text" id="walletFile" readonly value="---"></div>
        </div>
        <div style="margin-top:20px;display:flex;gap:12px;flex-wrap:wrap">
          <button class="btn btn-secondary" id="showPrivkeyBtn" onclick="toggleShowPrivateKey()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg> Show Private Key</button>
          <button class="btn btn-secondary" onclick="exportWallet()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg> Export wallet.dat</button>
        </div>
        <div id="privkeyDisplay" style="display:none;margin-top:16px;padding:16px;background:rgba(249,115,22,0.05);border:1px solid rgba(249,115,22,0.2);border-radius:12px">
          <div style="font-size:12px;color:#6b7a8f;margin-bottom:8px"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg> Private Key (keep secret!)</div>
          <div style="font-family:monospace;font-size:12px;color:#f97316;word-break:break-all" id="privkeyValue"></div>
        </div>
      </div>
      <div class="danger-zone">
        <div class="danger-title"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg> Danger Zone</div>
        <p style="font-size:13px;color:#6b7a8f;margin-bottom:16px">Creating a new wallet will overwrite your current wallet.dat. Make sure you have backed up your private key!</p>
        <button class="btn btn-danger" onclick="createNewWallet()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg> Create New Wallet</button>
      </div>
    </div>
    <div id="tab-logs" class="tab-content">
      <div class="glass-card">
        <div class="section-header"><div class="section-title">System Logs</div><button class="btn btn-secondary" onclick="clearLogs()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg> Clear</button></div>
        <div class="log-container" id="logContainer"><div class="empty-state" style="padding:40px"><div class="empty-state-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg></div><div>No logs yet</div></div></div>
      </div>
    </div>
  </main>
</div>
<div class="toast-container" id="toastContainer"></div>
<script>
const particlesContainer=document.getElementById('particles');
for(let i=0;i<20;i++){const p=document.createElement('div');p.className='particle';const s=Math.random()*100+50;p.style.width=s+'px';p.style.height=s+'px';p.style.left=Math.random()*100+'%';p.style.top=Math.random()*100+'%';p.style.animationDelay=Math.random()*20+'s';p.style.animationDuration=(Math.random()*20+20)+'s';particlesContainer.appendChild(p);}
let currentTab='connect',pollInterval,privateKeyVisible=false,isDisconnecting=false;
function switchTab(tab,el){currentTab=tab;document.querySelectorAll('.nav-item').forEach(t=>t.classList.remove('active'));document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));if(el)el.classList.add('active');else{const items=document.querySelectorAll('.nav-item');for(let i=0;i<items.length;i++){if(items[i].getAttribute('onclick')&&items[i].getAttribute('onclick').indexOf(tab)!==-1){items[i].classList.add('active');break;}}}document.getElementById('tab-'+tab).classList.add('active');}
function showToast(msg,type='info'){const c=document.getElementById('toastContainer'),t=document.createElement('div');t.className='toast toast-'+type;t.textContent=msg;c.appendChild(t);setTimeout(()=>{t.style.animation='slideIn .4s cubic-bezier(0.16,1,0.3,1) reverse';setTimeout(()=>t.remove(),400)},4000);}
async function connect(){const host=document.getElementById('nodeHost').value,port=parseInt(document.getElementById('nodePort').value),btn=document.getElementById('connectBtn');btn.disabled=true;btn.textContent='⏳ Connecting...';try{const res=await fetch('/api/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host,port})});const data=await res.json();if(data.success){showToast(data.message,'success');startPolling()}else{showToast(data.message,'error');btn.disabled=false;btn.textContent='🔗 Connect'}}catch(e){showToast('Failed: '+e.message,'error');btn.disabled=false;btn.textContent='🔗 Connect'}}
async function disconnect(){isDisconnecting=true;stopPolling();await fetch('/api/disconnect',{method:'POST'});showToast('Disconnected','info');updateUI({connected:false});isDisconnecting=false;}
async function syncChain(){const res=await fetch('/api/sync',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error');}
async function getStats(){const res=await fetch('/api/stats',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error');}
async function showLocalChain(){const res=await fetch('/api/local_chain');const data=await res.json();renderBlocks(data.chain);showToast('Loaded '+data.chain.length+' blocks','success');}
async function sendTransfer(){const to=document.getElementById('transferTo').value,amount=document.getElementById('transferAmount').value;const res=await fetch('/api/transfer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({to,amount})});const data=await res.json();showToast(data.message,data.success?'success':'error');if(data.success){document.getElementById('transferTo').value='';document.getElementById('transferAmount').value='';}}
async function refreshHistory(){const res=await fetch('/api/history',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error');}
async function clearHistory(){await fetch('/api/clear_history',{method:'POST'});document.getElementById('historyContainer').innerHTML='<div class="empty-state" style="padding:40px"><div class="empty-state-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg></div><div>History cleared</div></div>';showToast('History cleared','info');}
async function clearLogs(){await fetch('/api/clear_logs',{method:'POST'});document.getElementById('logContainer').innerHTML='<div class="empty-state" style="padding:40px"><div class="empty-state-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg></div><div>Logs cleared</div></div>';showToast('Logs cleared','info');}
function toggleShowPrivateKey(){const display=document.getElementById('privkeyDisplay'),btn=document.getElementById('showPrivkeyBtn');if(display.style.display==='none'||display.style.display===''){display.style.display='block';btn.textContent='🔒 Hide Private Key';showPrivateKey();}else{display.style.display='none';btn.textContent='🔑 Show Private Key';privateKeyVisible=false;}}
async function showPrivateKey(){try{const res=await fetch('/api/wallet_info');const data=await res.json();if(data.private_key){document.getElementById('privkeyValue').textContent=data.private_key;privateKeyVisible=true;}else{showToast('Could not retrieve private key','error')}}catch(e){showToast('Error: '+e.message,'error')}}
async function exportWallet(){try{const res=await fetch('/api/export_wallet_dat');if(!res.ok){showToast('Export failed','error');return}const blob=await res.blob();const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='wallet.dat';a.click();URL.revokeObjectURL(url);showToast('wallet.dat exported!','success');}catch(e){showToast('Export error: '+e.message,'error')}}
async function createNewWallet(){if(!confirm('WARNING: This will overwrite your current wallet!\\nMake sure you have backed up your private key.\\n\\nContinue?'))return;const res=await fetch('/api/new_wallet',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error');if(data.success){setTimeout(()=>location.reload(),1000)}}
function renderHistory(txs){const c=document.getElementById('historyContainer');if(!txs||txs.length===0){c.innerHTML='<div class="empty-state" style="padding:40px"><div class="empty-state-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg></div><div>No transactions yet</div></div>';return;}let html='';[...txs].reverse().forEach(tx=>{const myAddr=document.getElementById('addressDisplay').textContent;const isSent=tx.from===myAddr;const type=isSent?'Sent':tx.to===myAddr?'Received':'Transfer';const icon=isSent?'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>':tx.to===myAddr?'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>':'<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="1" x2="12" y2="23"></line><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path></svg>';const typeClass=isSent?'sent':tx.to===myAddr?'received':'reward';const status=tx.status||'confirmed';const date=tx.timestamp?new Date(tx.timestamp*1000).toLocaleDateString():'Unknown';const counterparty=isSent?(tx.to||'N/A'):(tx.from||'N/A');const feeStr=tx.fee?' <span style="color:#f97316">+'+tx.fee+' fee</span>':'';html+='<div class="tx-item"><div class="tx-icon '+typeClass+'">'+icon+'</div><div class="tx-details"><div class="tx-type">'+type+'</div><div class="tx-addr">'+counterparty+'</div></div><div class="tx-amount"><div class="tx-amount-value">'+(tx.amount||0)+' XODE'+feeStr+'</div><div style="font-size:11px;color:#4a5568">'+(tx.block_index?'Block #'+tx.block_index+' | ':'')+date+'</div></div></div>';});c.innerHTML=html;}
function renderBlocks(chain){const c=document.getElementById('blocksContainer');if(!chain||chain.length===0){c.innerHTML='<div class="empty-state"><div class="empty-state-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg></div><div>No blocks loaded yet</div></div>';return;}let html='';[...chain].reverse().forEach(block=>{const reward=block.reward||block.reward_tx||{},supply=block.supply||{},txs=block.transactions||[];const date=new Date(block.timestamp*1000).toLocaleString();const perUser=reward.per_user||reward.reward_per_user||0;let rewardText='';if(reward.online_count>0){rewardText=perUser+' XODE x '+reward.online_count+' users'}else if(reward.burned>0){rewardText='<span style="color:#ef4444">'+reward.burned+' XODE burned</span>'}else{rewardText=(reward.total||0)+' XODE'}let txDetailsHtml='';if(txs.length>0){txDetailsHtml='<div style="margin-top:12px;padding:12px;background:rgba(0,212,255,0.04);border-radius:10px;border:1px solid rgba(0,212,255,0.15);"><div style="font-size:11px;color:#00d4ff;margin-bottom:8px;font-weight:600">Transactions ('+txs.length+'):</div>'+txs.map((tx,idx)=>'<div style="font-size:12px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.04);'+(idx===txs.length-1?'border-bottom:none;':'')+'"><div style="display:flex;justify-content:space-between;margin-bottom:3px"><span style="color:#6b7a8f;font-size:11px">From:</span><span style="color:#e0e6ed;font-family:monospace;font-size:11px">'+tx.from+'</span></div><div style="display:flex;justify-content:space-between;margin-bottom:3px"><span style="color:#6b7a8f;font-size:11px">To:</span><span style="color:#e0e6ed;font-family:monospace;font-size:11px">'+tx.to+'</span></div><div style="display:flex;justify-content:space-between"><span style="color:#6b7a8f;font-size:11px">Amount:</span><span style="color:#00d4ff;font-weight:600">'+tx.amount+' XODE</span></div></div>').join('')+'</div>';}html+='<div class="block-card"><div class="block-header"><span class="block-num">#'+block.index+'</span><span class="block-hash">'+(block.hash?block.hash.substring(0,24)+'...':'')+'</span></div><div class="block-meta"><span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> '+date+'</span><span><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg> '+(block.previous_hash?block.previous_hash.substring(0,16)+'...':'Genesis')+'</span><span><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="7"></circle><polyline points="12 8 12 12 15 15"></polyline><path d="M2.5 18.5A5 5 0 0 1 8 22h8a5 5 0 0 0 5-5.5V12"></path></svg> '+rewardText+'</span><span><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg> '+(reward.online_count||0)+' online</span>'+(supply.issued?'<span><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg> '+supply.issued.toLocaleString()+' / '+(supply.total?supply.total.toLocaleString():'?')+' XODE</span>':'')+'</div>'+txDetailsHtml+'</div>';});c.innerHTML=html;}
function updateUI(state){const statusEl=document.getElementById('connectionStatus'),statusText=document.getElementById('statusText'),connectBtn=document.getElementById('connectBtn'),disconnectBtn=document.getElementById('disconnectBtn'),sendBtn=document.getElementById('sendBtn');const connected=state.connected;if(connected){statusEl.className='status-pill connected';statusText.textContent='Connected ('+state.connected_nodes+' nodes)';connectBtn.disabled=true;connectBtn.textContent='✅ Connected';disconnectBtn.disabled=false;sendBtn.disabled=false;}else{statusEl.className='status-pill disconnected';statusText.textContent='Disconnected';connectBtn.disabled=false;connectBtn.textContent='🔗 Connect';disconnectBtn.disabled=true;sendBtn.disabled=true;}if(state.balance!==undefined)document.getElementById('balanceDisplay').textContent=state.balance.toLocaleString();if(state.block_height!==undefined)document.getElementById('blockHeightDisplay').textContent=state.block_height.toLocaleString();if(state.online_users!==undefined)document.getElementById('onlineUsers').textContent=state.online_users;if(state.total_issued!==undefined){document.getElementById('issuedDisplay').textContent=state.total_issued.toLocaleString();const pct=state.total_supply?(state.total_issued/state.total_supply*100).toFixed(4):0;document.getElementById('supplyProgress').style.width=pct+'%';document.getElementById('supplyProgress2').style.width=pct+'%';document.getElementById('supplyPercent').textContent=pct+'%';}if(state.burned_total!==undefined)document.getElementById('burnedDisplay').textContent=state.burned_total.toLocaleString();if(state.address){document.getElementById('addressDisplay').textContent=state.address;document.getElementById('walletAddrDetail').value=state.address;}if(state.public_key){document.getElementById('walletPubkeyDetail').value=state.public_key;}if(state.block_time)document.getElementById('blockTime').textContent=state.block_time+'s';if(state.block_reward)document.getElementById('blockReward').textContent=state.block_reward+' XODE';if(state.transfer_fee)document.getElementById('transferFee').textContent=state.transfer_fee+' XODE';if(state.pending_tx!==undefined)document.getElementById('pendingTx').textContent=state.pending_tx;if(state.wallet_file)document.getElementById('walletFile').value=state.wallet_file;if(state.wallet_created)document.getElementById('walletCreated').value=new Date(state.wallet_created*1000).toLocaleString();if(state.balance!==undefined)document.getElementById('walletBalanceDetail').value=state.balance.toLocaleString()+' XODE';if(state.nonce!==undefined)document.getElementById('walletNonce').value=state.nonce;if(state.connected_nodes!==undefined){document.getElementById('peerCount').textContent=state.connected_nodes;document.getElementById('peerSub').textContent=state.connected_nodes===1?'connected':'connected';}const syncEl=document.getElementById('syncStatus'),syncInd=document.getElementById('syncIndicator');if(state.syncing){syncEl.innerHTML='<span class="sync-badge"><span class="spinner"></span>Syncing...</span>';syncInd.innerHTML='<span class="sync-badge"><span class="spinner"></span>Syncing '+state.sync_progress+'%</span>';}else if(state.chain_length&&state.block_height>state.local_height){syncEl.innerHTML='<span style="color:#f97316;font-size:12px">Local: #'+state.local_height+' / #'+state.block_height+'</span>';syncInd.innerHTML='';}else{syncEl.textContent='Synced';syncInd.innerHTML='';}if(state.logs&&state.logs.length>0){const logContainer=document.getElementById('logContainer');let html='';state.logs.forEach(log=>{const levelClass=log.level==='error'?'log-error':log.level==='success'?'log-success':log.level==='warning'?'log-warning':'log-info';html+='<div class="log-entry"><span class="log-time">'+log.time+'</span><span class="'+levelClass+'">'+log.msg+'</span></div>';});logContainer.innerHTML=html;logContainer.scrollTop=logContainer.scrollHeight;}if(state.transfer_result){const resultEl=document.getElementById('transferResult');if(state.transfer_result.success){resultEl.innerHTML='<div style="background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);padding:16px;border-radius:12px;color:#22c55e;"><strong><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg> Transfer Success</strong><br>Sent '+state.transfer_result.amount+' XODE to '+state.transfer_result.to+'<br>Fee: '+(state.transfer_result.fee||0)+' XODE | Balance: '+(state.transfer_result.balance||0)+' XODE</div>';}else{resultEl.innerHTML='<div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);padding:16px;border-radius:12px;color:#ef4444;"><strong><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg> Transfer Failed</strong><br>'+(state.transfer_result.error||'Unknown error')+'</div>';}}if(state.chain){if(!window._lastChainLen||window._lastChainLen!==state.chain.length){window._lastChainLen=state.chain.length;renderBlocks(state.chain);}}if(state.transaction_history){renderHistory(state.transaction_history);}if(state.first_connect_block!==undefined){const cdCard=document.getElementById('cooldownCard'),elCard=document.getElementById('eligibleCard');if(state.is_eligible){cdCard.style.display='none';elCard.style.display='block';}else{cdCard.style.display='block';elCard.style.display='none';const rem=state.cooldown_remaining||0;document.getElementById('cooldownDisplay').textContent=rem;}}}
async function pollState(){if(isDisconnecting)return;try{const res=await fetch('/api/state');if(!res.ok)throw new Error('HTTP '+res.status);const state=await res.json();if(isDisconnecting)return;updateUI(state);}catch(e){console.error('Poll error:',e);if(isDisconnecting)return;updateUI({connected:false,logs:[{time:new Date().toLocaleTimeString(),msg:'Connection lost: '+e.message,level:'error'}]});}}
function startPolling(){if(pollInterval)clearInterval(pollInterval);pollInterval=setInterval(pollState,1000);pollState();}
function stopPolling(){if(pollInterval){clearInterval(pollInterval);pollInterval=null;}}
document.getElementById('transferAmount').addEventListener('input',function(){const amount=parseFloat(this.value)||0;const fee=parseFloat(document.getElementById('transferFee').textContent)||1;document.getElementById('displayTotal').value=(amount+fee).toFixed(2)+' XODE';});
pollState();startPolling();
</script>
</body>
</html>
'''


# ============ API Handler ============
class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_error(self, code, message=None):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        err_msg = message or self.responses.get(code, ('Error',))[0]
        self.wfile.write(json.dumps({"error": err_msg, "code": code}).encode('utf-8'))

    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode('utf-8'))
        elif self.path == '/api/state':
            self.send_json(client.get_state())
        elif self.path == '/api/local_chain':
            self.send_json({"chain": client.chain_store.chain})
        elif self.path == '/api/wallet_info':
            info = {
                "address": client.wallet.address,
                "public_key": client.wallet.public_key,
                "balance": client.wallet.balance,
                "created_at": client.wallet.created_at,
                "private_key": client.wallet.private_key,
                "nonce": client.wallet.nonce,
                "version": client.wallet.version
            }
            self.send_json(info)
        elif self.path == '/api/export_wallet_dat':
            if os.path.exists(WALLET_FILE):
                try:
                    with open(WALLET_FILE, 'rb') as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Disposition', 'attachment; filename="wallet.dat"')
                    self.send_header('Content-Length', str(len(data)))
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(data)
                except Exception as e:
                    self.send_json({"success": False, "message": f"Export failed: {str(e)}"})
            else:
                self.send_json({"success": False, "message": "wallet.dat not found"})

        else:
            self.send_error(404)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        try:
            data = json.loads(body) if body else {}
        except:
            data = {}

        if self.path == '/api/connect':
            success, message = client.connect(host=data.get('host'), port=data.get('port'))
            self.send_json({"success": success, "message": message})
        elif self.path == '/api/disconnect':
            client.disconnect()
            self.send_json({"success": True, "message": "Disconnected"})
        elif self.path == '/api/sync':
            if not client.connman.get_connected_nodes():
                self.send_json({"success": False, "message": "Not connected"})
                return
            threading.Thread(target=client.request_sync, daemon=True).start()
            self.send_json({"success": True, "message": "Sync started"})
        elif self.path == '/api/stats':
            if not client.connman.get_connected_nodes():
                self.send_json({"success": False, "message": "Not connected"})
                return
            client.connman.broadcast({"type": "get_stats"})
            self.send_json({"success": True, "message": "Stats requested"})
        elif self.path == '/api/transfer':
            success, message = client.transfer(data.get('to'), data.get('amount'))
            self.send_json({"success": success, "message": message})
        elif self.path == '/api/clear_logs':
            client.logs = []
            client.transfer_result = None
            client.balance_update = None
            self.send_json({"success": True})
        elif self.path == '/api/new_wallet':
            client.wallet.create_new()
            self.send_json({"success": True, "message": f"New wallet: {client.wallet.address}"})
        elif self.path == '/api/history':
            self.send_json({"success": True, "message": f"{len(client.transaction_history)} transactions"})
        elif self.path == '/api/clear_history':
            client.transaction_history = []
            self.send_json({"success": True})
        else:
            self.send_error(404)

    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

class ReuseAddrServer(HTTPServer):
    allow_reuse_address = True
    allow_reuse_port = True

if __name__ == '__main__':
    import sys
    PORT = 5000
    try:
        server = ReuseAddrServer(('0.0.0.0', PORT), APIHandler)
    except OSError as e:
        print("=" * 60)
        print("XODE Wallet v3.0 - ECDSA secp256k1")
        print(f"[FATAL] Cannot start server on port {PORT}: {e}")
        print(f"        Port may be in use. Try: kill $(lsof -t -i:{PORT})")
        print("=" * 60)
        sys.exit(1)
    print("=" * 60)
    print("XODE Wallet v3.0 - ECDSA secp256k1")
    print(f"Wallet:   {WALLET_FILE}")
    print(f"Chain:    {CHAIN_FILE}")
    print(f"Balances: {BALANCES_FILE}")
    print(f"MyTx:     {MYTX_FILE}")
    print(f"Open http://127.0.0.1:{PORT} in your browser")
    print("=" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[FATAL] Server error: {e}")
    finally:
        print("\nShutting down...")
        try:
            client.disconnect()
        except Exception:
            pass
        try:
            server.shutdown()
        except Exception:
            pass
        print("Shutdown complete.")
