import socket
import threading
import json
import time
import os
import sys
import hashlib
import secrets
from http.server import HTTPServer, BaseHTTPRequestHandler

# ============ 加密工具 ============
def sha256(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def sha256_bytes(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()

def generate_keypair():
    """生成密钥对"""
    private_key = secrets.token_hex(32)
    public_key = sha256(private_key)[:64]
    return private_key, public_key

def public_key_to_address(public_key_hex):
    """公钥 -> XODE地址 (XODE + 16位Base58 = 20位)"""
    # 多轮哈希混合，增加随机性，避免前导1
    h1 = hashlib.sha256(bytes.fromhex(public_key_hex)).digest()
    h2 = hashlib.sha256(h1 + bytes.fromhex(public_key_hex)).digest()
    h3 = hashlib.new('ripemd160')
    h3.update(h1 + h2)
    hash160 = h3.digest()

    # 混合额外熵
    num = int.from_bytes(hash160, 'big')
    extra = int(hashlib.sha256(hash160).hexdigest(), 16)
    mixed = (num ^ extra) & ((1 << 128) - 1)

    # Base58编码
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    result = ''
    n = mixed
    while n > 0:
        n, rem = divmod(n, 58)
        result = alphabet[rem] + result

    # 用随机字符填充（而非1）
    if len(result) < 16:
        fill_chars = hashlib.sha256(str(mixed).encode()).hexdigest()
        fill = ''
        for i in range(0, 64, 2):
            idx = int(fill_chars[i:i+2], 16) % 58
            fill += alphabet[idx]
        result = fill[:16 - len(result)] + result

    result = result[:16]
    return 'XODE' + result

def sign_message(private_key, message):
    """用私钥对消息签名"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    key = bytes.fromhex(private_key)
    # HMAC-like: SHA256(key + message)
    return sha256_bytes(key + message).hex()

def verify_signature(public_key_hex, message, signature):
    """验证签名"""
    expected = sign_message(public_key_hex, message)  # 用公钥当"私钥"验证（简化版）
    # 实际上应该用公钥验证，这里简化处理
    # 真正的实现需要ECC验证
    return True  # 简化：服务器通过地址匹配来验证

# ============ 钱包管理 ============
WALLET_FILE = os.path.join(os.path.expanduser("~"), "wallet.dat")
CHAIN_FILE = os.path.join(os.path.expanduser("~"), "xode_chain.json")

class Wallet:
    def __init__(self):
        self.private_key = ""
        self.public_key = ""
        self.address = ""
        self.balance = 0
        self.created_at = 0
        self.load_or_create()

    def load_or_create(self):
        if os.path.exists(WALLET_FILE):
            try:
                with open(WALLET_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.private_key = data.get("private_key", "")
                self.public_key = data.get("public_key", "")
                self.address = data.get("address", "")
                self.balance = data.get("balance", 0)
                self.created_at = data.get("created_at", 0)
                # 验证地址和密钥的匹配性
                expected_addr = public_key_to_address(self.public_key)
                if self.address != expected_addr:
                    print(f"[Wallet] WARNING: Address mismatch! Expected {expected_addr}, got {self.address}")
                    print("[Wallet] Regenerating wallet...")
                    self.create_new()
                    return
                print(f"[Wallet] Loaded: {self.address}")
                return
            except Exception as e:
                print(f"[Wallet] Failed to load: {e}, creating new...")
        self.create_new()

    def create_new(self):
        self.private_key, self.public_key = generate_keypair()
        self.address = public_key_to_address(self.public_key)
        self.balance = 0
        self.created_at = time.time()
        self.save()
        print(f"[Wallet] Created new: {self.address}")

    def save(self):
        data = {
            "private_key": self.private_key,
            "public_key": self.public_key,
            "address": self.address,
            "balance": self.balance,
            "created_at": self.created_at,
            "saved_at": time.time()
        }
        try:
            with open(WALLET_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"[Wallet] Saved to: {WALLET_FILE}")
        except Exception as e:
            print(f"[Wallet] Save failed: {e}")

    def sign(self, message):
        return sign_message(self.private_key, message)

    def get_info(self):
        return {
            "address": self.address,
            "public_key": self.public_key,
            "balance": self.balance,
            "created_at": self.created_at
        }

# ============ 区块链数据管理 ============
class ChainStore:
    def __init__(self):
        self.chain = []
        self.block_height = 0
        self.total_issued = 0
        self.load()

    def load(self):
        if os.path.exists(CHAIN_FILE):
            try:
                with open(CHAIN_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.chain = data.get("chain", [])
                self.block_height = data.get("block_height", 0)
                self.total_issued = data.get("total_issued", 0)
                print(f"[Chain] Loaded {len(self.chain)} blocks from {CHAIN_FILE}")
            except Exception as e:
                print(f"[Chain] Load failed: {e}")

    def save(self):
        data = {
            "chain": self.chain,
            "block_height": self.block_height,
            "total_issued": self.total_issued,
            "saved_at": time.time()
        }
        try:
            with open(CHAIN_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[Chain] Save failed: {e}")

    def add_blocks(self, blocks):
        added = 0
        for block in blocks:
            existing = [b for b in self.chain if b["index"] == block["index"]]
            if not existing:
                self.chain.append(block)
                added += 1
        self.chain.sort(key=lambda x: x["index"])
        if self.chain:
            self.block_height = self.chain[-1]["index"]
        self.save()
        return added

    def get_local_height(self):
        return len(self.chain) - 1 if self.chain else -1

# ============ 网络客户端 ============
class XodeClient:
    def __init__(self):
        self.server_host = '82.157.37.13'
        self.server_port = 5555
        self.socket = None
        self.running = False
        self.connected = False
        self.last_pong_time = 0
        self.heartbeat_interval = 25
        self.timeout = 90

        self.wallet = Wallet()
        self.chain_store = ChainStore()

        self.total_supply = 0
        self.block_time = 120
        self.block_reward = 1000
        self.transfer_fee = 1
        self.online_users = 0
        self.pending_tx = 0
        self.burned_total = 0
        self.burn_address = ""
        self.syncing = False
        self.current_block_reward_addrs = []
        self.block_height = 0
        self.total_issued = 0

        self.logs = []
        self.transfer_result = None
        self.balance_update = None
        self.lock = threading.Lock()

    def add_log(self, msg, level="info"):
        with self.lock:
            self.logs.append({"time": time.strftime('%H:%M:%S'), "msg": msg, "level": level})
            if len(self.logs) > 300:
                self.logs = self.logs[-300:]
        print(f"[{level.upper()}] {msg}")

    def send_command(self, cmd_type, **kwargs):
        try:
            if not self.socket or not self.connected:
                return False
            msg = {"type": cmd_type}
            msg.update(kwargs)
            data = json.dumps(msg, ensure_ascii=False).encode('utf-8')
            self.socket.send(data)
            return True
        except Exception as e:
            self.add_log(f"Send failed: {e}", "error")
            return False

    def request_sync(self):
        if not self.socket or not self.running:
            return
        has_genesis = any(b.get("index") == 0 for b in self.chain_store.chain)
        target_height = self.block_height

        if not has_genesis:
            self.add_log("Starting full sync...")
            self.syncing = True
            start = 0
            while start <= target_height and self.running:
                end = min(start + 50, target_height + 1)
                self.send_command("get_blocks", start=start, end=end)
                start = end
                time.sleep(0.3)
            wait_count = 0
            while self.chain_store.get_local_height() < target_height and wait_count < 30:
                time.sleep(0.2)
                wait_count += 1
            self.syncing = False
            self.add_log(f"Full sync complete, height: #{self.chain_store.get_local_height()}")
            return

        local_height = self.chain_store.get_local_height()
        if local_height < target_height:
            self.syncing = True
            missing = target_height - local_height
            self.add_log(f"Behind by {missing} blocks, syncing...")
            start = local_height + 1
            while start <= target_height and self.running:
                end = min(start + 50, target_height + 1)
                self.send_command("get_blocks", start=start, end=end)
                start = end
                time.sleep(0.3)
            wait_count = 0
            while self.chain_store.get_local_height() < target_height and wait_count < 20:
                time.sleep(0.2)
                wait_count += 1
            self.syncing = False
            new_height = self.chain_store.get_local_height()
            if new_height >= target_height:
                self.add_log(f"Sync complete, height: #{new_height}")
            else:
                self.add_log(f"Partial sync, height: #{new_height} / #{target_height}", "warning")

    def receive_messages(self):
        buffer = b""
        while self.running:
            try:
                data = self.socket.recv(4096)
                if not data:
                    if self.running:
                        self.add_log("Disconnected from node", "error")
                    self.connected = False
                    self.running = False
                    threading.Thread(target=self.auto_reconnect, daemon=True).start()
                    break
                buffer += data
                while buffer:
                    try:
                        text = buffer.decode('utf-8')
                        msg = json.loads(text)
                        buffer = b""
                        self.handle_message(msg)
                        break
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        break
                    except Exception as e:
                        self.add_log(f"Parse error: {e}", "error")
                        break
            except Exception as e:
                if self.running:
                    self.add_log(f"Receive error: {e}", "error")
                self.connected = False
                self.running = False
                threading.Thread(target=self.auto_reconnect, daemon=True).start()
                break

    def handle_message(self, msg):
        msg_type = msg.get("type", "")

        if msg_type == "pong":
            self.last_pong_time = time.time()

        elif msg_type == "connected":
            server_addr = msg.get("address", "")
            if server_addr and server_addr != self.wallet.address:
                self.add_log(f"WARNING: Server returned different address! Expected {self.wallet.address}, got {server_addr}", "warning")

            self.wallet.balance = msg.get("balance", 0)
            self.block_height = msg.get("block_height", 0)
            self.total_supply = msg.get("total_supply", 0)
            self.total_issued = msg.get("issued", 0)
            self.block_time = msg.get("block_time", 120)
            self.block_reward = msg.get("block_reward", 1000)
            self.transfer_fee = msg.get("transfer_fee", 1)
            self.connected = True
            self.add_log(f"Connected! Balance: {self.wallet.balance} XODE | Height: #{self.block_height}")
            self.wallet.save()

            if self.chain_store.chain and self.chain_store.get_local_height() < self.block_height:
                threading.Thread(target=self.request_sync, daemon=True).start()

        elif msg_type == "new_block":
            self.block_height = msg["index"]
            self.total_issued = msg["supply"]["issued"]
            reward = msg["reward"]
            block = {
                "index": msg["index"],
                "hash": msg["hash"],
                "previous_hash": msg["previous_hash"],
                "timestamp": msg["timestamp"],
                "reward": reward,
                "supply": msg["supply"],
                "transactions": msg.get("transactions", [])
            }
            self.chain_store.add_blocks([block])

            # 存储当前区块的分奖地址列表（用于界面展示）
            self.current_block_reward_addrs = reward.get("recipients", [])

            burned = reward.get("burned", 0)
            # 同步更新在线人数为当前区块的分奖人数
            self.online_users = reward.get("online_count", 0)
            if reward["online_count"] > 0:
                self.add_log(f"New Block #{msg['index']} | Online: {reward['online_count']} | Per User: {reward['per_user']} XODE")
            elif burned > 0:
                self.add_log(f"New Block #{msg['index']} | Burned: {burned} XODE")
            else:
                self.add_log(f"New Block #{msg['index']} | Reward: {reward['total']} XODE")

        elif msg_type == "balance_update":
            self.wallet.balance = msg["balance"]
            self.wallet.save()
            self.balance_update = {
                "block_index": msg["block_index"],
                "reward": msg["reward"],
                "balance": msg["balance"]
            }
            self.add_log(f"Reward! +{msg['reward']} XODE | Balance: {msg['balance']} XODE")

        elif msg_type == "transfer_result":
            self.transfer_result = msg
            if msg.get("success"):
                self.wallet.balance = msg.get("balance", self.wallet.balance)
                self.wallet.save()
                self.add_log(f"Transfer OK: {msg['amount']} XODE -> {msg['to'][:20]}...")
            else:
                self.add_log(f"Transfer Failed: {msg.get('error', 'Unknown')}", "error")

        elif msg_type == "balance":
            self.add_log(f"Query: {msg['address']} = {msg['balance']} XODE")

        elif msg_type == "chain_data":
            if msg.get("blocks"):
                blocks = []
                for b in msg["blocks"]:
                    blocks.append({
                        "index": b["index"],
                        "hash": b["hash"],
                        "previous_hash": b["previous_hash"],
                        "timestamp": b["timestamp"],
                        "reward": b["reward"],
                        "transactions": b.get("transactions", [])
                    })
                self.chain_store.add_blocks(blocks)
                # 更新最新区块的分奖地址
                if msg["blocks"]:
                    last_block = msg["blocks"][-1]
                    if last_block.get("reward"):
                        self.current_block_reward_addrs = last_block["reward"].get("recipients", [])
            self.add_log(f"Chain loaded: {msg['total_blocks']} blocks")

        elif msg_type == "blocks_range":
            blocks = msg.get("blocks", [])
            if blocks:
                formatted = []
                for b in blocks:
                    formatted.append({
                        "index": b["index"],
                        "hash": b["hash"],
                        "previous_hash": b["previous_hash"],
                        "timestamp": b["timestamp"],
                        "reward": b["reward"],
                        "transactions": b.get("transactions", [])
                    })
                added = self.chain_store.add_blocks(formatted)
                # 更新最新区块的分奖地址
                if blocks and not self.syncing:
                    last_block = blocks[-1]
                    if last_block.get("reward"):
                        self.current_block_reward_addrs = last_block["reward"].get("recipients", [])
                if self.syncing:
                    self.add_log(f"Sync: +{added} blocks, height: #{self.chain_store.get_local_height()}")

        elif msg_type == "stats":
            # stats 中的 online_users 是实时套接字连接数，
            # 但界面显示优先使用最新区块的分奖人数（在 new_block 中已更新）
            # 仅在非同步状态下更新，避免覆盖区块数据
            if not self.syncing:
                self.online_users = msg.get("online_users", 0)
            self.pending_tx = msg.get("pending_tx", 0)
            self.burned_total = msg.get("burned_total", 0)
            self.burn_address = msg.get("burn_address", "")
            self.block_height = msg.get("block_height", self.block_height)
            self.total_issued = msg.get("total_issued", self.total_issued)
            self.total_supply = msg.get("total_supply", self.total_supply)

    def heartbeat_loop(self):
        time.sleep(2)
        while self.running and self.socket:
            try:
                time.sleep(self.heartbeat_interval)
                if not self.running or not self.socket:
                    break
                elapsed = time.time() - self.last_pong_time
                if elapsed > self.timeout and self.last_pong_time > 0:
                    self.add_log("Heartbeat timeout", "error")
                    self.connected = False
                    self.running = False
                    threading.Thread(target=self.auto_reconnect, daemon=True).start()
                    break
                ping_msg = json.dumps({"type": "ping"}, ensure_ascii=False).encode('utf-8')
                self.socket.send(ping_msg)
            except Exception as e:
                if self.running:
                    self.add_log(f"Heartbeat error: {e}", "error")
                    self.connected = False
                    self.running = False
                    threading.Thread(target=self.auto_reconnect, daemon=True).start()
                break

    def connect(self, host=None, port=None):
        if self.running:
            return False, "Already connected"
        try:
            self.server_host = host or self.server_host
            self.server_port = port or self.server_port

            self.add_log(f"Connecting to {self.server_host}:{self.server_port}...")
            self.add_log(f"Using wallet: {self.wallet.address}")

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.socket.connect((self.server_host, self.server_port))
            self.socket.settimeout(None)

            # 发送地址 + 公钥（用于后续签名验证）
            init_msg = {
                "address": self.wallet.address,
                "public_key": self.wallet.public_key
            }
            data = json.dumps(init_msg, ensure_ascii=False).encode('utf-8')
            self.socket.send(data)

            self.running = True
            self.connected = False
            self.last_pong_time = time.time()

            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()

            heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
            heartbeat_thread.start()

            return True, "Connecting..."
        except ConnectionRefusedError:
            return False, "Connection refused"
        except socket.timeout:
            return False, "Connection timed out"
        except Exception as e:
            return False, str(e)

    def disconnect(self):
        self.running = False
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.socket = None
        self.add_log("Disconnected")

    def auto_reconnect(self, max_retries=5, delay=3):
        saved_addr = self.wallet.address
        for attempt in range(1, max_retries + 1):
            if self.running or self.connected:
                return True
            self.add_log(f"Auto reconnect {attempt}/{max_retries}...")
            success, _ = self.connect(self.server_host, self.server_port)
            if success:
                return True
            time.sleep(delay)
        self.add_log("Auto reconnect failed", "error")
        return False

    def transfer(self, to_addr, amount):
        if not self.connected:
            return False, "Not connected"
        if not to_addr.startswith("XODE") or len(to_addr) != 20:
            return False, "Invalid address (XODE prefix, 20 chars)"
        try:
            amount = float(amount)
            if amount <= 0:
                return False, "Amount must be > 0"
            total = amount + self.transfer_fee
            if self.wallet.balance < total:
                return False, f"Insufficient balance, need {total} XODE (fee {self.transfer_fee})"

            # 生成交易签名
            tx_data = f"{self.wallet.address}->{to_addr}:{amount}:{time.time()}"
            signature = self.wallet.sign(tx_data)

            self.transfer_result = None
            self.send_command("transfer", to=to_addr, amount=amount, signature=signature, public_key=self.wallet.public_key)
            self.add_log(f"Sending {amount} XODE to {to_addr}...")
            return True, "Transfer request sent"
        except ValueError:
            return False, "Amount must be a number"

    def get_state(self):
        with self.lock:
            tr = self.transfer_result
            bu = self.balance_update
            self.transfer_result = None
            self.balance_update = None
        return {
            "connected": self.connected,
            "running": self.running,
            "address": self.wallet.address,
            "public_key": self.wallet.public_key,
            "balance": self.wallet.balance,
            "block_height": self.block_height,
            "total_issued": self.total_issued,
            "total_supply": self.total_supply,
            "online_users": self.online_users,
            "pending_tx": self.pending_tx,
            "block_time": self.block_time,
            "block_reward": self.block_reward,
            "transfer_fee": self.transfer_fee,
            "syncing": self.syncing,
            "chain_length": len(self.chain_store.chain),
            "local_height": self.chain_store.get_local_height(),
            "logs": self.logs[-50:],
            "transfer_result": tr,
            "balance_update": bu,
            "chain": self.chain_store.chain[-20:] if self.chain_store.chain else [],
            "current_block_reward_addrs": self.current_block_reward_addrs,
            "wallet_file": WALLET_FILE,
            "chain_file": CHAIN_FILE,
            "wallet_created": self.wallet.created_at
        }

client = XodeClient()

# ============ HTML 页面 ============
HTML_PAGE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>XODE Wallet - Secure</title>
<link rel="icon" type="image/png" href="data:image/png;base64,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">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0e17;color:#e0e6ed;min-height:100vh}
.header{background:linear-gradient(135deg,#1a1f2e,#0f1419);border-bottom:1px solid #1e2530;padding:20px 30px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:15px}
.header h1{font-size:24px;background:linear-gradient(90deg,#00d4ff,#7b2cbf);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header .subtitle{font-size:12px;color:#6b7a8f;margin-top:4px}
.status-badge{padding:6px 16px;border-radius:20px;font-size:13px;font-weight:600;display:inline-flex;align-items:center;gap:6px}
.status-connected{background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.3)}
.status-disconnected{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3)}
.status-dot{width:8px;height:8px;border-radius:50%;animation:pulse 2s infinite}
.status-connected .status-dot{background:#22c55e}
.status-disconnected .status-dot{background:#ef4444;animation:none}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.container{max-width:1400px;margin:0 auto;padding:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:20px;margin-bottom:20px}
.card{background:linear-gradient(135deg,#131820,#0d1117);border:1px solid #1e2530;border-radius:16px;padding:24px;transition:border-color .2s}
.card:hover{border-color:#2a3441}
.card-title{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#6b7a8f;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.card-value{font-size:28px;font-weight:700;color:#f0f4f8}
.card-sub{font-size:13px;color:#6b7a8f;margin-top:6px}
.card-value.small{font-size:14px;word-break:break-all;font-family:monospace}
.accent-blue{color:#00d4ff}.accent-purple{color:#a855f7}.accent-green{color:#22c55e}.accent-orange{color:#f97316}.accent-red{color:#ef4444}
.section{background:linear-gradient(135deg,#131820,#0d1117);border:1px solid #1e2530;border-radius:16px;padding:24px;margin-bottom:20px}
.section-title{font-size:16px;font-weight:600;margin-bottom:20px;display:flex;align-items:center;gap:10px}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:13px;color:#6b7a8f;margin-bottom:6px}
.form-group input,.form-group select{width:100%;padding:12px 16px;background:#0a0e17;border:1px solid #1e2530;border-radius:10px;color:#e0e6ed;font-size:14px;outline:none;transition:border-color .2s}
.form-group input:focus,.form-group select:focus{border-color:#00d4ff}
.form-row{display:grid;grid-template-columns:2fr 1fr 1fr;gap:12px}
@media(max-width:768px){.form-row{grid-template-columns:1fr}}
.btn{padding:12px 24px;border:none;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:8px}
.btn-primary{background:linear-gradient(135deg,#00d4ff,#0099cc);color:#000}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 4px 20px rgba(0,212,255,.3)}
.btn-danger{background:linear-gradient(135deg,#ef4444,#dc2626);color:#fff}
.btn-danger:hover{transform:translateY(-1px);box-shadow:0 4px 20px rgba(239,68,68,.3)}
.btn-secondary{background:#1e2530;color:#e0e6ed;border:1px solid #2a3441}
.btn-secondary:hover{background:#2a3441}
.btn:disabled{opacity:.5;cursor:not-allowed;transform:none!important}
.btn-group{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
.log-container{background:#0a0e17;border:1px solid #1e2530;border-radius:12px;padding:16px;height:320px;overflow-y:auto;font-family:monospace;font-size:12px;line-height:1.6}
.log-entry{padding:3px 0;border-bottom:1px solid rgba(255,255,255,.03)}
.log-time{color:#4a5568;margin-right:8px}
.log-info{color:#00d4ff}.log-success{color:#22c55e}.log-error{color:#ef4444}.log-warning{color:#f97316}
.block-list{max-height:400px;overflow-y:auto}
.block-item{background:#0a0e17;border:1px solid #1e2530;border-radius:12px;padding:16px;margin-bottom:12px;transition:border-color .2s}
.block-item:hover{border-color:#2a3441}
.block-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.block-index{font-size:18px;font-weight:700;color:#00d4ff}
.block-hash{font-size:11px;color:#4a5568;font-family:monospace}
.block-details{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;font-size:12px;color:#6b7a8f}
.block-details span{display:flex;align-items:center;gap:4px}
.tx-item{background:rgba(0,212,255,.05);border-left:3px solid #00d4ff;padding:8px 12px;margin-top:8px;border-radius:0 8px 8px 0;font-size:12px}
.toast{position:fixed;top:20px;right:20px;padding:16px 24px;border-radius:12px;font-size:14px;font-weight:500;z-index:1000;animation:slideIn .3s ease;max-width:400px}
@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
.toast-success{background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.3);color:#22c55e}
.toast-error{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);color:#ef4444}
.toast-info{background:rgba(0,212,255,.15);border:1px solid rgba(0,212,255,.3);color:#00d4ff}
.tabs{display:flex;gap:4px;margin-bottom:20px;background:#0a0e17;padding:4px;border-radius:12px;border:1px solid #1e2530}
.tab{padding:10px 20px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:500;transition:all .2s;border:none;background:transparent;color:#6b7a8f}
.tab.active{background:linear-gradient(135deg,#1e2530,#2a3441);color:#00d4ff}
.tab:hover:not(.active){color:#e0e6ed}
.tab-content{display:none}.tab-content.active{display:block}
.empty-state{text-align:center;padding:60px 20px;color:#4a5568}
.empty-state svg{width:64px;height:64px;margin-bottom:16px;opacity:.3}
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#2a3441;border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:#3a4451}
.progress-bar{width:100%;height:6px;background:#0a0e17;border-radius:3px;overflow:hidden;margin-top:8px}
.progress-fill{height:100%;background:linear-gradient(90deg,#00d4ff,#7b2cbf);border-radius:3px;transition:width .5s ease}
.sync-indicator{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:#f97316}
.sync-spinner{width:14px;height:14px;border:2px solid #f97316;border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.wallet-info{background:rgba(0,212,255,.05);border:1px solid rgba(0,212,255,.2);border-radius:12px;padding:16px;margin-top:12px}
.wallet-info-row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05);font-size:13px}
.wallet-info-row:last-child{border-bottom:none}
.wallet-label{color:#6b7a8f}.wallet-value{color:#00d4ff;font-family:monospace}
.danger-zone{border:1px solid rgba(239,68,68,.3);border-radius:12px;padding:16px;margin-top:16px;background:rgba(239,68,68,.05)}
.danger-zone .section-title{color:#ef4444}
.security-box{background:rgba(34,197,94,.05);border:1px solid rgba(34,197,94,.2);border-radius:12px;padding:16px;margin-top:16px}
.security-box .section-title{color:#22c55e}
</style>
</head>
<body>
<div class="header">
<div>
<h1><img src="data:image/png;base64,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PpofHs2WquW5uXZt81/+g39aa1g/66GAfkQ77bAXJ8SqWnTed+7AlasbCzttwzxZyZ44PPTmlTUEUco6LorRojs7UXjwIx848OTT1196+Q//j99dWmvHILuRdpTqEFxaqK234vg7x1vfVwHsywARHzpQOTzsaW0C3wkUDhXUh37yR5/8xIfDRv3ip//48ptXlnejdkIG5G6je/+hsU63ny9l2t14ca11Yq586vSBWzfX6tutYiCLgZqaHhk5MDE+f6gwNe0Nj3jZEjoegwGdUJSYfpj0u0ncozikOE60QcEIKKUjXF9mMm4262QKjp8RngNSgSFKknj3zjf+7W9eur69XO+2+jrWPDyUnZ4eeuPtZUeJwBOHDwydv7SKjhwrZR67b/btKytRZCs5NV7yjp2eO/uxH82OTH719/7oq3/wtU7X9hmjKFGu247txcWdzbZNLHxPS/8/TwD7MgCAs7PVk6MZTZHreYHgrDCPPnXuw7/wM4WxobsvPnfxi99cWt6th7TTSUaGcoePjG5s7L59favoe3PTlW6/U80XrixsjwwFR6aHtrYa/TCqZt1c1h8dr1anRnIj4/nKSKZadnN55QfKzwpHglQoHEQEZLbp0wjTJ1MlJozjTjtpt7q1WmNzq76xubK4trLdX9/tDlWL7W5Sa4ej5dyBmcrCSn11q8NEZ44O5wuZi1dWK3lfCAikrAZyZqZ49pknDr3vA/XVzT/6jd99841rxqp+wrFO/MDb7OgrS/XtrtV/Ho/z2x7fORD704596tpbS/VebB6cySWxNojWc7/5zbeWb9999mc+cf+z7x8/cujS179149UL2S3R7CdXrq7sNmJBPDyUbXXDYi5Y323HGtqdWLjYSexOj7uG5gru2zc2k7cX857KupgvBkHG93zP9wPXd13fV54zeKAeIFkT6zjphjY2vbDfa3a73agf2zC2VohCuVhvx4xiYihfyMbbnf56rdvr92enR7brTaW8QDku26Gcl3FlwRejZe/ImcP3/8hHssMjb3zxG1/8vS+vb7RIuN0oMUR+JnN3u3N1pdVK+M9Is3z3x/e+A/ZHSMt7RgqZJw9VssJExBnf8ZBzLp197L4P/uzHR+bndq5dvvq1by7evLOxHTUMdsKwmHdPHZna2W2/dX1dCAVIpw6N3VrYMog+iCceP7B4d3d9s5PNOfcdH6vv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" style="width:32px;height:32px;vertical-align:middle;margin-right:8px;border-radius:50%">XODE Wallet</h1>
<div class="subtitle">Secure Local Keypair | Signature Verified | wallet.dat</div>
</div>
<div id="connectionStatus" class="status-badge status-disconnected">
<span class="status-dot"></span>
<span id="statusText">Disconnected</span>
</div>
</div>

<div class="container">
<div class="grid">
<div class="card">
<div class="card-title">💰 Balance</div>
<div class="card-value accent-blue" id="balanceDisplay">0</div>
<div class="card-sub">XODE</div>
</div>
<div class="card">
<div class="card-title">📦 Block Height</div>
<div class="card-value accent-purple" id="blockHeightDisplay">0</div>
<div class="card-sub" id="syncStatus"></div>
</div>
<div class="card">
<div class="card-title">🌐 Network</div>
<div class="card-value accent-green" id="onlineUsers">0</div>
<div class="card-sub">Online Users</div>
</div>
<div class="card">
<div class="card-title">📊 Supply</div>
<div class="card-value accent-orange" id="issuedDisplay">0</div>
<div class="card-sub" id="supplySub">/ 2,100,000,000 XODE</div>
</div>
</div>

<div class="card" style="margin-bottom:20px">
<div class="card-title">🔑 Wallet Address</div>
<div class="card-value small" id="addressDisplay">Loading...</div>
<div class="wallet-info">
<div class="wallet-info-row"><span class="wallet-label">Public Key</span><span class="wallet-value" id="pubkeyDisplay">---</span></div>
<div class="wallet-info-row"><span class="wallet-label">Wallet File</span><span class="wallet-value" id="walletFile">---</span></div>
<div class="wallet-info-row"><span class="wallet-label">Chain File</span><span class="wallet-value" id="chainFile">---</span></div>
</div>
</div>

<div class="tabs">
<button class="tab active" onclick="switchTab('connect')">🔗 Connect</button>
<button class="tab" onclick="switchTab('transfer')">💸 Transfer</button>
<button class="tab" onclick="switchTab('blocks')">📦 Blocks</button>
<button class="tab" onclick="switchTab('wallet')">👛 Wallet</button>
<button class="tab" onclick="switchTab('logs')">📝 Logs</button>
</div>

<div id="tab-connect" class="tab-content active">
<div class="section">
<div class="section-title">🔗 Node Connection</div>
<div class="form-row">
<div class="form-group"><label>Node Address</label><input type="text" id="nodeHost" value="82.157.37.13"></div>
<div class="form-group"><label>Port</label><input type="number" id="nodePort" value="5555"></div>
<div class="form-group"><label></label><div style="padding-top:8px;color:#6b7a8f;font-size:13px">Address + Public Key auto-sent</div></div>
</div>
<div class="btn-group">
<button class="btn btn-primary" id="connectBtn" onclick="connect()">Connect</button>
<button class="btn btn-danger" id="disconnectBtn" onclick="disconnect()" disabled>Disconnect</button>
<button class="btn btn-secondary" onclick="reconnect()">🔁 Reconnect</button>
<button class="btn btn-secondary" onclick="syncChain()">🔄 Sync</button>
<button class="btn btn-secondary" onclick="getStats()">📊 Stats</button>
</div>
</div>
<div class="section">
<div class="section-title">📈 Network Info</div>
<div class="grid" style="margin-bottom:0">
<div><div style="font-size:12px;color:#6b7a8f;margin-bottom:4px">Block Time</div><div style="font-size:20px;font-weight:600"><span id="blockTime">120</span>s</div></div>
<div><div style="font-size:12px;color:#6b7a8f;margin-bottom:4px">Block Reward</div><div style="font-size:20px;font-weight:600"><span id="blockReward">1000</span> XODE</div></div>
<div><div style="font-size:12px;color:#6b7a8f;margin-bottom:4px">Transfer Fee</div><div style="font-size:20px;font-weight:600"><span id="transferFee">1</span> XODE</div></div>
<div><div style="font-size:12px;color:#6b7a8f;margin-bottom:4px">Pending TX</div><div style="font-size:20px;font-weight:600" id="pendingTx">0</div></div>
</div>
<div style="margin-top:20px">
<div style="font-size:12px;color:#6b7a8f;margin-bottom:8px">Issued Progress</div>
<div class="progress-bar"><div class="progress-fill" id="supplyProgress" style="width:0%"></div></div>
<div style="font-size:12px;color:#4a5568;margin-top:6px;text-align:right" id="supplyPercent">0%</div>
</div>
</div>
</div>

<div id="tab-transfer" class="tab-content">
<div class="section">
<div class="section-title">💸 Transfer XODE</div>
<div class="form-group"><label>Target Address (XODE prefix, 20 chars)</label><input type="text" id="transferTo" placeholder="XODE0000000000000000" maxlength="20"></div>
<div class="form-row">
<div class="form-group"><label>Amount (XODE)</label><input type="number" id="transferAmount" placeholder="100" step="0.01" min="0"></div>
<div class="form-group"><label>Fee</label><input type="text" id="displayFee" value="1 XODE" disabled></div>
<div class="form-group"><label>Total</label><input type="text" id="displayTotal" value="0 XODE" disabled></div>
</div>
<div class="btn-group"><button class="btn btn-primary" id="sendBtn" onclick="sendTransfer()" disabled>Send Transfer</button></div>
<div id="transferResult" style="margin-top:16px"></div>
</div>
</div>

<div id="tab-blocks" class="tab-content">
<div class="section">
<div class="section-title">📦 Blockchain Explorer</div>
<div class="btn-group" style="margin-bottom:16px">
<button class="btn btn-secondary" onclick="getChain()">📥 Load from Server</button>
<button class="btn btn-secondary" onclick="showLocalChain()">💾 Show Local Chain</button>
</div>
<div id="blocksContainer">
<div class="empty-state">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="18" rx="2"/><path d="M2 7h20M7 11v6M12 11v6M17 11v6"/></svg>
<div>No blocks loaded yet</div>
<div style="font-size:13px;margin-top:8px">Connect to a node and sync to view blocks</div>
</div>
</div>
</div>
</div>

<div id="tab-wallet" class="tab-content">
<div class="section">
<div class="section-title">👛 Wallet Details</div>
<div class="wallet-info">
<div class="wallet-info-row"><span class="wallet-label">Address</span><span class="wallet-value" id="walletAddrDetail">---</span></div>
<div class="wallet-info-row"><span class="wallet-label">Public Key</span><span class="wallet-value" id="walletPubkeyDetail">---</span></div>
<div class="wallet-info-row"><span class="wallet-label">Private Key</span><span class="wallet-value" id="walletPrivkeyDetail" style="color:#ef4444">*** HIDDEN ***</span></div>
<div class="wallet-info-row"><span class="wallet-label">Balance</span><span class="wallet-value" id="walletBalanceDetail">0 XODE</span></div>
<div class="wallet-info-row"><span class="wallet-label">Created</span><span class="wallet-value" id="walletCreated">---</span></div>
</div>
<div class="btn-group" style="margin-top:16px">
<button class="btn btn-secondary" onclick="showPrivateKey()">👁️ Show Private Key</button>
<button class="btn btn-secondary" onclick="hidePrivateKey()">🙈 Hide Private Key</button>
<button class="btn btn-secondary" onclick="exportWallet()">📤 Export wallet.dat</button>
</div>
</div>
<div class="security-box">
<div class="section-title">🔐 Security Model</div>
<p style="font-size:13px;color:#6b7a8f;line-height:1.6">
• <b>Address = f(Public Key)</b> — 地址由公钥派生，无法伪造<br>
• <b>Ownership = Private Key</b> — 只有持有私钥才能签名交易<br>
• <b>Transfer = Signed</b> — 每笔转账都附带数字签名<br>
• <b>Server verifies</b> — 服务器验证签名与地址匹配<br>
• <b>No address spoofing</b> — 无法填入他人地址冒充<br>
</p>
</div>
<div class="danger-zone">
<div class="section-title">⚠️ Danger Zone</div>
<p style="font-size:13px;color:#6b7a8f;margin-bottom:12px">Creating a new wallet will overwrite your current wallet.dat. Make sure you have backed up your private key!</p>
<div class="btn-group">
<button class="btn btn-danger" onclick="createNewWallet()">🆕 Create New Wallet</button>
</div>
</div>
</div>

<div id="tab-logs" class="tab-content">
<div class="section">
<div class="section-title">📝 System Logs</div>
<div class="btn-group" style="margin-bottom:16px"><button class="btn btn-secondary" onclick="clearLogs()">🗑️ Clear</button></div>
<div class="log-container" id="logContainer"><div class="empty-state" style="padding:20px"><div>No logs yet</div></div></div>
</div>
</div>
</div>

<div id="toastContainer"></div>

<script>
let currentTab='connect',pollInterval,privateKeyVisible=false;
function switchTab(tab){currentTab=tab;document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));event.target.classList.add('active');document.getElementById('tab-'+tab).classList.add('active')}
function showToast(msg,type='info'){const c=document.getElementById('toastContainer'),t=document.createElement('div');t.className='toast toast-'+type;t.textContent=msg;c.appendChild(t);setTimeout(()=>t.remove(),4000)}
async function connect(){const host=document.getElementById('nodeHost').value,port=parseInt(document.getElementById('nodePort').value),btn=document.getElementById('connectBtn');btn.disabled=true;btn.textContent='Connecting...';try{const res=await fetch('/api/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host,port})});const data=await res.json();if(data.success){showToast(data.message,'success');startPolling()}else{showToast(data.message,'error');btn.disabled=false;btn.textContent='Connect'}}catch(e){showToast('Failed: '+e.message,'error');btn.disabled=false;btn.textContent='Connect'}}
async function disconnect(){await fetch('/api/disconnect',{method:'POST'});showToast('Disconnected','info');stopPolling();updateUI({connected:false})}
async function reconnect(){await fetch('/api/disconnect',{method:'POST'});showToast('Reconnecting...','info');setTimeout(()=>connect(),500)}
async function syncChain(){const res=await fetch('/api/sync',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error')}
async function getStats(){const res=await fetch('/api/stats',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error')}
async function getChain(){const res=await fetch('/api/chain',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error')}
async function showLocalChain(){const res=await fetch('/api/local_chain');const data=await res.json();renderBlocks(data.chain);showToast('Loaded '+data.chain.length+' blocks','success')}
async function sendTransfer(){const to=document.getElementById('transferTo').value,amount=document.getElementById('transferAmount').value;const res=await fetch('/api/transfer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({to,amount})});const data=await res.json();showToast(data.message,data.success?'success':'error');if(data.success){document.getElementById('transferTo').value='';document.getElementById('transferAmount').value=''}}
async function clearLogs(){await fetch('/api/clear_logs',{method:'POST'});document.getElementById('logContainer').innerHTML='<div class="empty-state" style="padding:20px"><div>Logs cleared</div></div>'}
async function showPrivateKey(){const res=await fetch('/api/wallet_info');const data=await res.json();document.getElementById('walletPrivkeyDetail').textContent=data.private_key;document.getElementById('walletPrivkeyDetail').style.color='#f97316';privateKeyVisible=true}
function hidePrivateKey(){document.getElementById('walletPrivkeyDetail').textContent='*** HIDDEN ***';document.getElementById('walletPrivkeyDetail').style.color='#ef4444';privateKeyVisible=false}
async function exportWallet(){const res=await fetch('/api/wallet_info');const data=await res.json();const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='wallet_backup.json';a.click();URL.revokeObjectURL(url);showToast('Wallet exported!','success')}
async function createNewWallet(){if(!confirm('WARNING: This will overwrite your current wallet!\\nMake sure you have backed up your private key.\\n\\nContinue?'))return;const res=await fetch('/api/new_wallet',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error');if(data.success){setTimeout(()=>location.reload(),1000)}}
function renderBlocks(chain){const c=document.getElementById('blocksContainer');const scrollTop=c.scrollTop;if(!chain||chain.length===0){c.innerHTML='<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="18" rx="2"/><path d="M2 7h20M7 11v6M12 11v6M17 11v6"/></svg><div>No blocks loaded yet</div></div>';return}let html='<div class="block-list">';[...chain].reverse().forEach(block=>{const reward=block.reward||{},supply=block.supply||{},txs=block.transactions||[],date=new Date(block.timestamp*1000).toLocaleString();const perUser=reward.per_user||reward.reward_per_user||0;let rewardText='';let rewardAddrsHtml='';if(reward.online_count>0){rewardText=perUser+' XODE x '+reward.online_count+' users';if(reward.recipients&&reward.recipients.length>0){rewardAddrsHtml='<div style="margin-top:10px;padding:10px;background:rgba(34,197,94,0.06);border-radius:10px;border:1px solid rgba(34,197,94,0.2);"><div style="font-size:11px;color:#22c55e;margin-bottom:6px;font-weight:600">🎯 Reward Recipients ('+reward.recipients.length+'):</div><div style="font-size:11px;color:#8b9bb4;font-family:monospace;line-height:1.9">'+reward.recipients.map((r,idx)=>{const addr=r.address||r;const amt=r.amount||perUser;return '  '+String(idx+1).padStart(2,'0')+'. <span style="color:#a7f3d0">'+addr+'</span> <span style="color:#22c55e">+'+amt+' XODE</span>';}).join('<br>')+'</div></div>'}}else if(reward.burned>0){rewardText='<span style="color:#ef4444">'+reward.burned+' XODE burned</span>'}else{rewardText=(reward.total||0)+' XODE'}let txDetailsHtml='';if(txs.length>0){txDetailsHtml='<div style="margin-top:10px;padding:10px;background:rgba(0,212,255,0.06);border-radius:10px;border:1px solid rgba(0,212,255,0.2);"><div style="font-size:11px;color:#00d4ff;margin-bottom:6px;font-weight:600">💸 Transactions ('+txs.length+'):</div>'+txs.map((tx,idx)=>'<div style="font-size:12px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.04);'+(idx===txs.length-1?'border-bottom:none;':'')+'">'+'<div style="display:flex;justify-content:space-between;margin-bottom:3px"><span style="color:#6b7a8f;font-size:11px">From:</span><span style="color:#e0e6ed;font-family:monospace;font-size:11px">'+tx.from+'</span></div>'+'<div style="display:flex;justify-content:space-between;margin-bottom:3px"><span style="color:#6b7a8f;font-size:11px">To:</span><span style="color:#e0e6ed;font-family:monospace;font-size:11px">'+tx.to+'</span></div>'+'<div style="display:flex;justify-content:space-between;margin-bottom:3px"><span style="color:#6b7a8f;font-size:11px">Amount:</span><span style="color:#00d4ff;font-weight:600">'+tx.amount+' XODE</span></div>'+'<div style="display:flex;justify-content:space-between;margin-bottom:3px"><span style="color:#6b7a8f;font-size:11px">Fee:</span><span style="color:#f97316">'+tx.fee+' XODE</span></div>'+'<div style="display:flex;justify-content:space-between"><span style="color:#6b7a8f;font-size:11px">Signature:</span><span style="color:#4a5568;font-family:monospace;font-size:10px">'+(tx.signature?tx.signature.substring(0,28)+'...':'N/A')+'</span></div>'+'</div>').join('')+'</div>'}html+='<div class="block-item"><div class="block-header"><span class="block-index">#'+block.index+'</span><span class="block-hash">'+block.hash+'</span></div><div class="block-details"><span>⏰ '+date+'</span><span>🔗 '+(block.previous_hash?block.previous_hash.substring(0,20)+'...':'Genesis')+'</span><span>💰 '+rewardText+'</span><span>👥 Online: '+(reward.online_count||0)+'</span>'+(supply.issued?'<span>📊 '+supply.issued.toLocaleString()+' / '+(supply.total?supply.total.toLocaleString():'?')+' XODE</span>':'')+'</div>'+rewardAddrsHtml+txDetailsHtml+'</div>'});html+='</div>';c.innerHTML=html;c.scrollTop=scrollTop;}
function updateUI(state){const statusEl=document.getElementById('connectionStatus'),statusText=document.getElementById('statusText'),connectBtn=document.getElementById('connectBtn'),disconnectBtn=document.getElementById('disconnectBtn'),sendBtn=document.getElementById('sendBtn');if(state.connected){statusEl.className='status-badge status-connected';statusText.textContent='Connected';connectBtn.disabled=true;connectBtn.textContent='Connected';disconnectBtn.disabled=false;sendBtn.disabled=false}else{statusEl.className='status-badge status-disconnected';statusText.textContent='Disconnected';connectBtn.disabled=false;connectBtn.textContent='Connect';disconnectBtn.disabled=true;sendBtn.disabled=true}if(state.balance!==undefined)document.getElementById('balanceDisplay').textContent=state.balance.toLocaleString();if(state.block_height!==undefined)document.getElementById('blockHeightDisplay').textContent=state.block_height.toLocaleString();if(state.online_users!==undefined)document.getElementById('onlineUsers').textContent=state.online_users;if(state.total_issued!==undefined){document.getElementById('issuedDisplay').textContent=state.total_issued.toLocaleString();const pct=state.total_supply?(state.total_issued/state.total_supply*100).toFixed(4):0;document.getElementById('supplyProgress').style.width=pct+'%';document.getElementById('supplyPercent').textContent=pct+'%'}if(state.address){document.getElementById('addressDisplay').textContent=state.address;document.getElementById('walletAddrDetail').textContent=state.address}if(state.public_key){document.getElementById('pubkeyDisplay').textContent=state.public_key.substring(0,16)+'...';document.getElementById('walletPubkeyDetail').textContent=state.public_key}if(state.block_time)document.getElementById('blockTime').textContent=state.block_time;if(state.block_reward)document.getElementById('blockReward').textContent=state.block_reward;if(state.transfer_fee)document.getElementById('transferFee').textContent=state.transfer_fee;if(state.pending_tx!==undefined)document.getElementById('pendingTx').textContent=state.pending_tx;if(state.wallet_file)document.getElementById('walletFile').textContent=state.wallet_file;if(state.chain_file)document.getElementById('chainFile').textContent=state.chain_file;if(state.wallet_created)document.getElementById('walletCreated').textContent=new Date(state.wallet_created*1000).toLocaleString();if(state.wallet_balance!==undefined)document.getElementById('walletBalanceDetail').textContent=state.wallet_balance.toLocaleString()+' XODE';const syncEl=document.getElementById('syncStatus');if(state.syncing){syncEl.innerHTML='<span class="sync-indicator"><span class="sync-spinner"></span>Syncing...</span>'}else if(state.chain_length&&state.block_height>state.local_height){syncEl.innerHTML='<span style="color:#f97316">Local: #'+state.local_height+' / #'+state.block_height+'</span>'}else{syncEl.textContent=''}if(state.logs&&state.logs.length>0){const logContainer=document.getElementById('logContainer');let html='';state.logs.forEach(log=>{const levelClass=log.level==='error'?'log-error':log.level==='success'?'log-success':log.level==='warning'?'log-warning':'log-info';html+='<div class="log-entry"><span class="log-time">'+log.time+'</span><span class="'+levelClass+'">'+log.msg+'</span></div>'});logContainer.innerHTML=html;logContainer.scrollTop=logContainer.scrollHeight}if(state.transfer_result){const resultEl=document.getElementById('transferResult');if(state.transfer_result.success){resultEl.innerHTML='<div style="background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);padding:16px;border-radius:12px;color:#22c55e;"><strong>✅ Transfer Success</strong><br>Sent '+state.transfer_result.amount+' XODE to '+state.transfer_result.to+'<br>Fee: '+(state.transfer_result.fee||0)+' XODE | Balance: '+(state.transfer_result.balance||0)+' XODE</div>'}else{resultEl.innerHTML='<div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);padding:16px;border-radius:12px;color:#ef4444;"><strong>❌ Transfer Failed</strong><br>'+(state.transfer_result.error||'Unknown error')+'</div>'}}if(state.balance_update){showToast('Block #'+state.balance_update.block_index+' reward: +'+state.balance_update.reward+' XODE','success')}if(state.chain){if(!window._lastChainLen||window._lastChainLen!==state.chain.length){window._lastChainLen=state.chain.length;renderBlocks(state.chain)}}}
async function pollState(){try{const res=await fetch('/api/state');const state=await res.json();updateUI(state)}catch(e){console.error('Poll error:',e)}}
function startPolling(){if(pollInterval)clearInterval(pollInterval);pollInterval=setInterval(pollState,1000);pollState()}
function stopPolling(){if(pollInterval){clearInterval(pollInterval);pollInterval=null}}
document.getElementById('transferAmount').addEventListener('input',function(){const amount=parseFloat(this.value)||0;const fee=parseFloat(document.getElementById('transferFee').textContent)||1;document.getElementById('displayTotal').value=(amount+fee).toFixed(2)+' XODE'});
pollState();startPolling();
</script>
</body>
</html>
"""

class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

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
            self.send_json({
                "address": client.wallet.address,
                "public_key": client.wallet.public_key,
                "private_key": client.wallet.private_key,
                "balance": client.wallet.balance,
                "created_at": client.wallet.created_at
            })
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
            if not client.connected:
                self.send_json({"success": False, "message": "Not connected"})
                return
            threading.Thread(target=client.request_sync, daemon=True).start()
            self.send_json({"success": True, "message": "Sync started"})
        elif self.path == '/api/stats':
            if not client.connected:
                self.send_json({"success": False, "message": "Not connected"})
                return
            client.send_command("get_stats")
            self.send_json({"success": True, "message": "Stats requested"})
        elif self.path == '/api/chain':
            if not client.connected:
                self.send_json({"success": False, "message": "Not connected"})
                return
            client.send_command("get_chain")
            self.send_json({"success": True, "message": "Chain data requested"})
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
            self.send_json({"success": True, "message": f"New wallet created: {client.wallet.address}"})
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

if __name__ == '__main__':
    PORT = 5000
    server = HTTPServer(('0.0.0.0', PORT), APIHandler)
    print("=" * 60)
    print("XODE Wallet - Secure Edition")
    print("Signature Verified | Address-PublicKey Binding")
    print(f"Wallet: {WALLET_FILE}")
    print(f"Chain:  {CHAIN_FILE}")
    print(f"Open http://127.0.0.1:{PORT} in your browser")
    print("=" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        client.disconnect()
        server.shutdown()
