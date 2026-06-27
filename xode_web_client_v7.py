import socket
import threading
import json
import time
import os
import sys
import hashlib
import secrets
import hmac
import base64
import struct
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

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

def sign_message(key_hex, message):
    """用密钥对消息签名 - 使用HMAC-SHA256
    key_hex: 如果是公钥，会自动派生签名密钥 (sha256(公钥)[:32])
    message: 签名消息内容（应包含时间戳防重放）
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    # 派生签名密钥：与服务端 verify_signature 保持一致
    # 服务端: key = sha256(bytes.fromhex(public_key)).hexdigest()[:32]
    derived_key = hashlib.sha256(bytes.fromhex(key_hex)).hexdigest()[:32]
    signature = hmac.new(derived_key.encode('utf-8'), message, hashlib.sha256).hexdigest()
    return signature

def verify_signature(public_key_hex, message, signature):
    """验证签名 - 使用HMAC-SHA256比较，防时序攻击"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    # 派生签名密钥：与服务端保持一致
    derived_key = hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:32]
    expected = hmac.new(derived_key.encode('utf-8'), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

# ============ 钱包加密工具 ============
def derive_key(password: str, salt: bytes) -> bytes:
    """使用PBKDF2派生加密密钥"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_private_key(private_key: str, password: str) -> dict:
    """使用AES-256-GCM加密私钥"""
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    plaintext = private_key.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {
        "salt": base64.b64encode(salt).decode('ascii'),
        "nonce": base64.b64encode(nonce).decode('ascii'),
        "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
        "version": 2
    }

def decrypt_private_key(encrypted_data: dict, password: str) -> str:
    """解密私钥"""
    salt = base64.b64decode(encrypted_data["salt"])
    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')

# ============ 钱包管理 ============
WALLET_FILE = os.path.join(os.path.expanduser("~"), "wallet.dat")
CHAIN_FILE = os.path.join(os.path.expanduser("~"), "xode_chain.json")
PASS_FILE = os.path.join(os.path.expanduser("~"), ".xode_pass")
# 默认加密密码
DEFAULT_WALLET_PASSWORD = "XODE_2026"

def load_saved_password():
    """从文件加载保存的密码"""
    if os.path.exists(PASS_FILE):
        try:
            with open(PASS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get("password", DEFAULT_WALLET_PASSWORD)
        except Exception:
            pass
    return DEFAULT_WALLET_PASSWORD

def save_password(password: str):
    """保存密码到文件"""
    try:
        with open(PASS_FILE, 'w', encoding='utf-8') as f:
            json.dump({"password": password}, f, ensure_ascii=False)
    except Exception as e:
        print(f"[Password] Failed to save password: {e}")

# 启动时加载保存的密码
DEFAULT_WALLET_PASSWORD = load_saved_password()

class Wallet:
    def __init__(self):
        self.private_key = ""
        self.public_key = ""
        self.address = ""
        self.balance = 0
        self.created_at = 0
        self._private_key_unlocked = False  # 标记私钥是否已解锁
        self._encrypted_private_key = None  # 加密后的私钥数据
        self.nonce = 0  # 交易 nonce，严格递增防重放
        self.load_or_create()

    def load_or_create(self):
        if os.path.exists(WALLET_FILE):
            try:
                with open(WALLET_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # 支持加密钱包和旧版明文钱包迁移
                if "encrypted_private_key" in data:
                    # 新版加密钱包 - 使用当前 DEFAULT_WALLET_PASSWORD（可能已被用户修改）
                    self._encrypted_private_key = data["encrypted_private_key"]
                    try:
                        self.private_key = decrypt_private_key(self._encrypted_private_key, DEFAULT_WALLET_PASSWORD)
                        self._private_key_unlocked = True
                    except Exception as e:
                        print(f"[Wallet] Failed to decrypt wallet with saved password: {e}")
                        print("[Wallet] Creating new wallet...")
                        self.create_new()
                        return
                elif "private_key" in data:
                    # 旧版明文钱包 - 自动迁移
                    self.private_key = data.get("private_key", "")
                    self._encrypted_private_key = encrypt_private_key(self.private_key, DEFAULT_WALLET_PASSWORD)
                    print("[Wallet] Migrating from plaintext to encrypted storage...")
                else:
                    print("[Wallet] No private key found, creating new...")
                    self.create_new()
                    return

                self.public_key = data.get("public_key", "")
                self.address = data.get("address", "")
                self.balance = data.get("balance", 0)
                self.created_at = data.get("created_at", 0)
                self.nonce = data.get("nonce", 0)

                # 验证地址和密钥的匹配性
                expected_addr = public_key_to_address(self.public_key)
                if self.address != expected_addr:
                    print(f"[Wallet] WARNING: Address mismatch! Expected {expected_addr}, got {self.address}")
                    print("[Wallet] Regenerating wallet...")
                    self.create_new()
                    return

                # 如果是旧版迁移，保存加密版本
                if "encrypted_private_key" not in data and self._encrypted_private_key:
                    self.save()

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
        self._private_key_unlocked = True
        self._encrypted_private_key = encrypt_private_key(self.private_key, DEFAULT_WALLET_PASSWORD)
        self.nonce = 0
        self.save()
        # 确保密码已持久化
        save_password(DEFAULT_WALLET_PASSWORD)
        print(f"[Wallet] Created new: {self.address}")

    def save(self):
        # 保存加密后的私钥
        if self._encrypted_private_key is None and self.private_key:
            self._encrypted_private_key = encrypt_private_key(self.private_key, DEFAULT_WALLET_PASSWORD)

        data = {
            "public_key": self.public_key,
            "address": self.address,
            "balance": self.balance,
            "created_at": self.created_at,
            "saved_at": time.time(),
            "nonce": self.nonce,
            "encrypted_private_key": self._encrypted_private_key
        }
        try:
            with open(WALLET_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"[Wallet] Saved to: {WALLET_FILE}")
        except Exception as e:
            print(f"[Wallet] Save failed: {e}")

    def sign(self, message):
        if not self._private_key_unlocked:
            raise PermissionError("Private key is locked. Please unlock first.")
        # 使用 public_key 派生签名密钥，与服务端 verify_signature 保持一致
        return sign_message(self.public_key, message)

    def get_info(self):
        return {
            "address": self.address,
            "public_key": self.public_key,
            "balance": self.balance,
            "created_at": self.created_at,
            "private_key_locked": not self._private_key_unlocked
        }

    def unlock_private_key(self, password: str = None) -> bool:
        """解锁私钥查看"""
        if password is None:
            password = DEFAULT_WALLET_PASSWORD
        try:
            if self._encrypted_private_key:
                self.private_key = decrypt_private_key(self._encrypted_private_key, password)
                self._private_key_unlocked = True
                return True
        except Exception:
            pass
        return False

    def lock_private_key(self):
        """锁定私钥"""
        self._private_key_unlocked = False

    def change_password(self, old_password: str, new_password: str) -> bool:
        """修改钱包密码 - 新密码会持久化保存，重启后自动复用"""
        try:
            # 先用旧密码解密
            if self._encrypted_private_key is None:
                return False, "No encrypted private key found"

            private_key = decrypt_private_key(self._encrypted_private_key, old_password)

            # 用新密码重新加密
            self._encrypted_private_key = encrypt_private_key(private_key, new_password)
            self.private_key = private_key
            self._private_key_unlocked = True

            # 保存钱包文件
            self.save()

            # 持久化保存新密码，重启后自动复用
            global DEFAULT_WALLET_PASSWORD
            DEFAULT_WALLET_PASSWORD = new_password
            save_password(new_password)

            return True, "Password changed successfully. New password will be used after restart."
        except Exception as e:
            return False, f"Failed to change password: {str(e)}"

# ============ 区块链数据管理 ============
class ChainStore:
    def __init__(self):
        self.chain = []
        self.block_height = 0
        self.first_connect_block = None  # 首次连接时的区块高度
        self.cooldown_blocks = 15  # 新用户冷却区块数
        self.cooldown_remaining = 0  # 剩余冷却区块数
        self.is_eligible = False  # 是否已满足冷却条件
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
        """添加区块，验证 hash 链连续性"""
        added = 0
        rejected = 0

        # 先按 index 排序，确保按顺序验证
        sorted_blocks = sorted(blocks, key=lambda x: x.get("index", 0))

        for block in sorted_blocks:
            idx = block.get("index")
            if idx is None:
                rejected += 1
                continue

            # 检查是否已存在
            existing = [b for b in self.chain if b["index"] == idx]
            if existing:
                # 已存在，跳过（可选：验证 hash 是否一致，不一致说明分叉）
                if existing[0].get("hash") != block.get("hash"):
                    print(f"[ChainStore] WARNING: Block #{idx} hash mismatch! Existing: {existing[0].get('hash')[:16]}... New: {block.get('hash')[:16]}...")
                continue

            # 验证 hash 链连续性
            if idx == 0:
                # 创世区块：previous_hash 应为 "0" * 64
                prev_hash = block.get("previous_hash", "")
                if prev_hash != "0" * 64:
                    print(f"[ChainStore] REJECTED: Genesis block #{idx} has invalid previous_hash: {prev_hash[:16]}...")
                    rejected += 1
                    continue
            else:
                # 非创世区块：previous_hash 必须等于前一个区块的 hash
                prev_blocks = [b for b in self.chain if b["index"] == idx - 1]
                if not prev_blocks:
                    print(f"[ChainStore] REJECTED: Block #{idx} has no predecessor (previous block #{idx-1} not found)")
                    rejected += 1
                    continue
                expected_prev_hash = prev_blocks[0].get("hash", "")
                actual_prev_hash = block.get("previous_hash", "")
                if actual_prev_hash != expected_prev_hash:
                    print(f"[ChainStore] REJECTED: Block #{idx} previous_hash mismatch!")
                    print(f"  Expected: {expected_prev_hash}")
                    print(f"  Actual:   {actual_prev_hash}")
                    rejected += 1
                    continue

            self.chain.append(block)
            added += 1

        self.chain.sort(key=lambda x: x["index"])
        if self.chain:
            self.block_height = self.chain[-1]["index"]
        self.save()

        if rejected > 0:
            print(f"[ChainStore] Added {added}, rejected {rejected} blocks")

        return added

    def get_local_height(self):
        if not self.chain:
            return -1
        # 返回最后一个区块的实际索引，而不是链长度-1
        # 因为链中可能有空洞（同步时跳过某些区块）
        self.chain.sort(key=lambda x: x["index"])
        return self.chain[-1]["index"] if self.chain else -1

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
        self.balance_rank = 0
        self.total_addresses = 0
        self.server_rankings = []
        self.local_balances = {}  # 从本地链重建的余额字典
        self.syncing = False
        self.sync_progress = 0
        self.sync_total = 0
        self.current_block_reward_addrs = []
        self.block_height = 0
        self.first_connect_block = None  # 首次连接时的区块高度
        self.cooldown_blocks = 15  # 新用户冷却区块数
        self.cooldown_remaining = 0  # 剩余冷却区块数
        self.is_eligible = False  # 是否已满足冷却条件
        self.cooldown_users = 0  # 冷却中人数（服务端统计）
        self.total_issued = 0
        self.transaction_history = []

        self.logs = []
        self.transfer_result = None
        self.balance_update = None
        self.lock = threading.Lock()
        self.manual_disconnect = False  # 标记是否用户主动退出
        self._reconnecting = False  # 添加重连锁，防止多个重连线程同时运行
        self._sync_lock = threading.Lock()  # 同步锁，防止并发同步

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
            data = encode_message(msg)
            self.socket.sendall(data)
            return True
        except Exception as e:
            self.add_log(f"Send failed: {e}", "error")
            return False

    def request_sync(self):
        if not self.socket or not self.running:
            return

        # 获取锁，防止并发同步
        if not self._sync_lock.acquire(blocking=False):
            self.add_log("Sync already in progress, skipping request_sync...", "warning")
            return

        try:
            has_genesis = any(b.get("index") == 0 for b in self.chain_store.chain)
            local_height = self.chain_store.get_local_height()
            target_height = max(self.block_height, local_height)

            if not has_genesis:
                self.add_log("Starting full sync...")
                self.syncing = True
                self.sync_total = target_height + 1
                self.sync_progress = 0
                self._do_sync_batches(0, target_height)
                self.syncing = False
                self.sync_progress = 100
                self.add_log(f"Full sync complete, height: #{self.chain_store.get_local_height()}")
                return

            if local_height < target_height:
                self.syncing = True
                missing = target_height - local_height
                self.sync_total = missing
                self.sync_progress = 0
                self.add_log(f"Behind by {missing} blocks, syncing...")
                self._do_sync_batches(local_height + 1, target_height)
                self.syncing = False
                self.sync_progress = 100
                new_height = self.chain_store.get_local_height()
                if new_height >= target_height:
                    self.add_log(f"Sync complete, height: #{new_height}")
                else:
                    self.add_log(f"Partial sync, height: #{new_height} / #{target_height}", "warning")
        finally:
            self._sync_lock.release()

    def _do_sync_batches(self, start_height, target_height):
        """核心同步逻辑：自适应批次大小和间隔"""
        batch_size = 50
        base_interval = 1.0  # 初始间隔 1.0 秒（比原来的 0.5 宽松）
        max_wait_per_batch = 15.0  # 每批最长等待 15 秒
        start = start_height
        initial_local = self.chain_store.get_local_height()

        while start <= target_height and self.running:
            end = min(start + batch_size, target_height + 1)
            self.send_command("get_blocks", start=start, end=end)
            self.add_log(f"Requesting blocks #{start} to #{end-1} (batch={batch_size})...")

            # 等待这批区块到达，用实际收到高度判断
            wait_start = time.time()
            last_received = self.chain_store.get_local_height()

            while (self.chain_store.get_local_height() < end - 1 and 
                   time.time() - wait_start < max_wait_per_batch and 
                   self.running):
                time.sleep(0.2)
                # 如果高度有变化，重置等待计时器（给更多时间接收后续区块）
                if self.chain_store.get_local_height() > last_received:
                    last_received = self.chain_store.get_local_height()
                    wait_start = time.time()  # 重置计时器

            # 计算实际进度：用收到的高度 vs 目标
            received = self.chain_store.get_local_height() - initial_local
            if self.sync_total > 0:
                self.sync_progress = min(100, int((received / self.sync_total) * 100))

            # 自适应调整：如果这批没收到，减小批次、增大间隔
            actual_received = self.chain_store.get_local_height()
            if actual_received < end - 1:
                # 部分或全部丢失，减小批次
                old_batch = batch_size
                batch_size = max(10, batch_size // 2)
                base_interval = min(5.0, base_interval * 1.5)
                self.add_log(
                    f"Batch incomplete: received up to #{actual_received}, "
                    f"expected up to #{end-1}. Reducing batch {old_batch}->{batch_size}, "
                    f"interval {base_interval:.1f}s", "warning"
                )
                # 从实际收到的高度+1继续，而不是跳到end
                start = actual_received + 1
            else:
                # 正常收到，可以稍微增大批次、恢复正常间隔
                batch_size = min(100, batch_size + 10)
                base_interval = max(0.5, base_interval * 0.85)
                start = end

            # 批次间间隔
            if start <= target_height and self.running:
                time.sleep(base_interval)

        # 最终等待：确保所有区块都处理完
        final_wait = 0
        while (self.chain_store.get_local_height() < target_height and 
               final_wait < 30 and self.running):
            time.sleep(0.3)
            final_wait += 1
            if self.sync_total > 0:
                received = self.chain_store.get_local_height() - initial_local
                self.sync_progress = min(100, int((received / self.sync_total) * 100))

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
                    if not self.manual_disconnect:
                        threading.Thread(target=self.auto_reconnect, daemon=True).start()
                    break
                buffer += data

                # 使用 Magic + Length 协议解析消息
                messages, buffer = decode_messages(buffer)

                for msg in messages:
                    self.handle_message(msg)

            except Exception as e:
                if self.running:
                    self.add_log(f"Receive error: {e}", "error")
                self.connected = False
                self.running = False
                if not self.manual_disconnect:
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
            self.burned_total = msg.get("burned_total", 0)
            self.connected = True

            # 使用服务端字段名：blocks_remaining / reward_eligible
            server_cooldown = msg.get("blocks_remaining")
            server_eligible = msg.get("reward_eligible")
            server_first_block = msg.get("first_connect_block")

            if server_cooldown is not None:
                # 服务端明确告诉冷却状态，直接同步
                self.cooldown_remaining = server_cooldown
                if server_eligible is not None:
                    self.is_eligible = server_eligible
                if server_first_block is not None:
                    self.first_connect_block = server_first_block
                self.add_log(f"Server cooldown state: {self.cooldown_remaining} blocks remaining, eligible={self.is_eligible}")
            else:
                # 服务端没传，用客户端本地计算
                if self.first_connect_block is None:
                    self.first_connect_block = self.block_height
                    self.add_log(f"First connection at block #{self.block_height}. Cooldown: {self.cooldown_blocks} blocks", "warning")
                self._update_cooldown_status()

            self.add_log(f"Connected! Balance: {self.wallet.balance} XODE | Height: #{self.block_height}")
            self.wallet.save()

            if self.chain_store.chain and self.chain_store.get_local_height() < self.block_height:
                threading.Thread(target=self.request_sync, daemon=True).start()

        elif msg_type == "new_block":
            new_index = msg["index"]
            self.block_height = new_index
            self.total_issued = msg["supply"]["issued"]
            reward = msg["reward"]
            block = {
                "index": new_index,
                "hash": msg["hash"],
                "previous_hash": msg["previous_hash"],
                "timestamp": msg["timestamp"],
                "reward": reward,
                "supply": msg["supply"],
                "transactions": msg.get("transactions", [])
            }

            # 检查是否有缺失区块（比如网络丢包导致错过某些区块）
            local_height = self.chain_store.get_local_height()
            if local_height >= 0 and new_index > local_height + 1:
                # 有缺失区块，先同步缺失的区块再添加当前区块
                missing_start = local_height + 1
                missing_end = new_index
                self.add_log(f"Gap detected: missing blocks #{missing_start} to #{missing_end-1}, requesting sync...", "warning")
                threading.Thread(target=self._sync_missing_blocks, args=(missing_start, missing_end), daemon=True).start()

            self.chain_store.add_blocks([block])
            self._update_tx_history_from_blocks([block])

            # 存储当前区块的分奖地址列表（用于界面展示）
            self.current_block_reward_addrs = reward.get("recipients", [])

            burned = reward.get("burned", 0)
            # 同步更新在线人数为当前区块的分奖人数
            self.online_users = reward.get("online_count", 0)
            # 更新冷却中人数（从服务端区块数据）
            self.cooldown_users = reward.get("ineligible_count", 0)

            # 更新冷却状态
            self._update_cooldown_status()
            # 累计销毁量改为从区块实时计算，不再缓存
            # self.burned_total = msg["supply"]["burned_total"] if "supply" in msg and "burned_total" in msg["supply"] else self.burned_total
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
            # 收到奖励说明服务端认为已满足冷却，同步状态
            if not self.is_eligible:
                self.is_eligible = True
                self.cooldown_remaining = 0
                self.add_log(f"🎉 Cooldown complete! You are now eligible for block rewards!", "success")
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
                # 更新交易历史
                self._update_tx_history_from_blocks(blocks)
            self.add_log(f"Chain loaded: {msg['total_blocks']} blocks")

        elif msg_type == "history":
            self.transaction_history = msg.get("transactions", [])
            self.add_log(f"Loaded {len(self.transaction_history)} transactions from history")

        elif msg_type == "rankings":
            self.server_rankings = msg.get("rankings", [])
            self.total_addresses = msg.get("total_addresses", 0)
            self.add_log(f"Loaded {len(self.server_rankings)} rankings from server, total {self.total_addresses} addresses")
            # 更新自己的排名
            my_addr = msg.get("my_address", "")
            my_bal = msg.get("my_balance", 0)
            for r in self.server_rankings:
                if r.get("address") == my_addr:
                    self.balance_rank = r.get("rank", 0)
                    break
            else:
                # 如果不在前100名，计算排名
                self.balance_rank = self._calculate_balance_rank()
            self.add_log(f"My rank: #{self.balance_rank}, balance: {my_bal} XODE")

        elif msg_type == "blocks_range":
            blocks = msg.get("blocks", [])
            if blocks:
                self.add_log(f"Received blocks_range: {len(blocks)} blocks (indexes {blocks[0]['index']}-{blocks[-1]['index']})")
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
                if added > 0:
                    self._update_tx_history_from_blocks(formatted)
                if added < len(formatted):
                    self.add_log(f"Blocks range: {added}/{len(formatted)} accepted, {len(formatted)-added} rejected (invalid hash chain)", "warning")
                local_height = self.chain_store.get_local_height()
                self.add_log(f"Added {added} blocks, local height now: #{local_height}")

                # 检查是否还有缺失区块
                if blocks:
                    last_received = blocks[-1]["index"]
                    if self.block_height > last_received:
                        self.add_log(f"Still behind: local #{local_height} / server #{self.block_height}, will auto-sync...", "warning")
                        if not self.syncing:
                            threading.Thread(target=self.request_sync, daemon=True).start()

                # 更新最新区块的分奖地址
                if blocks and not self.syncing:
                    last_block = blocks[-1]
                    if last_block.get("reward"):
                        self.current_block_reward_addrs = last_block["reward"].get("recipients", [])
                if self.syncing:
                    self.add_log(f"Sync: +{added} blocks, height: #{local_height}")
            else:
                self.add_log("Received blocks_range: empty blocks array", "warning")

        elif msg_type == "stats":
            # stats 中的 online_users 是实时套接字连接数，
            # 但界面显示优先使用最新区块的分奖人数（在 new_block 中已更新）
            # 不再从 stats 更新 online_users，只使用 new_block 的数据（有资格分奖人数含服务器）
            # 避免 stats 的 socket 连接数覆盖正确的区块分奖人数
            # if not self.syncing:
            #     self.online_users = msg.get("online_users", 0)
            # 从 stats 获取冷却中人数（服务端 v14+ 支持）
            self.cooldown_users = msg.get("ineligible_users", self.cooldown_users)
            self.pending_tx = msg.get("pending_tx", 0)
            # burned_total 改为从区块实时计算，不再缓存
            # self.burned_total = msg.get("burned_total", 0)
            self.burn_address = msg.get("burn_address", "")
            # 使用服务端高度，但不低于本地链高度（避免空洞导致的高度回退）
            server_height = msg.get("block_height", self.block_height)
            local_height = self.chain_store.get_local_height()
            self.block_height = max(server_height, local_height)
            self.total_issued = msg.get("total_issued", self.total_issued)
            self.total_supply = msg.get("total_supply", self.total_supply)
            self.balance_rank = msg.get("balance_rank", 0)
            self.total_addresses = msg.get("total_addresses", 0)

            # 从服务器获取最新高度后，检查是否需要自动同步
            server_height = msg.get("block_height", 0)
            local_height = self.chain_store.get_local_height()
            if local_height >= 0 and server_height > local_height and not self.syncing:
                missing = server_height - local_height
                # 如果只差1-2个区块，可能是 new_block 消息丢失，直接请求缺失的区块
                if missing <= 2:
                    self.add_log(f"Auto sync: behind by {missing} block(s), requesting specific blocks...", "warning")
                    threading.Thread(target=self._sync_missing_blocks, args=(local_height + 1, server_height + 1), daemon=True).start()
                elif missing > 2 and missing <= 10:
                    # 中等差距，用轻量同步
                    self.add_log(f"Auto sync: behind by {missing} blocks, light sync...", "warning")
                    threading.Thread(target=self._sync_missing_blocks, args=(local_height + 1, server_height + 1), daemon=True).start()
                else:
                    # 大差距，用完整同步（带锁保护）
                    self.add_log(f"Auto sync: behind by {missing} blocks, full sync...", "warning")
                    threading.Thread(target=self.request_sync, daemon=True).start()

    def heartbeat_loop(self):
        time.sleep(2)
        sync_check_counter = 0
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
                    if not self.manual_disconnect:
                        threading.Thread(target=self.auto_reconnect, daemon=True).start()
                    break

                # 每3次心跳请求一次服务器状态，获取最新高度
                sync_check_counter += 1
                if sync_check_counter >= 3:
                    sync_check_counter = 0
                    self.send_command("get_stats")
                    # 心跳只检查是否需要同步，不直接触发全量同步
                    # 实际同步由 handle_message 中的 stats 响应或 new_block 触发

                ping_msg = encode_message({"type": "ping"})
                self.socket.sendall(ping_msg)
            except Exception as e:
                if self.running:
                    self.add_log(f"Heartbeat error: {e}", "error")
                    self.connected = False
                    self.running = False
                    threading.Thread(target=self.auto_reconnect, daemon=True).start()
                break

    def connect(self, host=None, port=None):
        self.manual_disconnect = False  # 重置主动退出标志
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
            data = encode_message(init_msg)
            self.socket.sendall(data)

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
        self.manual_disconnect = True  # 标记为主动退出
        self.running = False
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.socket = None
        self._reconnecting = False  # 重置重连锁
        self.add_log("Disconnected")

    def auto_reconnect(self, max_retries=5, delay=300):
        """自动重连，使用指数退避，添加_reconnecting锁防线程爆炸"""
        # 使用重连锁防止多个重连线程同时运行
        if self._reconnecting:
            self.add_log("Reconnect already in progress, skipping...", "warning")
            return False

        self._reconnecting = True
        saved_addr = self.wallet.address

        try:
            for attempt in range(1, max_retries + 1):
                if self.running or self.connected:
                    return True
                self.add_log(f"Auto reconnect {attempt}/{max_retries}...")
                success, _ = self.connect(self.server_host, self.server_port)
                if success:
                    return True

                # 使用指数退避策略：300, 600, 1200...
                wait_time = delay * (2 ** (attempt - 1))  # 指数退避: 300, 600, 1200...
                self.add_log(f"Reconnect failed, waiting {wait_time}s (server rate limit)...")
                time.sleep(wait_time)

            self.add_log("Auto reconnect failed", "error")
            return False
        finally:
            self._reconnecting = False

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

            # Nonce 防重放：严格递增
            self.wallet.nonce += 1
            tx_nonce = self.wallet.nonce

            # 使用 nonce + 时间戳签名，双重防重放
            tx_timestamp = int(time.time())
            tx_data = f"{self.wallet.address}{to_addr}{amount}{tx_nonce}{tx_timestamp}"
            signature = self.wallet.sign(tx_data)

            self.transfer_result = None
            self.send_command("transfer", to=to_addr, amount=amount, 
                              signature=signature, public_key=self.wallet.public_key,
                              timestamp=tx_timestamp, nonce=tx_nonce)
            self.add_log(f"Sending {amount} XODE to {to_addr} (nonce: {tx_nonce}, timestamp: {tx_timestamp})...")

            # 保存 nonce 到钱包文件
            self.wallet.save()

            return True, "Transfer request sent"
        except ValueError:
            return False, "Amount must be a number"
        except PermissionError as e:
            return False, str(e)

    def _update_tx_history_from_blocks(self, blocks):
        """从区块中提取当前地址相关的交易"""
        for block in blocks:
            for tx in block.get("transactions", []):
                if tx.get("from") == self.wallet.address or tx.get("to") == self.wallet.address:
                    if tx not in self.transaction_history:
                        self.transaction_history.append(tx)
        # 限制交易历史内存占用，保留最近 500 条
        if len(self.transaction_history) > 500:
            self.transaction_history = self.transaction_history[-500:]

    def rebuild_balances_from_history(self):
        """从交易历史重建余额（更准确，因为历史记录金额正确）"""
        balances = {}

        # 1. 先处理所有区块中的奖励（这部分数据是准确的）
        for block in self.chain_store.chain:
            reward = block.get("reward", {})
            recipients = reward.get("recipients", [])
            if recipients:
                for r in recipients:
                    if isinstance(r, dict):
                        addr = r.get("address")
                        try:
                            amt = float(r.get("amount", 0))
                        except:
                            amt = 0
                    else:
                        addr = r
                        try:
                            amt = float(reward.get("per_user", 0))
                        except:
                            amt = 0
                    if addr:
                        balances[addr] = balances.get(addr, 0) + amt

            burned = reward.get("burned", 0)
            if burned > 0:
                burn_addr = reward.get("burn_address", "XODE0000000000000000")
                try:
                    burned = float(burned)
                except:
                    burned = 0
                balances[burn_addr] = balances.get(burn_addr, 0) + burned

        # 2. 从交易历史处理转账（金额准确）
        for tx in self.transaction_history:
            from_addr = tx.get("from")
            to_addr = tx.get("to")
            amount = tx.get("amount", 0) or 0
            fee = tx.get("fee", 0) or 0

            try:
                amount = float(amount)
            except:
                amount = 0
            try:
                fee = float(fee)
            except:
                fee = 0

            if from_addr:
                balances[from_addr] = balances.get(from_addr, 0) - amount - fee
            if to_addr:
                balances[to_addr] = balances.get(to_addr, 0) + amount
            if fee > 0:
                burn_addr = "XODE0000000000000000"
                balances[burn_addr] = balances.get(burn_addr, 0) + fee

        self.local_balances = balances
        return balances

    def rebuild_balances(self):
        """重建余额：优先使用历史记录数据（更准确）"""
        # 如果有历史记录，用历史记录计算
        if self.transaction_history:
            return self.rebuild_balances_from_history()
        # 否则用区块数据（可能不准确）
        return self._rebuild_balances_from_blocks()

    def request_history(self):
        """请求交易历史"""
        if self.connected:
            self.send_command("get_history", address=self.wallet.address)

    def request_rankings(self):
        """请求余额排行榜"""
        if self.connected:
            self.send_command("get_rankings", limit=100)

    def _rebuild_balances_from_blocks(self):
        """从本地链重建所有地址余额（从区块数据，可能不准确）"""
        balances = {}

        for block in self.chain_store.chain:
            # 1. 处理转账交易
            for tx in block.get("transactions", []):
                from_addr = tx.get("from")
                to_addr = tx.get("to")
                amount = tx.get("amount", 0) or 0
                fee = tx.get("fee", 0) or 0

                try:
                    amount = float(amount)
                except:
                    amount = 0
                try:
                    fee = float(fee)
                except:
                    fee = 0

                if from_addr:
                    balances[from_addr] = balances.get(from_addr, 0) - amount - fee
                if to_addr:
                    balances[to_addr] = balances.get(to_addr, 0) + amount
                if fee > 0:
                    burn_addr = "XODE0000000000000000"
                    balances[burn_addr] = balances.get(burn_addr, 0) + fee

            # 2. 处理区块奖励
            reward = block.get("reward", {})
            recipients = reward.get("recipients", [])
            if recipients:
                for r in recipients:
                    if isinstance(r, dict):
                        addr = r.get("address")
                        try:
                            amt = float(r.get("amount", 0))
                        except:
                            amt = 0
                    else:
                        addr = r
                        try:
                            amt = float(reward.get("per_user", 0))
                        except:
                            amt = 0
                    if addr:
                        balances[addr] = balances.get(addr, 0) + amt

            # 3. 处理销毁（无人在线时）
            burned = reward.get("burned", 0)
            if burned > 0:
                burn_addr = reward.get("burn_address", "XODE0000000000000000")
                try:
                    burned = float(burned)
                except:
                    burned = 0
                balances[burn_addr] = balances.get(burn_addr, 0) + burned

        self.local_balances = balances
        return balances

    def get_balance_from_chain(self, address):
        """从本地链计算指定地址余额"""
        if not self.local_balances:
            self.rebuild_balances()
        return self.local_balances.get(address, 0)

    def get_all_rankings(self):
        """获取完整排行榜（纯本地计算）"""
        # 如果链为空，返回空列表
        if not self.chain_store.chain:
            self.add_log("[Rankings] Chain is empty, no data available")
            return []
        balances = self.rebuild_balances()

        # 过滤掉余额 <= 0 的地址
        valid = {k: v for k, v in balances.items() if v > 0}

        self.add_log(f"[Rankings] Rebuilt {len(valid)} addresses from {len(self.chain_store.chain)} blocks")

        if self.wallet.address in valid:
            self.add_log(f"[Rankings] My balance: {valid[self.wallet.address]:.2f} XODE")
        else:
            self.add_log(f"[Rankings] My address not in balances")

        sorted_items = sorted(valid.items(), key=lambda x: x[1], reverse=True)
        return [
            {"rank": i + 1, "address": addr, "balance": round(bal, 2), "is_me": addr == self.wallet.address}
            for i, (addr, bal) in enumerate(sorted_items)
        ]

    def get_my_rank(self):
        """获取当前地址排名"""
        balances = self.rebuild_balances()
        valid = {k: v for k, v in balances.items() if v > 0}

        if self.wallet.address not in valid:
            return 0, len(valid)

        sorted_items = sorted(valid.items(), key=lambda x: x[1], reverse=True)
        for i, (addr, bal) in enumerate(sorted_items, 1):
            if addr == self.wallet.address:
                return i, len(valid)
        return 0, len(valid)

    def _sync_missing_blocks(self, start, end):
        """同步指定范围的缺失区块（轻量版，带锁保护）"""
        if not self.socket or not self.running:
            return
        if not self._sync_lock.acquire(blocking=False):
            self.add_log("Sync already in progress, skipping _sync_missing_blocks...", "warning")
            return
        try:
            self.add_log(f"Syncing missing blocks #{start} to #{end-1}...")
            current = start
            batch_size = min(20, end - current)  # 小批次，更可靠

            while current < end and self.running:
                batch_end = min(current + batch_size, end)
                self.send_command("get_blocks", start=current, end=batch_end)
                self.add_log(f"Requesting missing blocks #{current} to #{batch_end-1}...")

                # 等待这批区块到达
                wait_start = time.time()
                while (self.chain_store.get_local_height() < batch_end - 1 and 
                       time.time() - wait_start < 10.0 and self.running):
                    time.sleep(0.2)

                # 如果没收到，减小批次重试
                if self.chain_store.get_local_height() < batch_end - 1:
                    batch_size = max(5, batch_size // 2)
                    self.add_log(f"Reducing missing sync batch to {batch_size}", "warning")
                    # 不跳到 batch_end，从实际收到+1继续
                    current = self.chain_store.get_local_height() + 1
                else:
                    current = batch_end

                if current < end and self.running:
                    time.sleep(0.5)  # 批次间间隔

            self.add_log(f"Missing blocks sync complete, height: #{self.chain_store.get_local_height()}")
        finally:
            self._sync_lock.release()

    def _calculate_balance_rank(self):
        """计算当前钱包余额排名"""
        rank, total = self.get_my_rank()
        return rank

    def _get_total_addresses(self):
        """获取链上总地址数"""
        balances = self.rebuild_balances()
        valid = {k: v for k, v in balances.items() if v > 0}
        return len(valid)

    def _update_cooldown_status(self):
        """更新冷却状态"""
        if self.first_connect_block is None:
            self.cooldown_remaining = self.cooldown_blocks
            self.is_eligible = False
            return

        elapsed = self.block_height - self.first_connect_block + 1
        self.cooldown_remaining = max(0, self.cooldown_blocks - elapsed)

        was_eligible = self.is_eligible
        self.is_eligible = self.cooldown_remaining == 0

        if not was_eligible and self.is_eligible:
            self.add_log(f"🎉 Cooldown complete! You are now eligible for block rewards!", "success")
        elif self.cooldown_remaining > 0 and self.cooldown_remaining <= 3:
            self.add_log(f"⏳ Cooldown: {self.cooldown_remaining} blocks remaining until eligible", "warning")

    def get_state(self):
        with self.lock:
            tr = self.transfer_result
            bu = self.balance_update
            self.transfer_result = None
            self.balance_update = None
        # 计算 burned_total：从完整本地链的所有区块累加
        burned_total = 0
        for block in self.chain_store.chain:
            supply = block.get("supply", {})
            if "burned_total" in supply and supply["burned_total"] is not None:
                try:
                    burned_total = float(supply["burned_total"])
                except:
                    pass
            else:
                reward = block.get("reward", {})
                burned = reward.get("burned", 0)
                if burned:
                    try:
                        burned_total += float(burned)
                    except:
                        pass
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
            "sync_progress": self.sync_progress,
            "chain_length": len(self.chain_store.chain),
            "local_height": self.chain_store.get_local_height(),
            "logs": self.logs[-50:],
            "transfer_result": tr,
            "balance_update": bu,
            "chain": self.chain_store.chain[-20:] if self.chain_store.chain else [],
            "current_block_reward_addrs": self.current_block_reward_addrs,
            "transaction_history": self.transaction_history[-20:] if self.transaction_history else [],
            "wallet_file": WALLET_FILE,
            "chain_file": CHAIN_FILE,
            "wallet_created": self.wallet.created_at,
            "balance_rank": self._calculate_balance_rank(),
            "total_addresses": self._get_total_addresses(),
            "server_rankings": self.server_rankings,
            "burned_total": burned_total,
            "first_connect_block": self.first_connect_block,
            "cooldown_blocks": self.cooldown_blocks,
            "cooldown_remaining": self.cooldown_remaining,
            "is_eligible": self.is_eligible,
            "cooldown_users": self.cooldown_users,
            "private_key_locked": not self.wallet._private_key_unlocked,
            "nonce": self.wallet.nonce
        }

# ============ 网络协议魔法字 ============
MAGIC = b'XODE'
HEADER_SIZE = 8
MAX_PAYLOAD_SIZE = 10_000_000

def encode_message(payload_dict):
    """编码消息: Magic + Length + JSON Payload"""
    payload = json.dumps(payload_dict, ensure_ascii=False).encode('utf-8')
    length = len(payload)
    if length > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Payload too large: {length} bytes")
    return MAGIC + struct.pack('>I', length) + payload

def decode_messages(buffer):
    """从缓冲区解码所有完整消息，返回 (messages, remaining_buffer)"""
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


client = XodeClient()

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
.cooldown-pulse{animation:cooldownPulse 2s infinite}
@keyframes cooldownPulse{0%,100%{opacity:1}50%{opacity:.6}}
#cooldownCard .card-value{font-size:32px}
#eligibleCard .card-value{font-size:24px}
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
.sync-progress-container{width:100%;height:8px;background:#0a0e17;border-radius:4px;overflow:hidden;margin-top:8px;border:1px solid #1e2530}
.sync-progress-fill{height:100%;background:linear-gradient(90deg,#00d4ff,#7b2cbf);border-radius:4px;transition:width .3s ease}
.sync-progress-text{font-size:11px;color:#6b7a8f;margin-top:4px;text-align:center}
.tx-history-item{background:#0a0e17;border:1px solid #1e2530;border-radius:12px;padding:16px;margin-bottom:10px;transition:border-color .2s}
.tx-history-item:hover{border-color:#2a3441}
.tx-history-item.sent{border-left:3px solid #ef4444}
.tx-history-item.received{border-left:3px solid #22c55e}
.tx-history-item.pending{border-left:3px solid #f97316}
.tx-status-badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600}
.tx-status-confirmed{background:rgba(34,197,94,.15);color:#22c55e}
.tx-status-pending{background:rgba(249,115,22,.15);color:#f97316}
.wallet-info{background:rgba(0,212,255,.05);border:1px solid rgba(0,212,255,.2);border-radius:12px;padding:16px;margin-top:12px}
.wallet-info-row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05);font-size:13px}
.wallet-info-row:last-child{border-bottom:none}
.wallet-label{color:#6b7a8f}.wallet-value{color:#00d4ff;font-family:monospace}
.danger-zone{border:1px solid rgba(239,68,68,.3);border-radius:12px;padding:16px;margin-top:16px;background:rgba(239,68,68,.05)}
.danger-zone .section-title{color:#ef4444}
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
<div class="card" id="cooldownCard" style="display:none">
<div class="card-title">⏳ Block Cooldown</div>
<div class="card-value accent-orange" id="cooldownDisplay">15</div>
<div class="card-sub" id="cooldownSub">blocks until eligible</div>
</div>
<div class="card" id="eligibleCard" style="display:none">
<div class="card-title">✅ Eligible</div>
<div class="card-value accent-green" id="eligibleDisplay">YES</div>
<div class="card-sub">You can earn rewards now</div>
</div>
<div class="card" id="cooldownUsersCard">
<div class="card-title">⏳ Cooling Down</div>
<div class="card-value accent-orange" id="cooldownUsersDisplay">0</div>
<div class="card-sub">users waiting for rewards</div>
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
<div class="card">
<div class="card-title">🔥 Burned</div>
<div class="card-value accent-red" id="burnedDisplay">0</div>
<div class="card-sub">XODE destroyed</div>
</div>
<div class="card">
<div class="card-title">🏆 Rank</div>
<div class="card-value accent-purple" id="rankDisplay">--</div>
<div class="card-sub" id="rankSub">Network position</div>
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
<button class="tab active" onclick="switchTab('connect', this)">🔗 Connect</button>
<button class="tab" onclick="switchTab('transfer', this)">💸 Transfer</button>
<button class="tab" onclick="switchTab('blocks', this)">📦 Blocks</button>
<button class="tab" onclick="switchTab('history', this)">📜 History</button>
<button class="tab" onclick="switchTab('wallet', this)">👛 Wallet</button>
<button class="tab" onclick="switchTab('rankings', this)">🏆 Rankings</button>
<button class="tab" onclick="switchTab('logs', this)">📝 Logs</button>
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
<button class="btn btn-secondary" onclick="syncChain()">🔄 Sync from Server</button>
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

<div id="tab-history" class="tab-content">
<div class="section">
<div class="section-title">📜 Transaction History</div>
<div class="btn-group" style="margin-bottom:16px">
<button class="btn btn-secondary" onclick="getHistory()">🔄 Refresh</button>
<button class="btn btn-secondary" onclick="clearHistory()">🗑️ Clear</button>
</div>
<div id="historyContainer" style="max-height:500px;overflow-y:auto">
<div class="empty-state">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="18" rx="2"/><path d="M2 7h20M7 11v6M12 11v6M17 11v6"/></svg>
<div>No transactions yet</div>
<div style="font-size:13px;margin-top:8px">Connect to a node and sync to view history</div>
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
<div id="unlockPrivkeyForm" style="margin-top:12px;padding:12px;background:rgba(249,115,22,0.05);border:1px solid rgba(249,115,22,0.2);border-radius:10px;display:none">
<div style="font-size:12px;color:#6b7a8f;margin-bottom:8px">🔐 Enter password to unlock private key</div>
<div style="display:flex;gap:10px;align-items:center">
<input type="password" id="unlockPassword" placeholder="Wallet password" style="flex:1;padding:10px 14px;background:#0a0e17;border:1px solid #1e2530;border-radius:8px;color:#e0e6ed;font-size:14px;outline:none" onkeydown="if(event.key==='Enter')doUnlockPrivateKey()">
<button class="btn btn-primary" onclick="doUnlockPrivateKey()" style="padding:10px 18px;font-size:13px">Unlock</button>
<button class="btn btn-secondary" onclick="cancelUnlockPrivateKey()" style="padding:10px 18px;font-size:13px">Cancel</button>
</div>
<div id="unlockPrivkeyResult" style="margin-top:8px;font-size:12px"></div>
</div>
<div class="wallet-info-row"><span class="wallet-label">Balance</span><span class="wallet-value" id="walletBalanceDetail">0 XODE</span></div>
<div class="wallet-info-row"><span class="wallet-label">Created</span><span class="wallet-value" id="walletCreated">---</span></div>
</div>
<div class="btn-group" style="margin-top:16px">
<button class="btn btn-secondary" id="unlockPrivkeyBtn" onclick="toggleUnlockPrivateKey()">🔓 Unlock Private Key</button>
<button class="btn btn-secondary" onclick="lockPrivateKey()">🔒 Lock Private Key</button>
<button class="btn btn-secondary" onclick="exportWallet()">📤 Export wallet.dat</button>
</div>
</div>

<div class="section" style="border:1px solid rgba(0,212,255,0.3);background:rgba(0,212,255,0.05)">
<div class="section-title" style="color:#00d4ff">🔐 Change Wallet Password</div>
<p style="font-size:13px;color:#6b7a8f;margin-bottom:12px">Change the encryption password for your wallet.dat file. You must know the current password to proceed. New password will be saved and automatically used after restart.</p>
<div class="form-group"><label>Current Password</label><input type="password" id="oldPassword" placeholder="Enter current password"></div>
<div class="form-group"><label>New Password (min 8 chars)</label><input type="password" id="newPassword" placeholder="Enter new password"></div>
<div class="form-group"><label>Confirm New Password</label><input type="password" id="confirmPassword" placeholder="Confirm new password"></div>
<div class="btn-group">
<button class="btn btn-primary" onclick="changePassword()">🔐 Change Password</button>
</div>
<div id="passwordChangeResult" style="margin-top:12px"></div>
</div>

<div class="danger-zone">
<div class="section-title">⚠️ Danger Zone</div>
<p style="font-size:13px;color:#6b7a8f;margin-bottom:12px">Creating a new wallet will overwrite your current wallet.dat. Make sure you have backed up your private key!</p>
<div class="btn-group">
<button class="btn btn-danger" onclick="createNewWallet()">🆕 Create New Wallet</button>
</div>
</div>
</div>

<div id="tab-rankings" class="tab-content">
<div class="section">
<div class="section-title">🏆 Network Balance Rankings</div>
<div class="btn-group" style="margin-bottom:16px">
<button class="btn btn-secondary" onclick="getRankings()">🔄 Refresh</button>
</div>
<div id="rankingsContainer" style="max-height:600px;overflow-y:auto">
<div class="empty-state">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M6 9l6 6 6-6"/></svg>
<div>No ranking data yet</div>
<div style="font-size:13px;margin-top:8px">Sync chain to calculate rankings from local data</div>
</div>
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
function switchTab(tab,el){currentTab=tab;document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));if(el){el.classList.add('active')}else{var tabs=document.querySelectorAll('.tab');for(var i=0;i<tabs.length;i++){if(tabs[i].getAttribute('onclick')&&tabs[i].getAttribute('onclick').indexOf(tab)!=-1){tabs[i].classList.add('active');break}}}document.getElementById('tab-'+tab).classList.add('active');if(tab==='rankings'){if(document.getElementById('statusText').textContent.includes('Connected')){getRankings()}}}
function showToast(msg,type='info'){const c=document.getElementById('toastContainer'),t=document.createElement('div');t.className='toast toast-'+type;t.textContent=msg;c.appendChild(t);setTimeout(()=>t.remove(),4000)}
async function connect(){const host=document.getElementById('nodeHost').value,port=parseInt(document.getElementById('nodePort').value),btn=document.getElementById('connectBtn');btn.disabled=true;btn.textContent='Connecting...';try{const res=await fetch('/api/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host,port})});const data=await res.json();if(data.success){showToast(data.message,'success');startPolling()}else{showToast(data.message,'error');btn.disabled=false;btn.textContent='Connect'}}catch(e){showToast('Failed: '+e.message,'error');btn.disabled=false;btn.textContent='Connect'}}
async function disconnect(){await fetch('/api/disconnect',{method:'POST'});showToast('Disconnected','info');stopPolling();updateUI({connected:false})}
async function reconnect(){await fetch('/api/disconnect',{method:'POST'});showToast('Reconnecting...','info');setTimeout(()=>connect(),500)}
async function syncChain(){
    const res=await fetch('/api/sync',{method:'POST'});
    const data=await res.json();
    showToast(data.message,data.success?'success':'error');
    // syncChain triggers incremental block sync via get_blocks (paginated)
    // instead of downloading the entire chain at once
}
async function getStats(){const res=await fetch('/api/stats',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error')}
// getChain removed: use syncChain() for incremental sync instead of full download
async function showLocalChain(){const res=await fetch('/api/local_chain');const data=await res.json();renderBlocks(data.chain);showToast('Loaded '+data.chain.length+' blocks','success')}
async function sendTransfer(){const to=document.getElementById('transferTo').value,amount=document.getElementById('transferAmount').value;const res=await fetch('/api/transfer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({to,amount})});const data=await res.json();showToast(data.message,data.success?'success':'error');if(data.success){document.getElementById('transferTo').value='';document.getElementById('transferAmount').value=''}}
async function getHistory(){const res=await fetch('/api/history',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error')}
async function clearHistory(){await fetch('/api/clear_history',{method:'POST'});document.getElementById('historyContainer').innerHTML='<div class="empty-state" style="padding:40px 20px"><div>History cleared</div></div>';showToast('History cleared','info')}
async function clearLogs(){await fetch('/api/clear_logs',{method:'POST'});document.getElementById('logContainer').innerHTML='<div class="empty-state" style="padding:20px"><div>Logs cleared</div></div>'}
function toggleUnlockPrivateKey(){const form=document.getElementById('unlockPrivkeyForm');if(form.style.display==='none'||form.style.display===''){form.style.display='block';document.getElementById('unlockPassword').focus()}else{form.style.display='none'}}
function cancelUnlockPrivateKey(){document.getElementById('unlockPrivkeyForm').style.display='none';document.getElementById('unlockPassword').value='';document.getElementById('unlockPrivkeyResult').textContent=''}
async function doUnlockPrivateKey(){const password=document.getElementById('unlockPassword').value;if(!password){document.getElementById('unlockPrivkeyResult').innerHTML='<span style="color:#ef4444">❌ Please enter password</span>';return}document.getElementById('unlockPrivkeyResult').innerHTML='<span style="color:#00d4ff">⏳ Unlocking...</span>';try{const res=await fetch('/api/unlock_wallet',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});const data=await res.json();if(data.success&&data.private_key){document.getElementById('walletPrivkeyDetail').textContent=data.private_key;document.getElementById('walletPrivkeyDetail').style.color='#f97316';privateKeyVisible=true;document.getElementById('unlockPrivkeyForm').style.display='none';document.getElementById('unlockPassword').value='';document.getElementById('unlockPrivkeyResult').textContent='';showToast('Private key unlocked','success')}else{document.getElementById('unlockPrivkeyResult').innerHTML='<span style="color:#ef4444">❌ '+(data.message||'Failed to unlock')+'</span>';showToast(data.message||'Failed to unlock','error')}}catch(e){document.getElementById('unlockPrivkeyResult').innerHTML='<span style="color:#ef4444">❌ Error: '+e.message+'</span>';showToast('Error: '+e.message,'error')}}
function lockPrivateKey(){document.getElementById('walletPrivkeyDetail').textContent='*** HIDDEN ***';document.getElementById('walletPrivkeyDetail').style.color='#ef4444';privateKeyVisible=false;showToast('Private key locked','info')}
async function exportWallet(){try{const res=await fetch('/api/export_wallet_dat');if(!res.ok){showToast('Export failed','error');return}const blob=await res.blob();const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='wallet.dat';a.click();URL.revokeObjectURL(url);showToast('wallet.dat exported!','success')}catch(e){showToast('Export error: '+e.message,'error')}}
async function changePassword(){const oldPwd=document.getElementById('oldPassword').value,newPwd=document.getElementById('newPassword').value,confirmPwd=document.getElementById('confirmPassword').value,resultEl=document.getElementById('passwordChangeResult');if(!oldPwd){resultEl.innerHTML='<div style="color:#ef4444;font-size:13px">❌ Please enter current password</div>';return}if(!newPwd||newPwd.length<8){resultEl.innerHTML='<div style="color:#ef4444;font-size:13px">❌ New password must be at least 8 characters</div>';return}if(newPwd!==confirmPwd){resultEl.innerHTML='<div style="color:#ef4444;font-size:13px">❌ New passwords do not match</div>';return}resultEl.innerHTML='<div style="color:#00d4ff;font-size:13px">⏳ Changing password...</div>';try{const res=await fetch('/api/change_password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old_password:oldPwd,new_password:newPwd})});const data=await res.json();if(data.success){resultEl.innerHTML='<div style="color:#22c55e;font-size:13px">✅ '+data.message+'</div>';showToast('Password changed! Will auto-apply after restart.','success');document.getElementById('oldPassword').value='';document.getElementById('newPassword').value='';document.getElementById('confirmPassword').value=''}else{resultEl.innerHTML='<div style="color:#ef4444;font-size:13px">❌ '+data.message+'</div>';showToast(data.message,'error')}}catch(e){resultEl.innerHTML='<div style="color:#ef4444;font-size:13px">❌ Error: '+e.message+'</div>';showToast('Error: '+e.message,'error')}}
async function createNewWallet(){if(!confirm('WARNING: This will overwrite your current wallet!\\nMake sure you have backed up your private key.\\n\\nContinue?'))return;const res=await fetch('/api/new_wallet',{method:'POST'});const data=await res.json();showToast(data.message,data.success?'success':'error');if(data.success){setTimeout(()=>location.reload(),1000)}}
async function getRankings(){const c=document.getElementById('rankingsContainer');if(!document.getElementById('statusText').textContent.includes('Connected')){c.innerHTML='<div class="empty-state" style="padding:40px 20px"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:64px;height:64px;margin-bottom:16px;opacity:.3"><path d="M6 9l6 6 6-6"/></svg><div>Not connected to server</div><div style="font-size:13px;margin-top:8px">Connect to a node first to view rankings</div></div>';return}c.innerHTML='<div style="text-align:center;padding:40px;color:#6b7a8f"><div class="sync-spinner" style="margin:0 auto 16px"></div><div>Loading rankings from server...</div></div>';try{const res=await fetch('/api/rankings',{method:'GET'});const data=await res.json();if(data.success&&data.rankings&&data.rankings.length>0){renderRankings(data.rankings,data.my_address);showToast('Loaded '+data.rankings.length+' addresses from server','success')}else if(data.success){renderRankings([],data.my_address);showToast('No ranking data available yet','info')}else{showToast('Failed to load rankings: '+(data.message||'Unknown error'),'error')}}catch(e){showToast('Error loading rankings: '+e.message,'error');console.error(e)}}
function renderRankings(rankings,myAddress){const c=document.getElementById('rankingsContainer');if(!rankings||rankings.length===0){c.innerHTML='<div class="empty-state" style="padding:40px 20px"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:64px;height:64px;margin-bottom:16px;opacity:.3"><path d="M6 9l6 6 6-6"/></svg><div>No ranking data yet</div><div style="font-size:13px;margin-top:8px">Sync chain to calculate rankings from local data</div></div>';return}const scrollTop=c.scrollTop;let html='';html+='<div style="display:grid;grid-template-columns:60px 1fr 120px;gap:12px;padding:12px 16px;background:rgba(0,212,255,0.05);border-radius:12px;margin-bottom:12px;font-size:12px;color:#6b7a8f;font-weight:600"><div>Rank</div><div>Address</div><div style="text-align:right">Balance</div></div>';rankings.forEach(r=>{const isMe=r.is_me?' style="background:rgba(0,212,255,0.08);border:1px solid rgba(0,212,255,0.3)"':'';const rankColor=r.rank===1?'#fbbf24':r.rank===2?'#c0c0c0':r.rank===3?'#cd7f32':'#6b7a8f';const medal=r.rank===1?'👑':r.rank===2?'🥈':r.rank===3?'🥉':'#';html+='<div style="display:grid;grid-template-columns:60px 1fr 120px;gap:12px;padding:14px 16px;background:#0a0e17;border:1px solid #1e2530;border-radius:12px;margin-bottom:8px;align-items:center"'+isMe+'><div style="font-size:18px;font-weight:700;color:'+rankColor+'">'+medal+r.rank+'</div><div style="font-family:monospace;font-size:13px;word-break:break-all;color:'+(r.is_me?'#00d4ff':'#e0e6ed')+'">'+r.address+(r.is_me?' <span style="color:#00d4ff;font-size:11px">(YOU)</span>':'')+'</div><div style="text-align:right;font-size:16px;font-weight:600;color:#22c55e">'+r.balance.toLocaleString()+' XODE</div></div>'});html+='</div>';c.innerHTML=html;c.scrollTop=scrollTop;}
function renderHistory(txs){const c=document.getElementById('historyContainer');if(!txs||txs.length===0){c.innerHTML='<div class="empty-state" style="padding:40px 20px"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:64px;height:64px;margin-bottom:16px;opacity:.3"><rect x="2" y="3" width="20" height="18" rx="2"/><path d="M2 7h20M7 11v6M12 11v6M17 11v6"/></svg><div>No transactions yet</div><div style="font-size:13px;margin-top:8px">Your transfers and rewards will appear here</div></div>';return}const scrollTop=c.scrollTop;let html='';[...txs].reverse().forEach(tx=>{const myAddr=document.getElementById('addressDisplay').textContent;const isSent=tx.from===myAddr;const typeClass=isSent?'sent':tx.to===myAddr?'received':'pending';const status=tx.status||'confirmed';const statusClass=status==='confirmed'?'tx-status-confirmed':'tx-status-pending';const date=tx.timestamp?new Date(tx.timestamp*1000).toLocaleString():'Unknown';html+='<div class="tx-history-item '+typeClass+'"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><span style="font-size:14px;font-weight:600;color:#e0e6ed">'+(isSent?'📤 Sent':'📥 Received')+'</span><span class="tx-status-badge '+statusClass+'">'+status+'</span></div><div style="display:flex;justify-content:space-between;margin-bottom:4px;font-size:12px"><span style="color:#6b7a8f">From:</span><span style="color:#e0e6ed;font-family:monospace;font-size:11px">'+(tx.from||'N/A')+'</span></div><div style="display:flex;justify-content:space-between;margin-bottom:4px;font-size:12px"><span style="color:#6b7a8f">To:</span><span style="color:#e0e6ed;font-family:monospace;font-size:11px">'+(tx.to||'N/A')+'</span></div><div style="display:flex;justify-content:space-between;margin-bottom:4px;font-size:12px"><span style="color:#6b7a8f">Amount:</span><span style="color:#00d4ff;font-weight:600">'+(tx.amount||0)+' XODE</span></div>'+(tx.fee?'<div style="display:flex;justify-content:space-between;font-size:12px"><span style="color:#6b7a8f">Fee:</span><span style="color:#f97316">'+tx.fee+' XODE</span></div>':'')+'<div style="margin-top:8px;font-size:11px;color:#4a5568">'+date+(tx.tx_hash?' | Hash: '+tx.tx_hash:'')+(tx.block_index?' | Block #'+tx.block_index:'')+'</div></div>'});c.innerHTML=html;const newScrollContainer=c.querySelector('div[style*="overflow-y:auto"]')||c;newScrollContainer.scrollTop=scrollTop;}
function renderBlocks(chain){const c=document.getElementById('blocksContainer');const scrollTop=c.scrollTop;if(!chain||chain.length===0){c.innerHTML='<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="18" rx="2"/><path d="M2 7h20M7 11v6M12 11v6M17 11v6"/></svg><div>No blocks loaded yet</div></div>';return}let html='<div class="block-list">';[...chain].reverse().forEach(block=>{const reward=block.reward||{},supply=block.supply||{},txs=block.transactions||[],date=new Date(block.timestamp*1000).toLocaleString();const perUser=reward.per_user||reward.reward_per_user||0;let rewardText='';let rewardAddrsHtml='';if(reward.online_count>0){rewardText=perUser+' XODE x '+reward.online_count+' users';if(reward.recipients&&reward.recipients.length>0){rewardAddrsHtml='<div style="margin-top:10px;padding:10px;background:rgba(34,197,94,0.06);border-radius:10px;border:1px solid rgba(34,197,94,0.2);"><div style="font-size:11px;color:#22c55e;margin-bottom:6px;font-weight:600">🎯 Reward Recipients ('+reward.recipients.length+'):</div><div style="font-size:11px;color:#8b9bb4;font-family:monospace;line-height:1.9">'+reward.recipients.map((r,idx)=>{const addr=r.address||r;const amt=r.amount||perUser;return '  '+String(idx+1).padStart(2,'0')+'. <span style="color:#a7f3d0">'+addr+'</span> <span style="color:#22c55e">+'+amt+' XODE</span>';}).join('<br>')+'</div></div>'}}else if(reward.burned>0){rewardText='<span style="color:#ef4444">'+reward.burned+' XODE burned</span>'}else{rewardText=(reward.total||0)+' XODE'}let txDetailsHtml='';if(txs.length>0){txDetailsHtml='<div style="margin-top:10px;padding:10px;background:rgba(0,212,255,0.06);border-radius:10px;border:1px solid rgba(0,212,255,0.2);"><div style="font-size:11px;color:#00d4ff;margin-bottom:6px;font-weight:600">💸 Transactions ('+txs.length+'):</div>'+txs.map((tx,idx)=>'<div style="font-size:12px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.04);'+(idx===txs.length-1?'border-bottom:none;':'')+'">'+'<div style="display:flex;justify-content:space-between;margin-bottom:3px"><span style="color:#6b7a8f;font-size:11px">From:</span><span style="color:#e0e6ed;font-family:monospace;font-size:11px">'+tx.from+'</span></div>'+'<div style="display:flex;justify-content:space-between;margin-bottom:3px"><span style="color:#6b7a8f;font-size:11px">To:</span><span style="color:#e0e6ed;font-family:monospace;font-size:11px">'+tx.to+'</span></div>'+'<div style="display:flex;justify-content:space-between;margin-bottom:3px"><span style="color:#6b7a8f;font-size:11px">Amount:</span><span style="color:#00d4ff;font-weight:600">'+tx.amount+' XODE</span></div>'+'<div style="display:flex;justify-content:space-between;margin-bottom:3px"><span style="color:#6b7a8f;font-size:11px">Fee:</span><span style="color:#f97316">'+tx.fee+' XODE</span></div>'+'<div style="display:flex;justify-content:space-between"><span style="color:#6b7a8f;font-size:11px">Signature:</span><span style="color:#4a5568;font-family:monospace;font-size:10px">'+(tx.signature?tx.signature.substring(0,28)+'...':'N/A')+'</span></div>'+'</div>').join('')+'</div>'}html+='<div class="block-item"><div class="block-header"><span class="block-index">#'+block.index+'</span><span class="block-hash">'+block.hash+'</span></div><div class="block-details"><span>⏰ '+date+'</span><span>🔗 '+(block.previous_hash?block.previous_hash.substring(0,20)+'...':'Genesis')+'</span><span>💰 '+rewardText+'</span><span>👥 Online: '+(reward.online_count||0)+'</span>'+(supply.issued?'<span>📊 '+supply.issued.toLocaleString()+' / '+(supply.total?supply.total.toLocaleString():'?')+' XODE</span>':'')+'</div>'+rewardAddrsHtml+txDetailsHtml+'</div>'});html+='</div>';c.innerHTML=html;c.scrollTop=scrollTop;}
function updateUI(state){const statusEl=document.getElementById('connectionStatus'),statusText=document.getElementById('statusText'),connectBtn=document.getElementById('connectBtn'),disconnectBtn=document.getElementById('disconnectBtn'),sendBtn=document.getElementById('sendBtn');if(state.connected){statusEl.className='status-badge status-connected';statusText.textContent='Connected';connectBtn.disabled=true;connectBtn.textContent='Connected';disconnectBtn.disabled=false;sendBtn.disabled=false}else{statusEl.className='status-badge status-disconnected';statusText.textContent='Disconnected';connectBtn.disabled=false;connectBtn.textContent='Connect';disconnectBtn.disabled=true;sendBtn.disabled=true}if(state.balance!==undefined)document.getElementById('balanceDisplay').textContent=state.balance.toLocaleString();if(state.block_height!==undefined)document.getElementById('blockHeightDisplay').textContent=state.block_height.toLocaleString();if(state.online_users!==undefined)document.getElementById('onlineUsers').textContent=state.online_users;if(state.total_issued!==undefined){document.getElementById('issuedDisplay').textContent=state.total_issued.toLocaleString();const pct=state.total_supply?(state.total_issued/state.total_supply*100).toFixed(4):0;document.getElementById('supplyProgress').style.width=pct+'%';document.getElementById('supplyPercent').textContent=pct+'%'}if(state.burned_total!==undefined)document.getElementById('burnedDisplay').textContent=state.burned_total.toLocaleString();if(state.balance_rank!==undefined){document.getElementById('rankDisplay').textContent=state.balance_rank>0?'#'+state.balance_rank:'--';document.getElementById('rankSub').textContent=state.balance_rank>0?'Top '+state.balance_rank+' / '+state.total_addresses+' addresses':'Network position'}if(state.cooldown_users!==undefined){document.getElementById('cooldownUsersDisplay').textContent=state.cooldown_users.toLocaleString()}if(state.address){document.getElementById('addressDisplay').textContent=state.address;document.getElementById('walletAddrDetail').textContent=state.address}if(state.public_key){document.getElementById('pubkeyDisplay').textContent=state.public_key.substring(0,16)+'...';document.getElementById('walletPubkeyDetail').textContent=state.public_key}if(state.block_time)document.getElementById('blockTime').textContent=state.block_time;if(state.block_reward)document.getElementById('blockReward').textContent=state.block_reward;if(state.transfer_fee)document.getElementById('transferFee').textContent=state.transfer_fee;if(state.pending_tx!==undefined)document.getElementById('pendingTx').textContent=state.pending_tx;if(state.wallet_file)document.getElementById('walletFile').textContent=state.wallet_file;if(state.chain_file)document.getElementById('chainFile').textContent=state.chain_file;if(state.wallet_created)document.getElementById('walletCreated').textContent=new Date(state.wallet_created*1000).toLocaleString();if(state.wallet_balance!==undefined)document.getElementById('walletBalanceDetail').textContent=state.wallet_balance.toLocaleString()+' XODE';const syncEl=document.getElementById('syncStatus');if(state.syncing){syncEl.innerHTML='<span class="sync-indicator"><span class="sync-spinner"></span>Syncing...</span>'}else if(state.chain_length&&state.block_height>state.local_height){syncEl.innerHTML='<span style="color:#f97316">Local: #'+state.local_height+' / #'+state.block_height+'</span>'}else{syncEl.textContent=''}if(state.logs&&state.logs.length>0){const logContainer=document.getElementById('logContainer');let html='';state.logs.forEach(log=>{const levelClass=log.level==='error'?'log-error':log.level==='success'?'log-success':log.level==='warning'?'log-warning':'log-info';html+='<div class="log-entry"><span class="log-time">'+log.time+'</span><span class="'+levelClass+'">'+log.msg+'</span></div>'});logContainer.innerHTML=html;logContainer.scrollTop=logContainer.scrollHeight}if(state.transfer_result){const resultEl=document.getElementById('transferResult');if(state.transfer_result.success){resultEl.innerHTML='<div style="background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);padding:16px;border-radius:12px;color:#22c55e;"><strong>✅ Transfer Success</strong><br>Sent '+state.transfer_result.amount+' XODE to '+state.transfer_result.to+'<br>Fee: '+(state.transfer_result.fee||0)+' XODE | Balance: '+(state.transfer_result.balance||0)+' XODE</div>'}else{resultEl.innerHTML='<div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);padding:16px;border-radius:12px;color:#ef4444;"><strong>❌ Transfer Failed</strong><br>'+(state.transfer_result.error||'Unknown error')+'</div>'}}if(state.balance_update){showToast('Block #'+state.balance_update.block_index+' reward: +'+state.balance_update.reward+' XODE','success');if(state.is_eligible){const cdCard=document.getElementById('cooldownCard'),elCard=document.getElementById('eligibleCard');if(cdCard&&elCard){cdCard.style.display='none';elCard.style.display='block';}}}if(state.chain){if(!window._lastChainLen||window._lastChainLen!==state.chain.length){window._lastChainLen=state.chain.length;renderBlocks(state.chain)}}if(state.transaction_history){renderHistory(state.transaction_history)}if(state.server_rankings&&state.server_rankings.length>0&&currentTab==='rankings'){renderRankings(state.server_rankings,state.address)}if(state.first_connect_block!==undefined){const cdCard=document.getElementById("cooldownCard"),elCard=document.getElementById("eligibleCard");if(state.is_eligible){cdCard.style.display="none";elCard.style.display="block";}else{cdCard.style.display="block";elCard.style.display="none";const rem=state.cooldown_remaining||0;document.getElementById("cooldownDisplay").textContent=rem;document.getElementById("cooldownSub").textContent=rem===1?"block until eligible":"blocks until eligible";}}}
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
            # 从本地链中提取当前地址的交易历史
            client._update_tx_history_from_blocks(client.chain_store.chain)
            self.send_json({"chain": client.chain_store.chain})
        elif self.path == '/api/wallet_info':
            # 默认不返回私钥，仅返回基本信息
            info = {
                "address": client.wallet.address,
                "public_key": client.wallet.public_key,
                "balance": client.wallet.balance,
                "created_at": client.wallet.created_at,
                "private_key_locked": not client.wallet._private_key_unlocked
            }
            # 如果私钥已解锁，才返回
            if client.wallet._private_key_unlocked:
                info["private_key"] = client.wallet.private_key
            self.send_json(info)
        elif self.path == '/api/export_wallet_dat':
            # 导出真正的 wallet.dat 文件
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
        elif self.path == '/api/rankings':
            # 如果未连接且链为空，返回空数据
            if not client.connected and not client.chain_store.chain:
                self.send_json({"success": True, "rankings": [], "my_address": client.wallet.address})
                return
            if client.connected:
                # 请求服务端排行榜
                client.request_rankings()
                # 等待响应（通过轮询）
                import time
                for _ in range(20):  # 最多等2秒
                    if client.server_rankings:
                        self.send_json({"success": True, "rankings": client.server_rankings, "my_address": client.wallet.address})
                        return
                    time.sleep(0.1)
            # 未连接或服务端无响应，使用本地计算
            rankings = client.get_all_rankings()
            self.send_json({"success": True, "rankings": rankings, "my_address": client.wallet.address})
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
        # /api/chain removed: use /api/sync for incremental block sync instead
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
        elif self.path == '/api/history':
            if not client.connected:
                self.send_json({"success": False, "message": "Not connected"})
                return
            client.request_history()
            self.send_json({"success": True, "message": "History requested"})
        elif self.path == '/api/clear_history':
            client.transaction_history = []
            self.send_json({"success": True})
        elif self.path == '/api/unlock_wallet':
            # 解锁私钥API
            password = data.get('password', '')
            success = client.wallet.unlock_private_key(password)
            if success:
                self.send_json({"success": True, "message": "Wallet unlocked", "private_key": client.wallet.private_key})
            else:
                self.send_json({"success": False, "message": "Invalid password"})
        elif self.path == '/api/change_password':
            old_password = data.get('old_password', '')
            new_password = data.get('new_password', '')
            if not new_password or len(new_password) < 8:
                self.send_json({"success": False, "message": "New password must be at least 8 characters"})
                return
            success, message = client.wallet.change_password(old_password, new_password)
            self.send_json({"success": success, "message": message})
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
