import socket
import threading
import json
import time
import sys
import os

# Force flush output on Windows
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', line_buffering=True)

# Data file path
DATA_FILE = os.path.join(os.path.expanduser("~"), "xode_client_data.json")

class XodeClient:
    def __init__(self, server_host='127.0.0.1', server_port=5555):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.address = ""
        self.balance = 0
        self.running = False
        self.last_pong_time = 0
        self.heartbeat_interval = 25
        self.timeout = 90
        self.block_height = 0
        self.total_supply = 0
        self.total_issued = 0
        self.block_time = 120
        self.block_reward = 1000
        self.transfer_fee = 1
        self.chain = []
        self.syncing = False

        self.load_data()

    def save_data(self):
        data = {
            "address": self.address,
            "balance": self.balance,
            "chain": self.chain,
            "block_height": self.block_height,
            "total_issued": self.total_issued,
            "saved_at": time.time()
        }
        try:
            with open(DATA_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except PermissionError:
            try:
                alt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xode_client_data.json")
                with open(alt_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                print("[Persistence] Data saved to: " + alt_path, flush=True)
            except Exception as e:
                print("[Warning] Cannot save data: " + str(e), flush=True)
        except Exception as e:
            print("[Warning] Failed to save data: " + str(e), flush=True)

    def load_data(self):
        paths = [
            DATA_FILE,
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "xode_client_data.json"),
            "xode_client_data.json"
        ]

        for path in paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        data = json.load(f)

                    self.address = data.get("address", "")
                    self.balance = data.get("balance", 0)
                    self.chain = data.get("chain", [])
                    self.block_height = data.get("block_height", 0)
                    self.total_issued = data.get("total_issued", 0)

                    print("[Persistence] Local data loaded: " + path, flush=True)
                    if self.address:
                        print("  Address: " + self.address, flush=True)
                    if self.balance:
                        print("  Balance: " + str(self.balance) + " XODE", flush=True)
                    if self.chain:
                        print("  Blocks: " + str(len(self.chain)), flush=True)
                    return
                except Exception as e:
                    print("[Warning] Failed to load data [" + path + "]: " + str(e), flush=True)

        print("[Persistence] Data file not found, will create new", flush=True)

    def request_sync(self):
        if not self.socket or not self.running:
            return

        has_genesis = False
        if self.chain:
            for b in self.chain:
                if b.get("index") == 0:
                    has_genesis = True
                    break

        if not has_genesis:
            print("[Sync] Local data incomplete, starting full sync...", flush=True)
            self.syncing = True
            start = 0
            while start <= self.block_height and self.running:
                end = min(start + 50, self.block_height + 1)
                self.send_command("get_blocks", start=start, end=end)
                start = end
                time.sleep(0.3)

            wait_count = 0
            while len(self.chain) < self.block_height + 1 and wait_count < 30:
                time.sleep(0.2)
                wait_count += 1

            self.syncing = False
            new_height = len(self.chain) - 1
            print("[Sync] Full sync complete, current block: #" + str(new_height), flush=True)
            return

        local_height = len(self.chain) - 1 if self.chain else -1
        if local_height < self.block_height:
            self.syncing = True
            missing = self.block_height - local_height
            print("[Sync] Local is behind by " + str(missing) + " blocks, starting sync...", flush=True)

            start = local_height + 1
            while start <= self.block_height and self.running:
                end = min(start + 50, self.block_height + 1)
                self.send_command("get_blocks", start=start, end=end)
                start = end
                time.sleep(0.3)

            wait_count = 0
            while len(self.chain) - 1 < self.block_height and wait_count < 20:
                time.sleep(0.2)
                wait_count += 1

            self.syncing = False
            new_height = len(self.chain) - 1
            if new_height >= self.block_height:
                print("[Sync] Sync complete, current block: #" + str(new_height), flush=True)
            else:
                print("[Sync] Partial sync, current block: #" + str(new_height) + " / #" + str(self.block_height), flush=True)

    def receive_messages(self):
        buffer = b""
        while self.running:
            try:
                data = self.socket.recv(4096)
                if not data:
                    if self.running:
                        print("[System] Disconnected from node", flush=True)
                    self.running = False
                    break

                buffer += data

                while buffer:
                    try:
                        text = buffer.decode('utf-8')
                        msg = json.loads(text)
                        buffer = b""

                        msg_type = msg.get("type", "")

                        if msg_type == "pong":
                            self.last_pong_time = time.time()
                            continue

                        elif msg_type == "connected":
                            self.address = msg["address"]
                            self.balance = msg["balance"]
                            self.block_height = msg["block_height"]
                            self.total_supply = msg["total_supply"]
                            self.total_issued = msg["issued"]
                            self.block_time = msg["block_time"]
                            self.block_reward = msg["block_reward"]
                            self.transfer_fee = msg.get("transfer_fee", 1)
                            print("", flush=True)
                            print("=" * 60, flush=True)
                            print("[Connected] Connected to XODE blockchain node", flush=True)
                            print("Address: " + self.address, flush=True)
                            print("Balance: " + str(self.balance) + " XODE", flush=True)
                            print("Block Height: #" + str(self.block_height), flush=True)
                            print("Issued: " + str(self.total_issued) + " / " + str(self.total_supply) + " XODE", flush=True)
                            print("Block Time: " + str(self.block_time) + " seconds", flush=True)
                            print("Block Reward: " + str(self.block_reward) + " XODE", flush=True)
                            print("Transfer Fee: " + str(self.transfer_fee) + " XODE", flush=True)
                            print("=" * 60, flush=True)
                            self.save_data()

                            if self.chain and len(self.chain) - 1 < self.block_height:
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
                            self.chain.append(block)
                            self.save_data()

                            burned = reward.get("burned", 0)
                            burn_addr = reward.get("burn_address", "")
                            txs = msg.get("transactions", [])

                            print("", flush=True)
                            print("=" * 60, flush=True)
                            print("[New Block] #" + str(msg["index"]), flush=True)
                            print("  Hash: " + msg["hash"], flush=True)
                            print("  Previous Hash: " + msg["previous_hash"][:30] + "...", flush=True)
                            print("  Time: " + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(msg["timestamp"])), flush=True)
                            print("  Online Users: " + str(reward["online_count"]), flush=True)
                            print("  Total Reward: " + str(reward["total"]) + " XODE", flush=True)
                            if reward["online_count"] > 0:
                                print("  Per User: " + str(reward["per_user"]) + " XODE", flush=True)
                                print("  Burned: 0 XODE", flush=True)
                            elif burned > 0:
                                print("  Distributed: 0 XODE", flush=True)
                                print("  Burned: " + str(burned) + " XODE -> " + burn_addr, flush=True)
                            if txs:
                                print("  Transactions: " + str(len(txs)) + " tx(s)", flush=True)
                                for tx in txs:
                                    print("    [Transfer] " + tx["from"][:10] + "... -> " + tx["to"][:10] + "... Amount: " + str(tx["amount"]) + " XODE Fee: " + str(tx["fee"]) + " XODE", flush=True)
                            print("  Issued: " + str(msg["supply"]["issued"]) + " / " + str(msg["supply"]["total"]), flush=True)
                            print("  Remaining: " + str(msg["supply"]["remaining"]) + " XODE", flush=True)
                            if msg["supply"].get("burned_total"):
                                print("  Total Burned: " + str(msg["supply"]["burned_total"]) + " XODE", flush=True)
                            print("=" * 60, flush=True)

                        elif msg_type == "balance_update":
                            self.balance = msg["balance"]
                            self.save_data()
                            print("", flush=True)
                            print("[Balance Update] Block #" + str(msg["block_index"]) + " reward received!", flush=True)
                            print("  Received: +" + str(msg["reward"]) + " XODE", flush=True)
                            print("  Current Balance: " + str(self.balance) + " XODE", flush=True)

                        elif msg_type == "transfer_result":
                            print("", flush=True)
                            if msg.get("success"):
                                print("[Transfer Success]", flush=True)
                                print("  From: " + msg["from"], flush=True)
                                print("  To: " + msg["to"], flush=True)
                                print("  Amount: " + str(msg["amount"]) + " XODE", flush=True)
                                print("  Fee: " + str(msg.get("fee", 0)) + " XODE", flush=True)
                                print("  Current Balance: " + str(msg.get("balance", 0)) + " XODE", flush=True)
                                print("  " + msg["message"], flush=True)
                            else:
                                print("[Transfer Failed] " + msg.get("error", "Unknown error"), flush=True)

                        elif msg_type == "balance":
                            addr = msg["address"]
                            balance = msg["balance"]
                            print("", flush=True)
                            print("[Balance Query]", flush=True)
                            print("  Address: " + addr, flush=True)
                            print("  Balance: " + str(balance) + " XODE", flush=True)

                        elif msg_type == "chain_data":
                            if msg.get("blocks"):
                                self.chain = []
                                for block in msg["blocks"]:
                                    self.chain.append({
                                        "index": block["index"],
                                        "hash": block["hash"],
                                        "previous_hash": block["previous_hash"],
                                        "timestamp": block["timestamp"],
                                        "reward": block["reward"],
                                        "transactions": block.get("transactions", [])
                                    })
                                self.save_data()

                            print("", flush=True)
                            print("[Blockchain Data] Total " + str(msg["total_blocks"]) + " blocks", flush=True)
                            print("  Latest Hash: " + msg["latest_hash"][:30] + "...", flush=True)
                            print("", flush=True)
                            print("  Recent Blocks:", flush=True)
                            for block in msg["blocks"][-5:]:
                                reward_info = block["reward"]
                                print("  Block #" + str(block["index"]) + ": " + block["hash"][:20] + "...", flush=True)
                                print("    Time: " + time.strftime('%H:%M:%S', time.localtime(block["timestamp"])), flush=True)
                                print("    Reward: " + str(reward_info["total"]) + " XODE | Online: " + str(reward_info["online_count"]) + " users", flush=True)
                                if block.get("transactions"):
                                    print("    Transactions: " + str(len(block["transactions"])) + " tx(s)", flush=True)
                            print("", flush=True)

                        elif msg_type == "blocks_range":
                            blocks = msg.get("blocks", [])
                            added = 0
                            if blocks:
                                for block in blocks:
                                    existing = [b for b in self.chain if b["index"] == block["index"]]
                                    if not existing:
                                        self.chain.append({
                                            "index": block["index"],
                                            "hash": block["hash"],
                                            "previous_hash": block["previous_hash"],
                                            "timestamp": block["timestamp"],
                                            "reward": block["reward"],
                                            "transactions": block.get("transactions", [])
                                        })
                                        added += 1

                                self.chain.sort(key=lambda x: x["index"])

                                if self.chain:
                                    new_local_height = len(self.chain) - 1
                                    if new_local_height > self.block_height:
                                        self.block_height = new_local_height

                                self.save_data()

                                if self.syncing:
                                    print("[Sync] Received " + str(added) + " blocks, current height: #" + str(len(self.chain) - 1), flush=True)
                                else:
                                    print("[Sync] Received " + str(len(blocks)) + " blocks, current height: #" + str(len(self.chain) - 1), flush=True)

                        elif msg_type == "stats":
                            print("", flush=True)
                            print("[Node Statistics]", flush=True)
                            print("  Block Height: #" + str(msg["block_height"]), flush=True)
                            print("  Issued: " + str(msg["total_issued"]) + " / " + str(msg["total_supply"]) + " XODE", flush=True)
                            print("  Remaining: " + str(msg["remaining"]) + " XODE", flush=True)
                            if msg.get("burned_total"):
                                print("  Total Burned: " + str(msg["burned_total"]) + " XODE", flush=True)
                            if msg.get("burn_address"):
                                print("  Burn Address: " + msg["burn_address"], flush=True)
                            print("  Online Users: " + str(msg["online_users"]) + " users", flush=True)
                            print("  Block Time: " + str(msg["block_time"]) + " seconds", flush=True)
                            print("  Block Reward: " + str(msg["block_reward"]) + " XODE", flush=True)
                            print("  Transfer Fee: " + str(msg.get("transfer_fee", 1)) + " XODE", flush=True)
                            if msg.get("pending_tx") is not None:
                                print("  Pending Transactions: " + str(msg["pending_tx"]) + " tx(s)", flush=True)

                        break
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        break
                    except Exception as e:
                        print("[Parse Error] " + str(e), flush=True)
                        break

            except Exception as e:
                if self.running:
                    print("[Receive Error] " + str(e), flush=True)
                break

    def heartbeat_loop(self):
        time.sleep(2)
        while self.running and self.socket:
            try:
                time.sleep(self.heartbeat_interval)
                if not self.running or not self.socket:
                    break
                elapsed = time.time() - self.last_pong_time
                if elapsed > self.timeout and self.last_pong_time > 0:
                    print("[Heartbeat] Timeout, connection lost", flush=True)
                    self.running = False
                    break
                ping_msg = json.dumps({"type": "ping"}, ensure_ascii=False).encode('utf-8')
                self.socket.send(ping_msg)
            except Exception as e:
                if self.running:
                    print("[Heartbeat Error] " + str(e), flush=True)
                    self.running = False
                break

    def send_command(self, cmd_type, **kwargs):
        try:
            msg = {"type": cmd_type}
            msg.update(kwargs)
            data = json.dumps(msg, ensure_ascii=False).encode('utf-8')
            self.socket.send(data)
        except Exception as e:
            print("[Send Failed] " + str(e), flush=True)

    def show_local_chain(self):
        if not self.chain:
            print("[Info] No block data available", flush=True)
            return

        print("", flush=True)
        print("=" * 60, flush=True)
        print("[Local Blockchain] Total " + str(len(self.chain)) + " blocks", flush=True)
        print("=" * 60, flush=True)

        for block in self.chain:
            reward = block.get("reward", {})
            supply = block.get("supply", {})
            txs = block.get("transactions", [])

            print("", flush=True)
            print("[Block] #" + str(block["index"]), flush=True)
            print("  Hash: " + block["hash"], flush=True)
            print("  Previous Hash: " + block["previous_hash"][:30] + "...", flush=True)
            print("  Time: " + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(block["timestamp"])), flush=True)
            print("  Online Users: " + str(reward.get("online_count", 0)), flush=True)
            print("  Total Reward: " + str(reward.get("total", 0)) + " XODE", flush=True)
            if reward.get("online_count", 0) > 0:
                print("  Per User: " + str(reward.get("per_user", 0)) + " XODE", flush=True)
            elif reward.get("burned", 0) > 0:
                print("  Burned: " + str(reward.get("burned", 0)) + " XODE", flush=True)
            if txs:
                print("  Transactions:", flush=True)
                for tx in txs:
                    print("    [Transfer] " + tx["from"][:10] + "... -> " + tx["to"][:10] + "... Amount: " + str(tx["amount"]) + " XODE", flush=True)
            if supply:
                print("  Issued: " + str(supply.get("issued", 0)) + " / " + str(supply.get("total", 0)) + " XODE", flush=True)
                print("  Remaining: " + str(supply.get("remaining", 0)) + " XODE", flush=True)
            print("-" * 60, flush=True)

        print("", flush=True)
        print("[Stats] Locally saved " + str(len(self.chain)) + " blocks", flush=True)
        print("=" * 60, flush=True)

    def connect(self, address=None):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.socket.connect((self.server_host, self.server_port))
            self.socket.settimeout(None)

            init_msg = {"address": address or self.address or ""}
            data = json.dumps(init_msg, ensure_ascii=False).encode('utf-8')
            self.socket.send(data)

            self.running = True
            self.last_pong_time = time.time()

            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()

            heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
            heartbeat_thread.start()

            print("", flush=True)
            print("Connecting to node " + self.server_host + ":" + str(self.server_port) + "...", flush=True)
            print("Waiting for node confirmation...", flush=True)

            while self.running:
                try:
                    user_input = input("> ").strip()

                    if not user_input:
                        continue

                    if user_input in ["quit", "exit", "q"]:
                        print("Disconnecting...", flush=True)
                        self.running = False
                        break

                    elif user_input == "balance":
                        self.send_command("get_balance", address=self.address)

                    elif user_input == "chain":
                        self.send_command("get_chain")

                    elif user_input == "local":
                        self.show_local_chain()

                    elif user_input == "sync":
                        self.request_sync()

                    elif user_input == "stats":
                        self.send_command("get_stats")

                    elif user_input.startswith("send "):
                        # Transfer command: send target_address amount
                        parts = user_input[5:].strip().split()
                        if len(parts) == 2:
                            to_addr = parts[0]
                            try:
                                amount = float(parts[1])
                                if amount <= 0:
                                    print("[Error] Transfer amount must be greater than 0", flush=True)
                                    continue
                                if not to_addr.startswith("XODE") or len(to_addr) != 20:
                                    print("[Error] Invalid target address format, must be XODE prefix 20 chars", flush=True)
                                    continue
                                total = amount + self.transfer_fee
                                if self.balance < total:
                                    print("[Error] Insufficient balance, need " + str(total) + " XODE (including fee " + str(self.transfer_fee) + " XODE)", flush=True)
                                    continue
                                self.send_command("transfer", to=to_addr, amount=amount)
                                print("[Transfer] Sending " + str(amount) + " XODE to " + to_addr + "...", flush=True)
                            except ValueError:
                                print("[Error] Amount must be a number", flush=True)
                        else:
                            print("[Error] Format: send target_address amount", flush=True)
                            print("  Example: send XODE0000000000000000 100", flush=True)

                    elif user_input == "help":
                        print("", flush=True)
                        print("Command List:", flush=True)
                        print("  balance              -> Query balance", flush=True)
                        print("  chain                -> Get blockchain data from server", flush=True)
                        print("  local                -> Display locally saved full blockchain", flush=True)
                        print("  sync                 -> Manually sync missing blocks", flush=True)
                        print("  stats                -> View node statistics", flush=True)
                        print("  send address amount  -> Transfer XODE", flush=True)
                        print("  help                 -> Show help", flush=True)
                        print("  quit                 -> Exit", flush=True)
                        print("", flush=True)
                        print("Transfer Notes:", flush=True)
                        print("  Fee: " + str(self.transfer_fee) + " XODE per transaction", flush=True)
                        print("  Example: send XODE0000000000000000 100", flush=True)

                    else:
                        print("Unknown command: " + user_input, flush=True)
                        print("Type 'help' for available commands", flush=True)

                except KeyboardInterrupt:
                    print("Disconnecting...", flush=True)
                    self.running = False
                    break
                except EOFError:
                    print("Input ended, disconnecting...", flush=True)
                    self.running = False
                    break

        except ConnectionRefusedError:
            print("[Error] Connection refused, node not running", flush=True)
        except socket.timeout:
            print("[Error] Connection timed out", flush=True)
        except Exception as e:
            print("[Error] " + str(e), flush=True)
        finally:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            print("Disconnected", flush=True)
            print("Press Enter to exit...", flush=True)
            try:
                input()
            except:
                pass

    def run(self):
        print("=" * 60, flush=True)
        print("XODE Blockchain Client", flush=True)
        print("2.1B Total | 2min Block | Equal Reward | Transfer Support", flush=True)
        print("=" * 60, flush=True)

        try:
            server = input("Node Address (default 127.0.0.1): ").strip()
            if server:
                self.server_host = server

            port = input("Port (default 5555): ").strip()
            if port:
                try:
                    self.server_port = int(port)
                except ValueError:
                    print("Invalid port, using default 5555", flush=True)
                    self.server_port = 5555

            existing = input("Existing XODE address (press Enter to use local or generate new): ").strip()

            self.connect(address=existing)
        except Exception as e:
            print("[Startup Error] " + str(e), flush=True)
            print("Press Enter to exit...", flush=True)
            try:
                input()
            except:
                pass

if __name__ == "__main__":
    try:
        client = XodeClient()
        client.run()
    except Exception as e:
        print("[Fatal Error] " + str(e), flush=True)
        try:
            input("Press Enter to exit...")
        except:
            pass
