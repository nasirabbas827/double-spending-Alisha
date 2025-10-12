import simpy
import random
import time
import csv
from blockchain import Block, Transaction, Blockchain

class Node:
    def __init__(self, env, node_id, blockchain, is_malicious=False, hash_rate=1.0, network_delay=None):
        self.env = env
        self.node_id = node_id
        self.blockchain = blockchain  # Shared blockchain
        self.is_malicious = is_malicious
        self.hash_rate = hash_rate
        self.network_delay = network_delay
        self.transaction_queue = []
        self.processed_transaction_ids = set()  # Track processed transaction IDs
        self.attack_success_count = 0
        self.attack_attempts = 0
        self.private_chain = Blockchain(difficulty=blockchain.difficulty) if is_malicious else None
        self.action = env.process(self.run())

    def run(self):
        while True:
            yield self.env.timeout(self.network_delay)
            if self.transaction_queue:
                tx = self.transaction_queue[0]  # Peek at the first transaction
                if tx.id not in self.processed_transaction_ids and tx not in self.blockchain.pending_transactions:
                    if self.verify_transaction(tx) and self.blockchain.add_transaction(tx):
                        self.processed_transaction_ids.add(tx.id)
                        self.transaction_queue.pop(0)
                        for node in self.network.nodes:
                            if node.node_id != self.node_id and not node.is_malicious:
                                if tx.id not in node.processed_transaction_ids:
                                    node.transaction_queue.append(tx)
                else:
                    self.transaction_queue.pop(0)

    def verify_transaction(self, transaction):
        required_fields = ["id", "sender", "receiver", "amount", "timestamp"]
        tx_dict = transaction.to_dict()
        return (
            all(key in tx_dict for key in required_fields)
            and transaction.amount > 0
            and transaction.id not in self.processed_transaction_ids
        )

    def broadcast_transaction(self, target_node, transaction):
        yield self.env.timeout(self.network_delay)
        if not target_node.is_malicious and target_node.verify_transaction(transaction):
            target_node.transaction_queue.append(transaction)

    def mine_block(self, miner_address, blockchain=None):
        blockchain = blockchain or self.blockchain
        transactions = blockchain.pending_transactions[:]
        block = Block(len(blockchain.chain), transactions, time.time(), blockchain.get_latest_block().hash)
        block.mine_block(blockchain.difficulty)
        for tx in transactions:
            self.processed_transaction_ids.add(tx.id)
        return block

    def perform_double_spending_attack(self, transaction, amount):
        if not self.is_malicious:
            return False, 0.0, self.network_delay, 0, transaction
        self.attack_attempts += 1

        # Use the same timestamp for both transactions
        current_time = transaction.timestamp

        # Create malicious transaction to attacker's own wallet
        malicious_transaction = Transaction(
            transaction.sender,
            f"attacker_wallet_{self.node_id}",
            amount,
            current_time
        )

        # Verify both transactions by all nodes
        public_valid = True
        malicious_valid = True
        for node in self.network.nodes:
            if not node.verify_transaction(transaction):
                public_valid = False
            if not node.verify_transaction(malicious_transaction):
                malicious_valid = False
        if not public_valid or not malicious_valid:
            return False, self.attack_success_count / self.attack_attempts if self.attack_attempts > 0 else 0.0, self.network_delay, 0, transaction

        # Add public transaction to shared blockchain
        self.blockchain.add_transaction(transaction)
        self.processed_transaction_ids.add(transaction.id)

        # Add malicious transaction to private chain and mine immediately
        self.private_chain.pending_transactions = [malicious_transaction]
        malicious_block = self.mine_block(f"attacker_{self.node_id}", self.private_chain)
        self.private_chain.add_block(malicious_block)
        self.processed_transaction_ids.add(malicious_transaction.id)

        # Calculate total honest nodes' hash rate
        total_honest_hash_rate = sum(node.hash_rate for node in self.network.nodes if not node.is_malicious)
        # Calculate average honest nodes' delay
        honest_nodes = [node for node in self.network.nodes if not node.is_malicious]
        avg_honest_delay = sum(node.network_delay for node in honest_nodes) / len(honest_nodes) if honest_nodes else float('inf')

        # Capture honest chain state before attack
        honest_chain_before = [
            {
                'index': block.index,
                'transactions': [tx.to_dict() for tx in block.transactions],
                'timestamp': block.timestamp,
                'previous_hash': block.previous_hash,
                'nonce': block.nonce,
                'hash': block.hash
            } for block in self.blockchain.chain
        ]

        # Capture private chain state
        private_chain_state = [
            {
                'index': block.index,
                'transactions': [tx.to_dict() for tx in block.transactions],
                'timestamp': block.timestamp,
                'previous_hash': block.previous_hash,
                'nonce': block.nonce,
                'hash': block.hash
            } for block in self.private_chain.chain
        ]

        # Log attack attempt to CSV
        attack_log = {
            'timestamp': current_time,
            'attack_attempt': self.attack_attempts,
            'public_sender': transaction.to_dict()['sender'],
            'public_receiver': transaction.to_dict()['receiver'],
            'public_amount': transaction.to_dict()['amount'],
            'public_tx_id': transaction.to_dict()['id'],
            'malicious_sender': malicious_transaction.to_dict()['sender'],
            'malicious_receiver': malicious_transaction.to_dict()['receiver'],
            'malicious_amount': malicious_transaction.to_dict()['amount'],
            'malicious_tx_id': malicious_transaction.to_dict()['id'],
            'success': False,
            'success_rate': 0.0,
            'network_delay': self.network_delay,
            'private_chain_length': len(self.private_chain.chain),
            'honest_chain_before': honest_chain_before,
            'private_chain': private_chain_state
        }

        # Print chain and transaction details
        print(f"Node {self.node_id} (Malicious) - Honest Chain before attack: {honest_chain_before}")
        print(f"Public Transaction: {transaction.to_dict()}")
        print(f"Malicious Transaction: {malicious_transaction.to_dict()}")
        print(f"Node {self.node_id} - Private Chain: {private_chain_state}")

        # Check hash rate and delay conditions for attack success
        if self.hash_rate <= total_honest_hash_rate or self.network_delay >= avg_honest_delay:
            # Attack failed, mine public transaction on honest chain
            block = self.network.nodes[0].mine_block("honest_miner")
            self.network.shared_blockchain.add_block(block)
            for node in self.network.nodes:
                node.blockchain.chain = self.network.shared_blockchain.chain[:]
                node.blockchain.pending_transactions = self.network.shared_blockchain.pending_transactions[:]
                for tx in block.transactions:
                    node.processed_transaction_ids.add(tx.id)
            print(f"Node {self.node_id} - Attack failed. Honest chain updated: {[{ 'index': block.index, 'transactions': [tx.to_dict() for tx in block.transactions], 'timestamp': block.timestamp, 'previous_hash': block.previous_hash, 'nonce': block.nonce, 'hash': block.hash } for block in self.blockchain.chain]}")
            attack_log['success_rate'] = self.attack_success_count / self.attack_attempts if self.attack_attempts > 0 else 0.0
            self.log_attack_to_csv(attack_log)
            return False, attack_log['success_rate'], self.network_delay, len(self.private_chain.chain), transaction

        # Attack succeeds: broadcast private chain
        for node in self.network.nodes:
            node.blockchain.chain = self.private_chain.chain[:]
            node.blockchain.pending_transactions = []
            node.processed_transaction_ids.add(malicious_transaction.id)
        self.attack_success_count += 1
        print(f"Node {self.node_id} - Attack succeeded. Chain replaced: {[{ 'index': block.index, 'transactions': [tx.to_dict() for tx in block.transactions], 'timestamp': block.timestamp, 'previous_hash': block.previous_hash, 'nonce': block.nonce, 'hash': block.hash } for block in self.blockchain.chain]}")

        # Update attack log
        attack_log['success'] = True
        attack_log['success_rate'] = self.attack_success_count / self.attack_attempts if self.attack_attempts > 0 else 0.0
        attack_log['private_chain_length'] = len(self.private_chain.chain)
        self.log_attack_to_csv(attack_log)

        return True, attack_log['success_rate'], self.network_delay, len(self.private_chain.chain), malicious_transaction

    def log_attack_to_csv(self, attack_log):
        with open('attack_log.csv', 'a', newline='') as csvfile:
            fieldnames = [
                'timestamp', 'attack_attempt',
                'public_sender', 'public_receiver', 'public_amount', 'public_tx_id',
                'malicious_sender', 'malicious_receiver', 'malicious_amount', 'malicious_tx_id',
                'success', 'success_rate', 'network_delay', 'private_chain_length',
                'honest_chain_before', 'private_chain'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if csvfile.tell() == 0:
                writer.writeheader()
            writer.writerow({
                'timestamp': attack_log['timestamp'],
                'attack_attempt': attack_log['attack_attempt'],
                'public_sender': attack_log['public_sender'],
                'public_receiver': attack_log['public_receiver'],
                'public_amount': attack_log['public_amount'],
                'public_tx_id': attack_log['public_tx_id'],
                'malicious_sender': attack_log['malicious_sender'],
                'malicious_receiver': attack_log['malicious_receiver'],
                'malicious_amount': attack_log['malicious_amount'],
                'malicious_tx_id': attack_log['malicious_tx_id'],
                'success': attack_log['success'],
                'success_rate': attack_log['success_rate'],
                'network_delay': attack_log['network_delay'],
                'private_chain_length': attack_log['private_chain_length'],
                'honest_chain_before': str(attack_log['honest_chain_before']),
                'private_chain': str(attack_log['private_chain'])
            })

class BlockchainNetworkSimulator:
    def __init__(self, env, num_nodes=6, malicious_node_indices=None, difficulty=1):  
        self.env = env
        self.nodes = []
        self.difficulty = difficulty
        self.attack_stats = {'attempts': 0, 'successes': 0, 'success_rate': 0.0}
        self.shared_blockchain = Blockchain(difficulty=difficulty)
        node_configs = [
            {'node_id': 0, 'is_malicious': False, 'hash_rate': 1.0, 'network_delay': 0.3},
            {'node_id': 1, 'is_malicious': False, 'hash_rate': 1.0, 'network_delay': 0.4},
            {'node_id': 2, 'is_malicious': False, 'hash_rate': 1.0, 'network_delay': 0.35},
            {'node_id': 3, 'is_malicious': False, 'hash_rate': 1.0, 'network_delay': 0.45},
            {'node_id': 4, 'is_malicious': False, 'hash_rate': 1.0, 'network_delay': 0.5},
            {'node_id': 5, 'is_malicious': True, 'hash_rate': 6.0, 'network_delay': 0.1}
        ]
        for config in node_configs:
            node = Node(
                env,
                config['node_id'],
                self.shared_blockchain,
                is_malicious=config['is_malicious'],
                hash_rate=config['hash_rate'],
                network_delay=config['network_delay']
            )
            self.nodes.append(node)
        for node in self.nodes:
            node.network = self

    def add_transaction(self, transaction):
        # Verify transaction by all nodes
        for node in self.nodes:
            if not node.verify_transaction(transaction):
                return False
        success = self.shared_blockchain.add_transaction(transaction)
        if success:
            for node in self.nodes:
                if transaction.id not in node.processed_transaction_ids:
                    node.transaction_queue.append(transaction)
                    node.processed_transaction_ids.add(transaction.id)
        return success

    def mine_block(self, node_index, miner_address):
        block = self.nodes[node_index].mine_block(miner_address, self.shared_blockchain)
        self.shared_blockchain.add_block(block)
        for node in self.nodes:
            node.blockchain.chain = self.shared_blockchain.chain[:]
            node.blockchain.pending_transactions = self.shared_blockchain.pending_transactions[:]
            node.transaction_queue = [tx for tx in node.transaction_queue if tx.id not in {t.id for t in block.transactions}]
            for tx in block.transactions:
                node.processed_transaction_ids.add(tx.id)
        return block

    def perform_double_spending_attack(self, transaction, amount):
        malicious_node = next((node for node in self.nodes if node.is_malicious), None)
        if malicious_node:
            success, success_rate, network_delay, private_chain_length, returned_transaction = malicious_node.perform_double_spending_attack(transaction, amount)
            self.attack_stats['attempts'] = malicious_node.attack_attempts
            self.attack_stats['successes'] = malicious_node.attack_success_count
            self.attack_stats['success_rate'] = success_rate
            return success, success_rate, network_delay, private_chain_length, returned_transaction
        return False, 0.0, 0.0, 0, transaction

    def get_attack_stats(self):
        return self.attack_stats

    def run_simulation(self):
        self.env.run()