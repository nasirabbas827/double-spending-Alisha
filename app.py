from flask import Flask, jsonify, request, render_template, redirect, url_for, send_file
import simpy
from simblock_sim import BlockchainNetworkSimulator
from blockchain import Block, Transaction, Blockchain
import time
from threading import Thread

app = Flask(__name__)

# Global simulator instance
sim_env = simpy.Environment()
network_simulator = BlockchainNetworkSimulator(sim_env, num_nodes=6, malicious_node_indices=[5])

# Store the original transaction for display purposes
last_original_transaction = None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/chain', methods=['GET'])
def get_chain():
    blockchain = network_simulator.shared_blockchain
    response = {
        'chain': [{
            'index': block.index,
            'transactions': [tx.to_dict() for tx in block.transactions],
            'timestamp': block.timestamp,
            'previous_hash': block.previous_hash,
            'hash': block.hash,
            'nonce': block.nonce
        } for block in blockchain.chain],
        'length': len(blockchain.chain)
    }
    return jsonify(response)

@app.route('/show_chain', methods=['GET'])
def show_chain():
    blockchain = network_simulator.shared_blockchain
    response = {
        'chain': [{
            'index': block.index,
            'transactions': [tx.to_dict() for tx in block.transactions],
            'timestamp': block.timestamp,
            'previous_hash': block.previous_hash,
            'hash': block.hash,
            'nonce': block.nonce
        } for block in blockchain.chain],
        'length': len(blockchain.chain),
        'original_transaction': last_original_transaction.to_dict() if last_original_transaction else None
    }
    return render_template('chain.html', data=response)

@app.route('/nodes', methods=['GET'])
def get_nodes():
    nodes = [{
        'node_id': node.node_id,
        'is_malicious': node.is_malicious,
        'hash_rate': node.hash_rate,
        'network_delay': node.network_delay
    } for node in network_simulator.nodes]
    return jsonify({'nodes': nodes, 'total_nodes': len(nodes)})

@app.route('/show_nodes', methods=['GET'])
def show_nodes():
    nodes = [{
        'node_id': node.node_id,
        'is_malicious': node.is_malicious,
        'hash_rate': node.hash_rate,
        'network_delay': node.network_delay
    } for node in network_simulator.nodes]
    return render_template('nodes.html', data={'nodes': nodes, 'total_nodes': len(nodes)})

@app.route('/transaction/new', methods=['POST'])
def new_transaction():
    values = request.form
    required = ['sender', 'receiver', 'amount']
    if not all(k in values for k in required):
        return render_template('error.html', message='Missing values'), 400
    try:
        amount = float(values['amount'])
        transaction = Transaction(values['sender'], values['receiver'], amount, time.time())
        success = network_simulator.add_transaction(transaction)
        if success:
            return render_template('success.html', message='Transaction added successfully')
        return render_template('error.html', message='Invalid transaction'), 400
    except ValueError:
        return render_template('error.html', message='Invalid amount'), 400

@app.route('/mine', methods=['POST'])
def mine():
    values = request.form
    required = ['node_index']
    if not all(k in values for k in required):
        return render_template('error.html', message='Missing node index'), 400
    try:
        node_index = int(values['node_index'])
        miner_address = values.get('miner_address', f'node_{node_index}')
        if node_index not in range(len(network_simulator.nodes)):
            return render_template('error.html', message='Invalid node index'), 400
        block = network_simulator.mine_block(node_index, miner_address)
        return render_template('block.html', block={
            'index': block.index,
            'transactions': [tx.to_dict() for tx in block.transactions],
            'timestamp': block.timestamp,
            'previous_hash': block.previous_hash,
            'hash': block.hash,
            'nonce': block.nonce
        }, message='Block mined successfully')
    except ValueError:
        return render_template('error.html', message='Invalid node index'), 400

@app.route('/attack', methods=['POST'])
def perform_attack():
    global last_original_transaction
    values = request.form
    required = ['sender', 'receiver', 'amount']
    if not all(k in values for k in required):
        return render_template('error.html', message='Missing values'), 400
    try:
        amount = float(values['amount'])
        # Reset blockchain for clean state
        network_simulator.shared_blockchain = Blockchain(difficulty=4)
        for node in network_simulator.nodes:
            node.blockchain = network_simulator.shared_blockchain
            if node.is_malicious:
                node.private_chain = Blockchain(difficulty=4)
        transaction = Transaction(values['sender'], values['receiver'], amount, time.time())
        last_original_transaction = transaction  # Store the original transaction
        success, success_rate, network_delay, private_chain_length, returned_transaction = network_simulator.perform_double_spending_attack(transaction, amount)
        return render_template('attack.html', result={
            'message': 'Double-spending attack attempted',
            'success': success,
            'success_rate': success_rate,
            'network_delay': network_delay,
            'private_chain_length': private_chain_length,
            'original_transaction': transaction.to_dict(),
            'malicious_transaction': returned_transaction.to_dict()
        })
    except ValueError:
        return render_template('error.html', message='Invalid amount'), 400

@app.route('/stats', methods=['GET'])
def get_stats():
    stats = network_simulator.get_attack_stats()
    return jsonify(stats)

@app.route('/show_stats', methods=['GET'])
def show_stats():
    stats = network_simulator.get_attack_stats()
    return render_template('stats.html', data=stats)

@app.route('/download_csv', methods=['GET'])
def download_csv():
    try:
        return send_file('attack_log.csv', as_attachment=True, download_name='attack_log.csv')
    except FileNotFoundError:
        return render_template('error.html', message='Attack log CSV file not found'), 404

if __name__ == '__main__':
    simulation_thread = Thread(target=network_simulator.run_simulation, daemon=True)
    simulation_thread.start()
    app.run(host='0.0.0.0', port=5000, debug=True)