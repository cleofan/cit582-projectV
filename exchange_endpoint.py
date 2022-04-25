from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback
import random
import time
import base64
from algosdk.v2client import indexer
from web3 import Web3

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

print("We are at line 25")
app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()

def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """
print("Are we here at line 87?")
        
""" Helper Methods (skeleton code for you to implement) """

def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    new_log = Log(message = message)
    g.session.add(message)
    g.session.commit()
    return

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    #generate algo mnemonic
    algo_mnemonic = "quit snack pledge pool shell hidden forward gun cabbage genre arch ahead alarm comfort process prosper garbage bunker today type start learn goose absorb title"
    algo_sk = algosdk.mnemonic.to_private_key(algo_mnemonic)
    algo_pk = algosdk.mnemonic.to_public_key(algo_mnemonic)  
    return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
    
    w3 = Web3()
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys
    w3.eth.account.enable_unaudited_hdwallet_features()
    eth_mnemonic = "deposit alpha exact virtual heart demand pilot matter morning jeans drip logic"
    try:
        acct = w3.eth.account.from_mnemonic(eth_mnemonic)
        eth_pk = acct._address
        eth_sk = acct._private_key

        return eth_sk, eth_pk
    except Exception as e:
        print("Failed in acquiring eth keys")
        print(traceback.format_exc())
        
  
def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!
    
    query = g.session.query(Order).filter(Order.filled == None, Order.buy_currency == order.sell_currency, Order.sell_currency == order.buy_currency, Order.sell_amount / Order.buy_amount >= order.buy_amount/order.sell_amount)   
    count = query.count()
    if count > 0:
        existing_order = query.first()
        
        #First validate that the existing order has a payment
        existing_tx_id = existing_order.tx_id
        if (existing_order.sell_currency == "Ethereum"):
            existing_tx = g.w3.eth.get_transaction(existing_tx_id)       
            if(existing_tx['value'] != existing_order.sell_amount):
                return []
            
        elif existing_order.sell_currency == "Algorand":
             time.sleep(5)
             existing_tx = (g.icl.search_transactions(txid = existing_tx_id))["transactions"]
             verified = False
             if(existing_tx == []):
                 return []
                 for tx in order_tx:
                     if (tx['payment-transaction']['amount'] == order.sell_amount):
                         verified = True
                 if(verified == False):
                     print("Trade endpoint: the order failed verification on algo chain.")
                     return []
            

        #Update filled to timestamp
        dt = datetime.now()
        
        existing_order.filled, order.filled = (dt, dt)
        existing_order.counterparty_id = order.id
        order.counterparty_id = existing_order.id
        
        #Check if there is any unfilled amount
        if existing_order.buy_amount > order.sell_amount:
            #Calculate the max unfilled amount
            child_buy = existing_order.buy_amount - order.sell_amount
            sell_min = math.ceil (existing_order.sell_amount / existing_order.buy_amount * child_buy)
            sell_max = existing_order.sell_amount - order.buy_amount
            child_sell = random.randint(sell_min, sell_max)
            child_order = Order(sender_pk=existing_order.sender_pk,receiver_pk=existing_order.receiver_pk, buy_currency=existing_order.buy_currency, sell_currency=existing_order.sell_currency, buy_amount=child_buy, sell_amount=child_sell, creator_id = existing_order.id)
            g.session.add(child_order)
            #create tx for existing_order
            tx_existing = {'platform':existing_order.buy_currency, 'receiver_pk':existing_order.receiver_pk, 'order_id':existing_order.id, 'amount':order.sell_amount}
            txes.append(tx_existing)
            tx_order = {'platform':order.buy_currency, 'receiver_pk':order.receiver_pk, 'order_id':order.id, 'amount':order.buy_amount}
            txes.append(tx_order)
        
        elif order.buy_amount > existing_order.sell_amount:
            #Calculate the max unfilled amount
            child_buy = order.buy_amount - existing_order.sell_amount
            sell_min = math.ceil (order.sell_amount / order.buy_amount * child_buy)
            sell_max = order.sell_amount - existing_order.buy_amount
            child_sell = random.randint(sell_min, sell_max)
            child_order = Order( sender_pk=order.sender_pk,receiver_pk=order.receiver_pk, buy_currency=order.buy_currency, sell_currency=order.sell_currency, buy_amount=child_buy, sell_amount=child_sell, creator_id = order.id)
            g.session.add(child_order)
            tx_existing = {'platform':existing_order.buy_currency, 'receiver_pk':existing_order.receiver_pk, 'order_id':existing_order.id, 'amount':existing_order.buy_amount}
            txes.append(tx_existing)
            tx_order = {'platform':order.buy_currency, 'receiver_pk':order.receiver_pk, 'order_id':order.id, 'amount':existing_order.sell_amount}
            txes.append(tx_order)
        
        else:
            tx_existing = {'platform':existing_order.buy_currency, 'receiver_pk':existing_order.receiver_pk, 'order_id':existing_order.id, 'amount':existing_order.buy_amount}
            txes.append(tx_existing)
            tx_order = {'platform':order.buy_currency, 'receiver_pk':order.receiver_pk, 'order_id':order.id, 'amount':order.buy_amount}
            txes.append(tx_order)
            
            
            
        
        g.session.commit()
        #Also create the txes for execution
        #child_tx = {'platform':child_order.sell_currency, 'receiver_pk':child_order.receiver_pk, 'order_id':child_order.creator_id, 'amount':child_order.sell_amount}
        #add it to the list of txes to be executed
        #txes.append(child_tx)
        #Then match for child order
        return txes
    
    else:
        return txes    
    pass
  
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )
        return False;

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

    algo_result_txids = send_tokens_algo(g.acl, algo_sk, algo_txes)
    if len(algo_result_txids) != len(algo_txes):
        print("Trade:failed sending tokens to algo orders")
    for tx in algo_txes:
        transaction = TX(platform = tx['platform'], receiver_pk = tx['receiver_pk'], order_id = tx['order_id'], tx_id = tx['tx_id'])
        g.session.add(transaction)
        g.session.commit()
        print("Added TX", transaction.tx_id)
    
    eth_result_txids = send_tokens_eth(g.w3, eth_sk, eth_txes)
    if len(eth_result) != len(eth_txes):
        print("Trade:failed sending tokens to eth orders")
    for tx in eth_txes:
        transaction = TX(platform = tx['platform'], receiver_pk = tx['receiver_pk'], order_id = tx['order_id'], tx_id = tx['tx_id'])
        g.session.add(transaction)
        g.session.commit()
        print("added TX", transaction.tx_id)
        
    if len(algo_result_txids) != len(algo_txes) or len(eth_result) != len(eth_txes):
        return False
    else:
        return True
    pass

def check_sig(payload,sig):
    platform = payload.get("platform")
    message = json.dumps(payload)
    sender_pk = payload.get("sender_pk")
    if (platform == "Algorand"):
        if(algosdk.util.verify_bytes(message.encode('utf-8'),sig, sender_pk) == True):
            return jsonify(True)
    else:
        eth_encoded_msg = eth_account.messages.encode_defunct(text=message)
        recovered_pk = eth_account.Account.recover_message(eth_encoded_msg, signature = sig)
        if recovered_pk == sender_pk:
            return jsonify(True)
    return jsonify(False)
    pass


""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            eth_sk, eth_pk = get_eth_keys()
            #Your code here
            return jsonify(eth_pk)
        if content['platform'] == "Algorand":
            #Your code here
            algo_sk, algo_pk = get_algo_keys()
            return jsonify( algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        payload = content.get("payload")
        sig = content.get("sig")
        if check_sig(payload, sig) == jsonify(False):
            print("signature verification failed")
            log_message(payload)
            return jsonify(False)
        else:
      
        # 2. Add the order to the table
            payload['signature'] = sig
            order = Order(receiver_pk = payload['receiver_pk'], sender_pk = payload['sender_pk'], tx_id = payload['tx_id'], buy_currency = payload['buy_currency'], sell_currency = payload['sell_currency'], buy_amount = payload['buy_amount'], sell_amount = payload['sell_amount'], signature= payload['signature'])
            g.session.add(order)
            g.session.commit()
            print("Finished checking signature and adding the order")
        
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
            order_tx_id = order.tx_id
            eth_pk = get_eth_keys()[1]
            algo_pk = get_algo_keys()[1]
            
            if (order.sell_currency == "Ethereum"):
                try:
                    order_tx = g.w3.eth.get_transaction(order_tx_id)
                    print("Eth Transaction Info: " )
                    print(order_tx)
                    if(order_tx is None) or( order_tx['value'] != order.sell_amount) or (order_tx['from'] != order.sender_pk) or (order_tx['to'] != eth_pk) :
                        print("Eth Error: verifying order on chain failed")
                        return jsonify(False)
                    else:
                        print("Eth: verifying order on chain successful")
                except Exception as e:
                    import traceback
                    print(traceback.format_exc())
                    return jsonfiy(False)
                    print(e)
                
                
            
            elif order.sell_currency == "Algorand":
                #order_tx_id = base64.b64decode(order_tx_id).encode('ascii')
                time.sleep(5)
                try:
                    response = g.icl.search_transactions(txid = order_tx_id)
                    if response is None:
                        return jsonify(False)
                    if isinstance(response, str):
                        return jsonify(False)
                    transactions = response["transactions"][0]
                    print("Algo Tranastion Info: " + json.dumps(transactions, indent=2, sort_keys=True))
                    if transactions is None:
                        return jsonify(False)
                    verified = False
                    for tx in transactions:
                        if (tx['payment-transaction']['amount'] == order.sell_amount and tx['payment-transaction']['receiver'] == algo_pk and tx['sender'] == order.sender_pk):
                            verified = True
                    if(verified == False):
                        print("Trade endpoint: the order failed verification on algo chain.")
                        return jsonify(False)
                except Exception as e:
                    print("Error in using the indexer in Trade endpoint.")
                    print(e)
                    return jsonify (False)
                
        # 3b. Fill the order (as in Exchange Server II) if the order is valid
            txes = []
            fill_order(order, txes)
            print("Finished filling orders")
        
        # 4
            returnBool = execute_txes(txes)
            if returnBool == False:
                return jsonify(False)
            
        
        # If all goes well, return jsonify(True). else return jsonify(False)
        return jsonify(True)
    else:
        return jsonify(False)

@app.route('/order_book')
def order_book():
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk", "sender_pk" ]
    
    # Same as before
    query = g.session.query(Order).filter().all()
    result_lst = []
    
    for u in query:
        order = {}
        order['sender_pk'] = u.sender_pk
        order['receiver_pk'] = u.receiver_pk
        order['buy_currency']=u.buy_currency
        order['sell_currency']=u.sell_currency
        order['buy_amount']=u.buy_amount
        order['sell_amount']=u.sell_amount
        order['signature']=u.signature
        order['tx_id'] = u.tx_id
        result_lst.append(order)
    result = {}
    result['data']=result_lst
    return jsonify(result)
    pass

if __name__ == '__main__':
    app.run(port='5002')
