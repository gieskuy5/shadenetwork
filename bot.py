import requests
import json
import os
import random
import time
from eth_account import Account
from eth_account.messages import encode_defunct
from datetime import datetime, timezone
from colorama import init, Fore, Style

# Initialize colorama
init()

# ======================= CONFIGURATION =======================
BASE_URL = 'https://v1.shadenetwork.io'
POINTS_URL = 'https://points.shadenetwork.io'
PRIVATEKEY_FILE = './privatekey.txt'
PROXY_FILE = './proxy.txt'
REFF_FILE = './reff.txt'

# Wallet API for onchain operations
WALLET_URL = 'https://wallet.shadenetwork.io'

# Captcha solver configuration
CAPTCHA_API_KEY = 'SCTG APIKEY'
TURNSTILE_SITEKEY = '0x4AAAAAACN1moBrJQ-mAzdh'
TURNSTILE_PAGEURL = 'https://wallet.shadenetwork.io'

# Onchain quest IDs
QUEST_FAUCET = 'onchain_004'
QUEST_SHIELD = 'onchain_001'
QUEST_UNSHIELD = 'onchain_002'
QUEST_PRIVATE_SEND = 'onchain_003'

# Registration settings
DELAY_MIN_SECONDS = 5
DELAY_MAX_SECONDS = 10
MAX_RETRIES = 3

# ======================= FINGERPRINT GENERATOR =======================
def generate_fingerprint():
    chrome_versions = ['120', '121', '122', '123', '124', '125', '126', '127', '128', '129', '130', '131', '132', '133', '134', '135', '136', '137', '138', '139', '140', '141', '142', '143', '144']
    platforms = ['Windows', 'Linux', 'macOS']
    languages = ['en-US', 'en-GB', 'en-CA', 'en-AU']
    brands = [
        {'name': 'Microsoft Edge', 'brand': 'Microsoft Edge'},
        {'name': 'Google Chrome', 'brand': 'Google Chrome'},
    ]

    chrome_version = random.choice(chrome_versions)
    platform = random.choice(platforms)
    language = random.choice(languages)
    selected_brand = random.choice(brands)

    if platform == 'Windows':
        user_agent = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version}.0.0.0 Safari/537.36"
    elif platform == 'Linux':
        user_agent = f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version}.0.0.0 Safari/537.36"
    else:
        user_agent = f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version}.0.0.0 Safari/537.36"

    sec_ch_ua = f'"Not(A:Brand";v="8", "Chromium";v="{chrome_version}", "{selected_brand["brand"]}";v="{chrome_version}"'

    return {
        'userAgent': user_agent,
        'secChUa': sec_ch_ua,
        'secChUaPlatform': f'"{platform}"',
        'acceptLanguage': f'{language},en;q=0.9',
        'chromeVersion': chrome_version,
        'platform': platform
    }

# ======================= PROXY FUNCTIONS =======================
def load_proxies():
    try:
        if not os.path.exists(PROXY_FILE):
            return []
        with open(PROXY_FILE, 'r', encoding='utf-8') as f:
            proxies = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return proxies
    except:
        return []

def get_proxy_dict(proxy_line):
    if not proxy_line:
        return None
    if proxy_line.startswith("http://") or proxy_line.startswith("https://"):
        proxy_url = proxy_line
    else:
        proxy_url = f"http://{proxy_line}"
    return {
        "http": proxy_url,
        "https": proxy_url
    }

def get_proxy_display(proxy_line):
    if not proxy_line:
        return ''
    try:
        if '@' in proxy_line:
            host_port = proxy_line.split('@')[-1]
            return f":{host_port.split(':')[-1]}"
        return ''
    except:
        return ''

# ======================= PRIVATE KEY FUNCTIONS =======================
def load_private_keys():
    """Load private keys from privatekey.txt file (one per line)"""
    try:
        if not os.path.exists(PRIVATEKEY_FILE):
            return []
        with open(PRIVATEKEY_FILE, 'r', encoding='utf-8') as f:
            keys = [line.strip() for line in f if line.strip() and not line.startswith('#') and line.strip() != '.']
        # Normalize keys - add 0x prefix if missing
        normalized_keys = []
        for key in keys:
            if key.startswith('0x') or key.startswith('0X'):
                normalized_keys.append(key)
            else:
                normalized_keys.append(f'0x{key}')
        return normalized_keys
    except:
        return []

def get_accounts():
    """Load accounts from private keys"""
    private_keys = load_private_keys()
    accounts = []
    
    for i, pk in enumerate(private_keys):
        try:
            account = Account.from_key(pk)
            accounts.append({
                'id': i + 1,
                'address': account.address,
                'privateKey': pk,
                'account': account,
                'fingerprint': generate_fingerprint()
            })
        except Exception as e:
            print(f"{Fore.RED}Invalid key at line {i + 1}: {str(e)[:30]}{Style.RESET_ALL}")
    
    return accounts

def read_ref():
    try:
        with open(REFF_FILE, 'r', encoding='utf-8') as f:
            ref = f.readline().strip()
            return ref if ref else 'airdroplahat'
    except:
        return 'airdroplahat'

def generate_random_nickname():
    first_names = [
        'James', 'John', 'Robert', 'Michael', 'William', 'David', 'Richard', 'Joseph', 'Thomas', 'Charles',
        'Emma', 'Olivia', 'Ava', 'Isabella', 'Sophia', 'Mia', 'Charlotte', 'Amelia', 'Harper', 'Evelyn',
        'Daniel', 'Matthew', 'Anthony', 'Mark', 'Donald', 'Steven', 'Paul', 'Andrew', 'Joshua', 'Kenneth',
        'Emily', 'Elizabeth', 'Sofia', 'Avery', 'Ella', 'Scarlett', 'Grace', 'Chloe', 'Victoria', 'Riley',
        'Alex', 'Ryan', 'Tyler', 'Brandon', 'Justin', 'Austin', 'Kevin', 'Brian', 'Eric', 'Jason',
        'Lily', 'Zoe', 'Hannah', 'Natalie', 'Leah', 'Savannah', 'Audrey', 'Brooklyn', 'Claire', 'Skylar'
    ]
    last_names = [
        'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez',
        'Anderson', 'Taylor', 'Thomas', 'Moore', 'Jackson', 'Martin', 'Lee', 'Thompson', 'White', 'Harris',
        'Clark', 'Lewis', 'Robinson', 'Walker', 'Young', 'Allen', 'King', 'Wright', 'Scott', 'Green'
    ]
    return f"{random.choice(first_names)}{random.choice(last_names)}{random.randint(0, 999)}"

def short_addr(addr):
    return f"{addr[:8]}...{addr[-6:]}"

# ======================= API FUNCTIONS =======================
def get_headers(fingerprint, token=None):
    headers = {
        'accept': '*/*',
        'accept-language': fingerprint['acceptLanguage'],
        'cache-control': 'no-cache',
        'content-type': 'application/json',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'sec-ch-ua': fingerprint['secChUa'],
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': fingerprint['secChUaPlatform'],
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'referer': 'https://v1.shadenetwork.io/',
        'user-agent': fingerprint['userAgent']
    }
    if token:
        headers['authorization'] = f'Bearer {token}'
    return headers

def get_user_info(address, fingerprint, proxies=None):
    """Get user info from API - returns user data if registered, None if not"""
    try:
        response = requests.get(
            f"{BASE_URL}/api/auth/user?wallet={address}",
            headers=get_headers(fingerprint),
            proxies=proxies,
            timeout=15
        )
        data = response.json()
        return data.get('user')
    except:
        return None

def create_session(wallet_address, private_key, fingerprint, proxies=None):
    try:
        timestamp = int(time.time() * 1000)
        message = f"Shade Points: Create account for {wallet_address.lower()} at {timestamp}"
        
        account = Account.from_key(private_key)
        signed = account.sign_message(encode_defunct(text=message))
        signature = signed.signature.hex()
        
        response = requests.post(
            f"{BASE_URL}/api/auth/session",
            headers=get_headers(fingerprint),
            json={'address': wallet_address, 'timestamp': timestamp, 'signature': f"0x{signature}"},
            proxies=proxies,
            timeout=15
        )
        data = response.json()
        if data.get('token'):
            return {'token': data['token'], 'expiresAt': data.get('expiresAt')}
        return None
    except:
        return None

def register_user_simple(wallet_address, nickname, referral_code, fingerprint, proxies=None):
    """Simple registration using points.shadenetwork.io"""
    try:
        response = requests.post(
            f"{POINTS_URL}/api/auth/user",
            headers=get_headers(fingerprint),
            json={
                'walletAddress': wallet_address,
                'nickname': nickname,
                'referredBy': referral_code
            },
            proxies=proxies,
            timeout=15
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('error'):
                return {'error': data['error']}
            return {'user': data.get('user', {'nickname': nickname, 'points': 0})}
        else:
            try:
                data = response.json()
                return {'error': data.get('error', f'Status {response.status_code}')}
            except:
                return {'error': f'Status {response.status_code}'}
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

def claim_daily(token, fingerprint, proxies=None):
    try:
        response = requests.post(
            f"{BASE_URL}/api/claim",
            headers=get_headers(fingerprint, token),
            json={},
            proxies=proxies,
            timeout=15
        )
        if response.status_code == 200:
            return response.json()
        else:
            try:
                error_data = response.json()
                return {'error': error_data.get('error', f'Status {response.status_code}'), 'status': response.status_code}
            except:
                return {'error': f'Status {response.status_code}: {response.text[:100]}', 'status': response.status_code}
    except Exception as e:
        return {'error': str(e)}

# ======================= CAPTCHA SOLVER =======================
def solve_turnstile_captcha(fingerprint, proxies=None):
    """Solve Cloudflare Turnstile captcha using external API"""
    from urllib.parse import urlencode
    try:
        params = {
            "key": CAPTCHA_API_KEY,
            "method": "turnstile",
            "pageurl": TURNSTILE_PAGEURL,
            "sitekey": TURNSTILE_SITEKEY
        }
        query = urlencode(params)
        url = f"https://api.sctg.xyz/in.php?{query}"
        
        response = requests.get(url, proxies=proxies, timeout=30)
        result = response.text.strip()
        
        if "|" not in result:
            return None
        
        status, task_id = result.split("|", 1)
        if status != "OK":
            return None
        
        max_wait = 120
        poll_interval = 5
        start_time = time.time()
        
        while (time.time() - start_time) < max_wait:
            time.sleep(poll_interval)
            
            poll_params = {
                "key": CAPTCHA_API_KEY,
                "id": task_id,
                "action": "get"
            }
            poll_query = urlencode(poll_params)
            poll_url = f"https://api.sctg.xyz/res.php?{poll_query}"
            
            poll_response = requests.get(poll_url, proxies=proxies, timeout=30)
            poll_result = poll_response.text.strip()
            
            if "CAPCHA_NOT_READY" in poll_result or "NOT_READY" in poll_result:
                continue
            
            if poll_result.startswith("OK|"):
                return poll_result.split("|", 1)[1]
            
            if "ERROR" not in poll_result:
                return poll_result
        
        return None
    except Exception as e:
        return None

# ======================= WALLET API FUNCTIONS =======================
def get_wallet_headers(fingerprint, token=None):
    headers = {
        'accept': '*/*',
        'accept-language': fingerprint['acceptLanguage'],
        'cache-control': 'no-cache',
        'content-type': 'application/json',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'sec-ch-ua': fingerprint['secChUa'],
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': fingerprint['secChUaPlatform'],
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'referer': 'https://wallet.shadenetwork.io/',
        'user-agent': fingerprint['userAgent']
    }
    return headers

def create_wallet_session(wallet_address, private_key, fingerprint, proxies=None):
    """Create session for wallet.shadenetwork.io"""
    try:
        timestamp = int(time.time() * 1000)
        message = f"Shade Wallet: Create session for {wallet_address.lower()} at {timestamp}"
        
        account = Account.from_key(private_key)
        signed = account.sign_message(encode_defunct(text=message))
        signature = f"0x{signed.signature.hex()}"
        
        response = requests.post(
            f"{WALLET_URL}/api/auth/session",
            headers=get_wallet_headers(fingerprint),
            json={'address': wallet_address, 'timestamp': timestamp, 'signature': signature},
            proxies=proxies,
            timeout=15
        )
        data = response.json()
        if data.get('token'):
            return {'token': data['token'], 'expiresAt': data.get('expiresAt')}
        return None
    except Exception as e:
        return None

def claim_faucet(wallet_address, turnstile_token, fingerprint, proxies=None):
    """Claim testnet faucet"""
    try:
        response = requests.post(
            f"{WALLET_URL}/api/drip",
            headers=get_wallet_headers(fingerprint),
            json={'address': wallet_address, 'turnstileToken': turnstile_token},
            proxies=proxies,
            timeout=30
        )
        return response.json()
    except Exception as e:
        return {'error': str(e)}

def get_activities(wallet_address, wallet_token, fingerprint, proxies=None, limit=20):
    """Get wallet activities/transaction history"""
    try:
        response = requests.post(
            f"{WALLET_URL}/api/activities",
            headers=get_wallet_headers(fingerprint),
            json={
                'address': wallet_address,
                'token': wallet_token,
                'limit': limit,
                'offset': 0
            },
            proxies=proxies,
            timeout=15
        )
        return response.json()
    except:
        return {'activities': []}

def get_last_faucet_tx(wallet_address, wallet_token, fingerprint, proxies=None):
    """Get the last successful faucet transaction hash"""
    activities = get_activities(wallet_address, wallet_token, fingerprint, proxies)
    for activity in activities.get('activities', []):
        if activity.get('type') == 'faucet' and activity.get('status') == 'success' and activity.get('txHash'):
            return activity.get('txHash')
    return None

def get_notes(wallet_address, wallet_token, fingerprint, proxies=None):
    """Get shielded notes for wallet"""
    try:
        response = requests.post(
            f"{WALLET_URL}/api/notes",
            headers=get_wallet_headers(fingerprint),
            json={'address': wallet_address, 'token': wallet_token},
            proxies=proxies,
            timeout=15
        )
        return response.json()
    except:
        return {'notes': []}

def do_unshield(wallet_address, private_key, wallet_token, note, fingerprint, proxies=None):
    """Perform unshield operation"""
    from eth_account.messages import encode_typed_data
    try:
        nonce = str(int(time.time() * 1000))
        amount = note['value']
        nullifier = note['commitment']
        note_hash = nullifier
        
        domain = {
            "name": "ShadeUnshield",
            "version": "1",
            "chainId": 271828,
            "verifyingContract": "0xe9c1dc736511f877c5fc1f10f3dff5885969e903"
        }
        
        types = {
            "UnshieldRequest": [
                {"name": "requester", "type": "address"},
                {"name": "recipient", "type": "address"},
                {"name": "amount", "type": "uint256"},
                {"name": "nullifier", "type": "bytes32"},
                {"name": "noteHash", "type": "bytes32"},
                {"name": "nonce", "type": "uint256"}
            ]
        }
        
        message = {
            "requester": wallet_address.lower(),
            "recipient": wallet_address.lower(),
            "amount": amount,
            "nullifier": nullifier,
            "noteHash": note_hash,
            "nonce": nonce
        }
        
        account = Account.from_key(private_key)
        
        full_message = {
            "types": types,
            "primaryType": "UnshieldRequest",
            "domain": domain,
            "message": message
        }
        
        signed = account.sign_typed_data(full_message=full_message)
        signature = f"0x{signed.signature.hex()}"
        
        response = requests.post(
            f"{WALLET_URL}/api/unshield",
            headers=get_wallet_headers(fingerprint),
            json={
                'requester': wallet_address,
                'recipient': wallet_address,
                'amount': amount,
                'noteHash': note_hash,
                'nullifier': nullifier,
                'nonce': nonce,
                'nullifiers': [nullifier],
                'signature': signature,
                'proof': '0x'
            },
            proxies=proxies,
            timeout=30
        )
        return response.json()
    except Exception as e:
        return {'error': str(e)}

def record_activity(action, activity_type, address, fingerprint, proxies=None, activity_id=None, status=None, tx_hash=None, block_number=None, amount=None):
    """Record activity for shield operations"""
    try:
        body = {'action': action, 'type': activity_type, 'address': address}
        if action == 'create':
            body['amount'] = amount
        elif action == 'update':
            body['activityId'] = activity_id
            body['status'] = status
            if tx_hash:
                body['txHash'] = tx_hash
            if block_number:
                body['blockNumber'] = block_number
        
        response = requests.post(
            f"{WALLET_URL}/api/activities/record",
            headers=get_wallet_headers(fingerprint),
            json=body,
            proxies=proxies,
            timeout=15
        )
        return response.json()
    except Exception as e:
        return {'error': str(e)}

def do_shield(wallet_address, private_key, amount_wei, fingerprint, proxies=None):
    """Perform shield operation - send on-chain transaction"""
    from web3 import Web3
    try:
        w3 = Web3(Web3.HTTPProvider('https://rpc.shadenetwork.io'))
        if not w3.is_connected():
            return {'error': 'Failed to connect to RPC'}
        
        SHIELD_CONTRACT = '0x9FDB75BeE75A924D78Fbd35859d7957609d997bB'
        nonce = w3.eth.get_transaction_count(wallet_address)
        
        import secrets
        commitment = '0x' + secrets.token_hex(32)
        
        ciphertext_data = {
            "owner": wallet_address.lower(),
            "value": str(amount_wei),
            "createdAt": int(time.time() * 1000)
        }
        ciphertext_hex = '0x00' + json.dumps(ciphertext_data).encode().hex()
        
        function_selector = '0x4de1332a'
        commitment_padded = commitment[2:].zfill(64)
        offset = '0000000000000000000000000000000000000000000000000000000000000040'
        ciphertext_bytes = bytes.fromhex(ciphertext_hex[2:]) if ciphertext_hex.startswith('0x') else bytes.fromhex(ciphertext_hex)
        length = hex(len(ciphertext_bytes))[2:].zfill(64)
        ciphertext_padded = ciphertext_bytes.hex().ljust((len(ciphertext_bytes) // 32 + 1) * 64, '0')
        
        calldata = function_selector + commitment_padded + offset + length + ciphertext_padded
        
        tx = {
            'chainId': 271828,
            'from': wallet_address,
            'to': SHIELD_CONTRACT,
            'value': int(amount_wei),
            'gas': 150000,
            'gasPrice': w3.eth.gas_price,
            'nonce': nonce,
            'data': calldata
        }
        
        activity_result = record_activity('create', 'shield', wallet_address, fingerprint, proxies, amount=str(amount_wei))
        activity_id = activity_result.get('activityId')
        
        account = Account.from_key(private_key)
        signed_tx = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        tx_hash_hex = ('0x' + tx_hash.hex()) if isinstance(tx_hash, bytes) else tx_hash
        
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        
        if activity_id:
            record_activity('update', 'shield', wallet_address, fingerprint, proxies, 
                          activity_id=activity_id, status='success', 
                          tx_hash=tx_hash_hex, block_number=receipt['blockNumber'])
        
        return {
            'success': True,
            'txHash': tx_hash_hex,
            'blockNumber': receipt['blockNumber'],
            'commitment': commitment
        }
    except Exception as e:
        return {'error': str(e)}

def do_private_send(wallet_address, private_key, recipient_address, amount_wei, note, fingerprint, proxies=None):
    """Perform private send operation"""
    try:
        import secrets
        
        nullifier = note['commitment']
        new_commitment_recipient = '0x' + secrets.token_hex(32)
        new_commitment_change = '0x' + secrets.token_hex(32)
        
        note_data_recipient = {
            "owner": recipient_address.lower(),
            "value": str(amount_wei),
            "createdAt": int(time.time() * 1000)
        }
        encrypted_note_recipient = '0x01' + secrets.token_hex(4) + json.dumps(note_data_recipient).encode().hex()
        
        change_amount = int(note['value']) - int(amount_wei)
        note_data_change = {
            "owner": wallet_address.lower(),
            "value": str(change_amount),
            "createdAt": int(time.time() * 1000)
        }
        encrypted_note_change = '0x01' + secrets.token_hex(4) + json.dumps(note_data_change).encode().hex()
        
        response = requests.post(
            f"{WALLET_URL}/api/transact",
            headers=get_wallet_headers(fingerprint),
            json={
                'proof': '0x',
                'nullifiers': [nullifier],
                'commitments': [new_commitment_recipient, new_commitment_change],
                'encryptedNotes': [encrypted_note_recipient, encrypted_note_change],
                'publicAmount': '0',
                'publicRecipient': '0x0000000000000000000000000000000000000000',
                'sender': wallet_address
            },
            proxies=proxies,
            timeout=30
        )
        return response.json()
    except Exception as e:
        return {'error': str(e)}

# ======================= QUEST VERIFICATION FUNCTIONS =======================
def get_onchain_quests(token, fingerprint, proxies=None):
    """Get list of available quests"""
    try:
        response = requests.get(
            f"{BASE_URL}/api/quests?",
            headers=get_headers(fingerprint, token),
            proxies=proxies,
            timeout=15
        )
        return response.json()
    except:
        return {'quests': []}

def verify_onchain_quest(token, quest_id, tx_hash, fingerprint, proxies=None):
    """Verify onchain quest with transaction hash"""
    try:
        response = requests.post(
            f"{BASE_URL}/api/quests/verify-onchain",
            headers=get_headers(fingerprint, token),
            json={'questId': quest_id, 'txHash': tx_hash},
            proxies=proxies,
            timeout=15
        )
        return response.json()
    except Exception as e:
        return {'error': str(e)}

def complete_onchain_quest(token, quest_id, verification_proof, fingerprint, proxies=None):
    """Complete onchain quest"""
    try:
        response = requests.post(
            f"{BASE_URL}/api/quests/complete",
            headers=get_headers(fingerprint, token),
            json={'questId': quest_id, 'verificationProof': verification_proof},
            proxies=proxies,
            timeout=15
        )
        return response.json()
    except Exception as e:
        return {'error': str(e)}

def wait_for_tx_confirmation(tx_hash, max_wait_seconds=30, fingerprint=None, proxies=None):
    """Wait for transaction to be confirmed on blockchain"""
    from web3 import Web3
    try:
        w3 = Web3(Web3.HTTPProvider('https://rpc.shadenetwork.io'))
        if not w3.is_connected():
            # If RPC fails, just wait a fixed time
            time.sleep(15)
            return True
        
        start_time = time.time()
        while (time.time() - start_time) < max_wait_seconds:
            try:
                receipt = w3.eth.get_transaction_receipt(tx_hash)
                if receipt and receipt.get('status') == 1:
                    return True
            except:
                pass
            time.sleep(3)
        
        # If timeout, still return True (let verification try anyway)
        return True
    except:
        # If any error, just wait a bit and return True
        time.sleep(10)
        return True

def verify_and_complete_quest(token, quest_id, tx_hash, fingerprint, proxies=None, max_retries=3):
    """Verify and complete a quest with retry logic"""
    
    for attempt in range(max_retries):
        verify_result = verify_onchain_quest(token, quest_id, tx_hash, fingerprint, proxies)
        
        if verify_result.get('verified'):
            proof = verify_result.get('proof')
            if not proof:
                return {'error': 'No proof returned', 'verified': False}
            
            complete_result = complete_onchain_quest(token, quest_id, proof, fingerprint, proxies)
            if complete_result.get('success'):
                return {
                    'success': True,
                    'pointsAwarded': complete_result.get('pointsAwarded', 0),
                    'newPoints': complete_result.get('newPoints', 0),
                    'completionCount': complete_result.get('completionCount', 0),
                    'maxCompletions': complete_result.get('maxCompletions', 0)
                }
            else:
                return {'error': complete_result.get('error', 'Complete failed'), 'success': False}
        else:
            # Verification failed - wait before retry
            if attempt < max_retries - 1:
                time.sleep(5)
            else:
                return {'error': f"Verification failed: {verify_result.get('error', 'Unknown')}", 'verified': False}
    
    return {'error': 'Max retries reached', 'success': False}

def check_quest_available(token, quest_id, fingerprint, proxies=None):
    """Check if a quest is available"""
    quests_data = get_onchain_quests(token, fingerprint, proxies)
    quests = quests_data.get('quests', [])
    
    for quest in quests:
        if quest.get('externalId') == quest_id:
            status = quest.get('status', '')
            can_complete = quest.get('canComplete', False)
            cooldown_remaining = quest.get('cooldownRemaining')
            progress = quest.get('progress', 0)
            max_progress = quest.get('maxProgress', 1)
            reward = quest.get('reward', 0)
            
            if status == 'cooldown' or cooldown_remaining:
                remaining = cooldown_remaining or 0
                return {'available': False, 'reason': f"Cooldown ({int(remaining)}s remaining)", 'quest': quest}
            
            if status == 'completed' or (max_progress > 0 and progress >= max_progress):
                return {'available': False, 'reason': f"Max completions reached ({progress}/{max_progress})", 'quest': quest}
            
            if can_complete or status == 'available':
                return {'available': True, 'completionCount': progress, 'maxCompletions': max_progress, 'points': reward, 'quest': quest}
            
            return {'available': False, 'reason': f"Status: {status}", 'quest': quest}
    
    return {'available': False, 'reason': 'Quest not found', 'quest': None}

# ======================= DISPLAY FUNCTIONS =======================
def display_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Fore.YELLOW} ___ ___  ___    _____  __  _ {Style.RESET_ALL}")
    print(f"{Fore.YELLOW}|   |   ||   \  |     ||  |/ ]{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}| _   _ ||    \ |   __||  ' / {Style.RESET_ALL}")
    print(f"{Fore.YELLOW}|  \_/  ||  D  ||  |_  |    \ {Style.RESET_ALL}")
    print(f"{Fore.YELLOW}|   |   ||     ||   _] |     |{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}|   |   ||     ||  |   |  .  |{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}|___|___||_____||__|   |__|\_| {Fore.CYAN}t.me/MDFKOfficial{Style.RESET_ALL}")
    print()
    print(f"{Fore.GREEN}SHADENETWORK{Style.RESET_ALL}")
    print()

def display_menu():
    accounts = get_accounts()
    proxies = load_proxies()
    
    print(f"{Fore.WHITE}🔑 Accounts: {len(accounts)} | 🌐 Proxies: {len(proxies)}{Style.RESET_ALL}")
    print()
    print(f"{Fore.WHITE} [1] Auto Register{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA} [2] Auto All Missions (Checkin + Onchain){Style.RESET_ALL}")
    print(f"{Fore.WHITE} [3] View Account Stats{Style.RESET_ALL}")
    print(f"{Fore.RED} [0] Exit{Style.RESET_ALL}")
    print()
    print()

def log(log_type, msg):
    icons = {'ok': '✓', 'err': '✗', 'warn': '⚠', 'info': '→'}
    colors = {'ok': Fore.GREEN, 'err': Fore.RED, 'warn': Fore.YELLOW, 'info': Fore.WHITE}
    print(f"{colors[log_type]}  {icons[log_type]} {msg}{Style.RESET_ALL}")

# ======================= FEATURE 1: AUTO REGISTER =======================
def handle_auto_register():
    print(f"\n{Fore.YELLOW}📝 AUTO REGISTER{Style.RESET_ALL}\n")
    
    accounts = get_accounts()
    
    if not accounts:
        log('err', f'No accounts found. Add private keys to {PRIVATEKEY_FILE}')
        return
    
    # Check registration status from API
    print(f"{Fore.WHITE}Checking registration status from API...{Style.RESET_ALL}")
    unregistered = []
    registered_count = 0
    proxies = load_proxies()
    
    for i, acc in enumerate(accounts):
        proxy_index = i % (len(proxies) if proxies else 1)
        proxy = proxies[proxy_index] if proxies else None
        proxy_dict = get_proxy_dict(proxy)
        
        user_info = get_user_info(acc['address'], acc['fingerprint'], proxy_dict)
        if user_info:
            registered_count += 1
        else:
            unregistered.append(acc)
    
    print(f"{Fore.WHITE}Total: {len(accounts)} | Registered: {registered_count} | Unregistered: {len(unregistered)}{Style.RESET_ALL}\n")
    
    if not unregistered:
        log('warn', 'All accounts already registered')
        return
    
    referral_code = input(f"{Fore.WHITE}Referral code: {Style.RESET_ALL}").strip()
    if not referral_code:
        referral_code = read_ref()
    
    print()
    success = 0
    failed = 0
    
    print(f"{Fore.WHITE}Loaded {len(proxies)} proxies | Delay: {DELAY_MIN_SECONDS}-{DELAY_MAX_SECONDS}s | Max retries: {MAX_RETRIES}{Style.RESET_ALL}\n")
    
    for i, acc in enumerate(unregistered):
        used_proxy_indices = []
        
        for attempt in range(MAX_RETRIES):
            if proxies:
                if attempt == 0:
                    proxy_index = i % len(proxies)
                else:
                    for idx in range(len(proxies)):
                        if idx not in used_proxy_indices:
                            proxy_index = idx
                            break
                    else:
                        proxy_index = random.randint(0, len(proxies) - 1)
                used_proxy_indices.append(proxy_index)
                proxy = proxies[proxy_index]
            else:
                proxy = None
            
            proxy_dict = get_proxy_dict(proxy)
            fingerprint = acc['fingerprint']
            proxy_info = f"{Fore.WHITE} [proxy{get_proxy_display(proxy)}]{Style.RESET_ALL}" if proxy else f"{Fore.WHITE} [local]{Style.RESET_ALL}"
            attempt_info = f"{Fore.YELLOW} [retry {attempt}/{MAX_RETRIES - 1}]{Style.RESET_ALL}" if attempt > 0 else ''
            
            print(f"{Fore.CYAN}[{i + 1}/{len(unregistered)}] {short_addr(acc['address'])}{proxy_info}{attempt_info}{Style.RESET_ALL}")
            
            nickname = generate_random_nickname()
            result = register_user_simple(acc['address'], nickname, referral_code, fingerprint, proxy_dict)
            
            if result.get('user'):
                log('ok', f"Registered as {Fore.WHITE}{result['user'].get('nickname', nickname)}{Fore.GREEN} | {result['user'].get('points', 0)} pts")
                success += 1
                break
            else:
                last_error = result.get('error', 'Registration failed')
                is_rate_limit = 'too many' in last_error.lower() or 'rate' in last_error.lower()
                
                if is_rate_limit and attempt < MAX_RETRIES - 1:
                    log('warn', f"{last_error} - retrying with different proxy...")
                elif attempt >= MAX_RETRIES - 1:
                    log('err', last_error)
                    failed += 1
                else:
                    log('warn', f"{last_error} - retrying...")
        
        if i < len(unregistered) - 1:
            delay = random.randint(DELAY_MIN_SECONDS, DELAY_MAX_SECONDS)
            print(f"{Fore.WHITE}⏳ Waiting {delay}s before next registration...{Style.RESET_ALL}\n")
            time.sleep(delay)
    
    print(f"\n{Fore.CYAN}✓ Done | Success: {success} | Failed: {failed}{Style.RESET_ALL}\n")

# ======================= FEATURE 2: AUTO ALL MISSIONS =======================
def handle_auto_all_missions():
    print(f"\n{Fore.YELLOW}🎯 AUTO ALL MISSIONS (Checkin + Onchain per Wallet){Style.RESET_ALL}\n")
    
    accounts = get_accounts()
    
    if not accounts:
        log('err', f'No accounts found. Add private keys to {PRIVATEKEY_FILE}')
        return
    
    # Check which accounts are registered
    print(f"{Fore.WHITE}Checking registration status...{Style.RESET_ALL}")
    registered_accounts = []
    proxies = load_proxies()
    
    for i, acc in enumerate(accounts):
        proxy_index = i % (len(proxies) if proxies else 1)
        proxy = proxies[proxy_index] if proxies else None
        proxy_dict = get_proxy_dict(proxy)
        
        user_info = get_user_info(acc['address'], acc['fingerprint'], proxy_dict)
        if user_info:
            acc['user_info'] = user_info
            registered_accounts.append(acc)
    
    if not registered_accounts:
        log('err', 'No registered accounts found')
        return
    
    print(f"{Fore.WHITE}Registered accounts: {len(registered_accounts)}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Flow: Checkin → Faucet → Unshield → Shield → Send → Next Wallet{Style.RESET_ALL}\n")
    
    checkin_claimed = 0
    checkin_already = 0
    checkin_failed = 0
    onchain_success = 0
    onchain_failed = 0
    total_pts = 0
    
    for i, acc in enumerate(registered_accounts):
        proxy_index = i % (len(proxies) if proxies else 1)
        proxy = proxies[proxy_index] if proxies else None
        proxy_dict = get_proxy_dict(proxy)
        fingerprint = acc['fingerprint']
        user_info = acc.get('user_info', {})
        nickname = user_info.get('nickname', short_addr(acc['address']))
        proxy_info = f"{Fore.WHITE} [proxy{get_proxy_display(proxy)}]{Style.RESET_ALL}" if proxy else f"{Fore.WHITE} [local]{Style.RESET_ALL}"
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[{i + 1}/{len(registered_accounts)}] {nickname}{proxy_info}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Check if already claimed today
        already_claimed_today = False
        last_claim = user_info.get('lastClaimAt')
        if last_claim:
            try:
                last_claim_date = datetime.fromisoformat(last_claim.replace('Z', '+00:00')).date()
                today = datetime.now(timezone.utc).date()
                if last_claim_date == today:
                    already_claimed_today = True
                    log('warn', f"Checkin: Already claimed today | {user_info.get('points', 0)} pts | Streak: {user_info.get('streak', 0)}")
                    checkin_already += 1
            except:
                pass
        
        # Create session
        print(f"{Fore.WHITE}  → Creating session...{Style.RESET_ALL}")
        session = create_session(acc['address'], acc['privateKey'], fingerprint, proxy_dict)
        if not session:
            log('err', 'Failed to create session')
            checkin_failed += 1
            continue
        
        token = session['token']
        
        # Daily checkin (only if not already claimed)
        if not already_claimed_today:
            print(f"{Fore.WHITE}  → Claiming daily...{Style.RESET_ALL}")
            claim_result = claim_daily(token, fingerprint, proxy_dict)
            
            if claim_result.get('success'):
                pts = claim_result.get('pointsEarned', 0)
                total_pts += pts
                checkin_claimed += 1
                log('ok', f"Checkin +{pts} pts | Total: {claim_result.get('newPoints', 0)} | Streak: {claim_result.get('streak', 0)}")
            elif claim_result.get('error') and 'already' in claim_result.get('error', '').lower():
                log('warn', f"Already claimed: {claim_result.get('error')}")
                checkin_already += 1
            else:
                log('err', f"Checkin failed: {claim_result.get('error', 'Unknown')}")
                checkin_failed += 1
        
        # ============ ONCHAIN MISSIONS ============
        print(f"\n{Fore.YELLOW}  📦 ONCHAIN MISSIONS{Style.RESET_ALL}")
        
        print(f"{Fore.WHITE}  → Creating wallet session...{Style.RESET_ALL}")
        wallet_session = create_wallet_session(acc['address'], acc['privateKey'], fingerprint, proxy_dict)
        if not wallet_session:
            log('err', 'Failed to create wallet session')
        else:
            wallet_token = wallet_session['token']
            
            # FAUCET
            faucet_quest = check_quest_available(token, QUEST_FAUCET, fingerprint, proxy_dict)
            if faucet_quest.get('available'):
                print(f"{Fore.WHITE}  → Claiming faucet...{Style.RESET_ALL}")
                captcha_token = solve_turnstile_captcha(fingerprint, proxy_dict)
                if captcha_token:
                    faucet_result = claim_faucet(acc['address'], captcha_token, fingerprint, proxy_dict)
                    if faucet_result.get('txHash') or faucet_result.get('success'):
                        tx_hash = faucet_result.get('txHash') or get_last_faucet_tx(acc['address'], wallet_token, fingerprint, proxy_dict)
                        if tx_hash:
                            # Wait for transaction to be confirmed
                            print(f"{Fore.WHITE}  → Waiting for confirmation...{Style.RESET_ALL}")
                            wait_for_tx_confirmation(tx_hash, max_wait_seconds=30, fingerprint=fingerprint, proxies=proxy_dict)
                            
                            # Now verify and complete quest
                            quest_result = verify_and_complete_quest(token, QUEST_FAUCET, tx_hash, fingerprint, proxy_dict)
                            if quest_result.get('success'):
                                pts = quest_result.get('pointsAwarded', 0)
                                total_pts += pts
                                onchain_success += 1
                                log('ok', f"Faucet quest +{pts} pts")
                            else:
                                log('warn', f"Faucet verify: {quest_result.get('error', 'Failed')}")
                        else:
                            log('warn', 'Faucet: No tx hash found')
                    else:
                        log('warn', f"Faucet: {faucet_result.get('error', 'Failed')}")
                else:
                    log('warn', 'Faucet: Captcha failed')
            else:
                log('warn', f"Faucet quest: {faucet_quest.get('reason', 'Not available')}")
            
            # UNSHIELD
            unshield_quest = check_quest_available(token, QUEST_UNSHIELD, fingerprint, proxy_dict)
            if unshield_quest.get('available'):
                print(f"{Fore.WHITE}  → Unshielding...{Style.RESET_ALL}")
                notes = get_notes(acc['address'], wallet_token, fingerprint, proxy_dict)
                available_notes = [n for n in notes.get('notes', []) if int(n.get('value', 0)) >= 100000000000000000]
                if available_notes:
                    note = available_notes[0]
                    unshield_result = do_unshield(acc['address'], acc['privateKey'], wallet_token, note, fingerprint, proxy_dict)
                    if unshield_result.get('txHash'):
                        # Wait for confirmation
                        print(f"{Fore.WHITE}  → Waiting for confirmation...{Style.RESET_ALL}")
                        wait_for_tx_confirmation(unshield_result['txHash'], max_wait_seconds=30, fingerprint=fingerprint, proxies=proxy_dict)
                        
                        quest_result = verify_and_complete_quest(token, QUEST_UNSHIELD, unshield_result['txHash'], fingerprint, proxy_dict)
                        if quest_result.get('success'):
                            pts = quest_result.get('pointsAwarded', 0)
                            total_pts += pts
                            onchain_success += 1
                            log('ok', f"Unshield quest +{pts} pts")
                        else:
                            log('warn', f"Unshield verify: {quest_result.get('error', 'Failed')}")
                    else:
                        log('warn', f"Unshield: {unshield_result.get('error', 'Failed')}")
                else:
                    log('warn', 'Unshield: No notes with >= 0.2 SHADE')
            else:
                log('warn', f"Unshield quest: {unshield_quest.get('reason', 'Not available')}")
            
            # SHIELD
            shield_quest = check_quest_available(token, QUEST_SHIELD, fingerprint, proxy_dict)
            if shield_quest.get('available'):
                print(f"{Fore.WHITE}  → Shielding 0.1 SHADE...{Style.RESET_ALL}")
                shield_result = do_shield(acc['address'], acc['privateKey'], 100000000000000000, fingerprint, proxy_dict)
                if shield_result.get('success') and shield_result.get('txHash'):
                    # Wait for confirmation
                    print(f"{Fore.WHITE}  → Waiting for confirmation...{Style.RESET_ALL}")
                    wait_for_tx_confirmation(shield_result['txHash'], max_wait_seconds=30, fingerprint=fingerprint, proxies=proxy_dict)
                    
                    quest_result = verify_and_complete_quest(token, QUEST_SHIELD, shield_result['txHash'], fingerprint, proxy_dict)
                    if quest_result.get('success'):
                        pts = quest_result.get('pointsAwarded', 0)
                        total_pts += pts
                        onchain_success += 1
                        log('ok', f"Shield quest +{pts} pts")
                    else:
                        log('warn', f"Shield verify: {quest_result.get('error', 'Failed')}")
                else:
                    log('warn', f"Shield: {shield_result.get('error', 'Failed')}")
            else:
                log('warn', f"Shield quest: {shield_quest.get('reason', 'Not available')}")
            
            # PRIVATE SEND
            send_quest = check_quest_available(token, QUEST_PRIVATE_SEND, fingerprint, proxy_dict)
            if send_quest.get('available'):
                print(f"{Fore.WHITE}  → Private send 0.01 SHADE...{Style.RESET_ALL}")
                notes = get_notes(acc['address'], wallet_token, fingerprint, proxy_dict)
                available_notes = [n for n in notes.get('notes', []) if int(n.get('value', 0)) >= 10000000000000000]
                if available_notes:
                    note = available_notes[0]
                    send_result = do_private_send(acc['address'], acc['privateKey'], acc['address'], 10000000000000000, note, fingerprint, proxy_dict)
                    if send_result.get('txHash'):
                        # Wait for confirmation
                        print(f"{Fore.WHITE}  → Waiting for confirmation...{Style.RESET_ALL}")
                        wait_for_tx_confirmation(send_result['txHash'], max_wait_seconds=30, fingerprint=fingerprint, proxies=proxy_dict)
                        
                        quest_result = verify_and_complete_quest(token, QUEST_PRIVATE_SEND, send_result['txHash'], fingerprint, proxy_dict)
                        if quest_result.get('success'):
                            pts = quest_result.get('pointsAwarded', 0)
                            total_pts += pts
                            onchain_success += 1
                            log('ok', f"Private send quest +{pts} pts")
                        else:
                            log('warn', f"Send verify: {quest_result.get('error', 'Failed')}")
                    else:
                        log('warn', f"Send: {send_result.get('error', 'Failed')}")
                else:
                    log('warn', 'Send: No notes with >= 0.01 SHADE')
            else:
                log('warn', f"Send quest: {send_quest.get('reason', 'Not available')}")
        
        print(f"\n{Fore.GREEN}✓ Wallet [{i + 1}] completed!{Style.RESET_ALL}")
        print()
        time.sleep(3)
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}✓ ALL DONE{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  Checkin: Claimed {checkin_claimed} | Already {checkin_already} | Failed {checkin_failed}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  Onchain: Success {onchain_success} | Failed {onchain_failed}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  Total Points: +{total_pts}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

# ======================= FEATURE 3: VIEW STATS =======================
def handle_view_stats():
    print(f"\n{Fore.YELLOW}📊 ACCOUNT STATS{Style.RESET_ALL}\n")
    
    accounts = get_accounts()
    
    if not accounts:
        log('err', f'No accounts found. Add private keys to {PRIVATEKEY_FILE}')
        return
    
    print(f"{Fore.WHITE}Fetching data from API...{Style.RESET_ALL}\n")
    
    total_points = 0
    registered_count = 0
    proxies = load_proxies()
    
    print(f"{Fore.WHITE}{'#':<4} {'Address':<20} {'Nickname':<20} {'Points':<10} {'Status':<15}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{'-'*70}{Style.RESET_ALL}")
    
    for acc in accounts:
        proxy_index = (acc['id'] - 1) % (len(proxies) if proxies else 1)
        proxy = proxies[proxy_index] if proxies else None
        proxy_dict = get_proxy_dict(proxy)
        
        user_info = get_user_info(acc['address'], acc['fingerprint'], proxy_dict)
        
        if user_info:
            status = f"{Fore.GREEN}Registered{Style.RESET_ALL}"
            nickname = user_info.get('nickname', '-')
            points = user_info.get('points', 0)
            total_points += points
            registered_count += 1
        else:
            status = f"{Fore.YELLOW}Not Registered{Style.RESET_ALL}"
            nickname = '-'
            points = 0
        
        print(f"{acc['id']:<4} {short_addr(acc['address']):<20} {nickname:<20} {points:<10} {status}")
    
    print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  Total Accounts: {len(accounts)}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  Registered: {registered_count}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  Total Points: {total_points}{Style.RESET_ALL}\n")

# ======================= MAIN FUNCTION =======================
def main():
    display_banner()
    
    while True:
        display_menu()
        choice = input(f"{Fore.WHITE}Select: {Style.RESET_ALL}").strip()
        
        if choice == '1':
            handle_auto_register()
        elif choice == '2':
            handle_auto_all_missions()
        elif choice == '3':
            handle_view_stats()
        elif choice == '0':
            print(f"\n{Fore.CYAN}Goodbye! 👋{Style.RESET_ALL}\n")
            break
        else:
            print(f"\n{Fore.RED}Invalid option{Style.RESET_ALL}\n")
        
        input(f"{Fore.WHITE}Press Enter...{Style.RESET_ALL}")
        display_banner()

if __name__ == "__main__":
    main()
