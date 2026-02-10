# Shade Network Auto Bot 🚀

A powerful Python automation bot for Shade Network that handles account registration, daily check-ins, and automated onchain mission completion.

## � Important Links

- **Registration**: [https://v1.shadenetwork.io/ref/saygie](https://v1.shadenetwork.io/ref/saygie)
- **SCTG API Key** (Captcha Solver): [Get API Key via Telegram](https://t.me/Xevil_check_bot?start=6324725993)

## �📋 Features

### 1. **Auto Registration**
- Automatically registers new wallets to the Shade Network platform
- Supports referral codes for bonus points
- Multi-proxy support with automatic rotation
- Random nickname generation
- Retry mechanism for failed registrations

### 2. **Auto All Missions**
Complete workflow per wallet:
- ✅ **Daily Check-in** - Automatic daily points claim
- 💧 **Faucet Quest** - Request testnet tokens with captcha solving
- 🔓 **Unshield Quest** - Unshield 0.2 SHADE from private balance
- 🛡️ **Shield Quest** - Shield 0.1 SHADE to private balance
- 📨 **Private Send Quest** - Send 0.01 SHADE privately

### 3. **Account Stats Viewer**
- View all account statistics
- Check registration status
- Monitor total points across all wallets
- Display nicknames and balances

## 🛠️ Requirements

### Python Dependencies

```bash
pip install requests eth-account colorama web3
```

**Required packages:**
- `requests` - HTTP requests
- `eth-account` - Ethereum wallet management
- `colorama` - Colored terminal output
- `web3` - Blockchain interactions

### System Requirements
- Python 3.8+
- Internet connection
- Valid Ethereum private keys

## 📁 File Structure

```
SHADENETWORK/
├── main.py              # Main bot script
├── privatekey.txt       # Your private keys (one per line)
├── proxy.txt            # Proxy list (optional)
├── reff.txt             # Default referral code (optional)
├── state.json           # Bot state data
├── wallet.json          # Wallet data cache
└── README.md            # This file
```

## ⚙️ Configuration

### 1. **Private Keys Setup**
Create `privatekey.txt` and add your private keys (one per line):

```
0x1234567890abcdef...
0xabcdef1234567890...
```

> ⚠️ **IMPORTANT**: Never share your private keys! Keep this file secure.

### 2. **Proxy Setup (Optional)**
Create `proxy.txt` with proxy addresses:

```
http://user:pass@ip:port
http://ip:port
```

### 3. **Referral Code (Optional)**
Create `reff.txt` with your referral code:

```
your_referral_code
```

Default referral code: `saygie`

## 🚀 Usage

### Running the Bot

```bash
python main.py
```

### Menu Options

```
 [1] Auto Register              - Register new accounts
 [2] Auto All Missions          - Daily checkin + Onchain missions
 [3] View Account Stats         - Check account information
 [0] Exit                       - Quit the program
```

## 📊 Onchain Mission Flow

Each wallet executes missions in this order:

1. **Daily Check-in** → Claim daily rewards
2. **Faucet** → Get testnet tokens (requires captcha solving)
3. **Unshield** → Convert shielded tokens to public balance
4. **Shield** → Convert public tokens to shielded balance
5. **Private Send** → Send tokens privately

## 🔧 Technical Details

### API Endpoints

- **Points API**: `https://points.shadenetwork.io`
- **Main API**: `https://v1.shadenetwork.io`
- **Wallet API**: `https://wallet.shadenetwork.io`
- **RPC**: `https://rpc.shadenetwork.io`

### Network Details

- **Chain ID**: 271828
- **Shield Contract**: `0x9FDB75BeE75A924D78Fbd35859d7957609d997bB`

### Quest IDs

- `onchain_001` - Shield Quest
- `onchain_002` - Unshield Quest
- `onchain_003` - Private Send Quest
- `onchain_004` - Faucet Quest

## 🎯 Features Breakdown

### Fingerprint Generation
Generates randomized browser fingerprints for anti-detection:
- Random Chrome versions (120-144)
- Multiple platforms (Windows, Linux, macOS)
- Various language settings
- Realistic user agents

### Captcha Solving
- Automatic Cloudflare Turnstile captcha solving
- Uses SCTG external captcha solving service
- Get your API key: [SCTG Telegram Bot](https://t.me/Xevil_check_bot?start=6324725993)
- Configured for wallet.shadenetwork.io
- API key is already configured in the script: `QtU4iNokqmOXpOfzGUwVsxwOdJp4ZX6d`

### Quest Availability Check
Automatically checks before executing missions:
- ✅ Quest status (available/cooldown/completed)
- ⏰ Cooldown remaining time
- 📊 Progress tracking
- 🎁 Reward points

### Transaction Management
- Automatic transaction signing
- Transaction confirmation polling
- Receipt verification
- Error handling and retries

## 📈 Statistics & Monitoring

The bot provides detailed statistics:
- Total accounts loaded
- Registration status
- Points earned per mission
- Success/failure counts
- Cooldown tracking

## ⚙️ Advanced Configuration

### Timing Settings

```python
DELAY_MIN_SECONDS = 5     # Minimum delay between registrations
DELAY_MAX_SECONDS = 10    # Maximum delay between registrations
MAX_RETRIES = 3           # Maximum retry attempts
```

### Transaction Amounts

- **Unshield**: 0.2 SHADE minimum (200000000000000000 wei)
- **Shield**: 0.1 SHADE (100000000000000000 wei)
- **Private Send**: 0.01 SHADE (10000000000000000 wei)

## 🛡️ Security Features

- ✅ Private message signing for authentication
- ✅ EIP-712 typed data signing for transactions
- ✅ Session token management
- ✅ Proxy support for IP rotation
- ✅ Fingerprint randomization

## 🐛 Troubleshooting

### Common Issues

**"No accounts found"**
- Check if `privatekey.txt` exists and contains valid private keys
- Ensure keys start with `0x` or add them automatically

**"Failed to create session"**
- Check internet connection
- Verify proxy settings
- Ensure private key is valid

**"Quest not available"**
- Quest may be on cooldown
- Maximum completions reached
- Check quest status in stats viewer

**"Captcha failed"**
- Captcha service may be down
- Check API key configuration
- Try again later

## 📝 Notes

- The bot automatically rotates proxies for multiple accounts
- Each wallet completes missions sequentially
- Cooldowns are checked before attempting missions
- Failed transactions are logged but don't stop the flow
- All transactions are signed locally for security

## ⚠️ Disclaimer

This bot is for educational purposes only. Use at your own risk. Always:
- Keep your private keys secure
- Use testnet tokens only
- Follow platform terms of service
- Don't spam or abuse the system

## 🤝 Support

For issues or questions:
- Check the troubleshooting section
- Review the code comments
- Verify your configuration files

---

**Made with ❤️ for the Shade Network community**
