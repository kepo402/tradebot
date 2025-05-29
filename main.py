import logging
import asyncio
import time
import hashlib
import json
from datetime import datetime, timedelta
from telegram import Update, ReplyKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes, ConversationHandler

# Try to import optional libraries
try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    import yfinance as yf
except ImportError:
    yf = None

# Logging config
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
# Replace this with your real token
TOKEN = '7292232859:AAGTLITHJ_s3s-imNdg_OXXlwvIYX8PE4tA'

# Authentication states for conversation handler
USERNAME, PASSWORD = range(2)


def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()


# Generate correct password hashes
print("Generating password hashes...")
print(f"'pass1word!' hash: {hash_password('pass1word!')}")
print(f"'mySecureP@ss' hash: {hash_password('mySecureP@ss')}")

# Simple user database (in production, use a real database)
# Fixed password hashes - regenerated correctly
USERS_DB = {
    "user1": {
        "password_hash": hash_password("pass1word!"),  # Generate hash dynamically
        "active": True
    },
    "user2": {
        "password_hash": hash_password("mySecureP@ss"),  # Generate hash dynamically
        "active": True
    }
}

# Store authenticated users (user_id -> username)
authenticated_users = {}

# Session timeout (30 minutes)
SESSION_TIMEOUT = 30 * 60
user_sessions = {}

# Rate limiting and caching - optimized for better user experience
user_last_request = {}
RATE_LIMIT_SECONDS = 5  # Reduced since we're using faster APIs and mock data
stock_cache = {}
CACHE_DURATION = 900  # Increased to 15 minutes for better caching


def is_authenticated(user_id):
    """Check if user is authenticated and session is still valid"""
    if user_id not in authenticated_users:
        return False

    if user_id in user_sessions:
        last_activity = user_sessions[user_id]
        if (datetime.now() - last_activity).total_seconds() > SESSION_TIMEOUT:
            # Session expired
            del authenticated_users[user_id]
            del user_sessions[user_id]
            return False

    # Update last activity
    user_sessions[user_id] = datetime.now()
    return True


def verify_credentials(username, password):
    """Verify username and password with detailed logging"""
    print(f"Attempting to verify credentials for username: '{username}'")

    if username not in USERS_DB:
        print(f"Username '{username}' not found in database")
        return False

    user_data = USERS_DB[username]
    input_password_hash = hash_password(password)
    stored_password_hash = user_data["password_hash"]

    print(f"Input password hash: {input_password_hash}")
    print(f"Stored password hash: {stored_password_hash}")
    print(f"Hashes match: {input_password_hash == stored_password_hash}")
    print(f"User active: {user_data['active']}")

    return (input_password_hash == stored_password_hash and user_data["active"])


# Authentication conversation handlers
async def start_login(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start the login process"""
    user_id = update.effective_user.id

    if is_authenticated(user_id):
        await update.message.reply_text(
            f"✅ You're already logged in as {authenticated_users[user_id]}!\n"
            "Use /price <ticker> to get stock prices."
        )
        return ConversationHandler.END

    await update.message.reply_text(
        "🔐 **StockBot Authentication Required**\n\n"
        "Please enter your username:",
        parse_mode='Markdown'
    )
    return USERNAME


async def get_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle username input"""
    username = update.message.text.strip()
    context.user_data['username'] = username

    print(f"Received username: '{username}'")

    await update.message.reply_text(
        f"👤 Username: {username}\n"
        "🔑 Now enter your password:"
    )
    return PASSWORD


async def get_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle password input and authenticate"""
    password = update.message.text.strip()
    username = context.user_data.get('username')
    user_id = update.effective_user.id

    print(f"Received password for user '{username}': '{password}'")

    # Delete the password message for security
    try:
        await update.message.delete()
    except Exception as e:
        print(f"Could not delete password message: {e}")

    if verify_credentials(username, password):
        # Authentication successful
        authenticated_users[user_id] = username
        user_sessions[user_id] = datetime.now()

        keyboard = [['📈 Get Stock Price', '📊 My Account'], ['🚪 Logout']]
        reply_markup = ReplyKeyboardMarkup(keyboard, one_time_keyboard=False, resize_keyboard=True)

        await update.message.reply_text(
            f"✅ **Login Successful!**\n"
            f"Welcome back, {username}!\n\n"
            f"🕐 Session expires in 30 minutes\n"
            f"📱 Use the buttons below or type commands:",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
        return ConversationHandler.END
    else:
        await update.message.reply_text(
            "❌ **Authentication Failed**\n"
            "Invalid username or password.\n\n"
            "**Valid credentials:**\n"
            "• Username: `user1` Password: `pass1word!`\n"
            "• Username: `user2` Password: `mySecureP@ss`\n\n"
            "Try /login again or contact admin.",
            parse_mode='Markdown'
        )
        return ConversationHandler.END


async def cancel_login(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Cancel login process"""
    await update.message.reply_text(
        "❌ Login cancelled.\nUse /login to try again.",
        reply_markup=ReplyKeyboardRemove()
    )
    return ConversationHandler.END


# Main bot commands (protected)
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command - shows different message based on auth status"""
    user_id = update.effective_user.id

    if is_authenticated(user_id):
        username = authenticated_users[user_id]
        await update.message.reply_text(
            f"👋 Welcome back, {username}!\n\n"
            "🔹 /price <ticker> - Get stock price\n"
            "🔹 /account - View account info\n"
            "🔹 /logout - End session"
        )
    else:
        await update.message.reply_text(
            "👋 **Welcome to Authenticated StockBot!**\n\n"
            "🔐 You need to login first:\n"
            "• Use /login to authenticate\n\n"
            "📝 **Demo Accounts:**\n"
            "• Username: `user1` Password: `pass1word!`\n"
            "• Username: `user2` Password: `mySecureP@ss`",
            parse_mode='Markdown'
        )


async def fetch_stock_data_advanced(ticker):
    """Advanced stock data fetching with multiple reliable sources"""

    # Method 1: Try free financial APIs first (no rate limiting issues)
    try:
        if aiohttp:
            print(f"Trying free financial API for {ticker}...")

            # Try Yahoo Finance alternative API
            url = f"https://query1.finance.yahoo.com/v8/finance/chart/{ticker}"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'chart' in data and 'result' in data['chart'] and data['chart']['result']:
                            result = data['chart']['result'][0]
                            if 'meta' in result and 'regularMarketPrice' in result['meta']:
                                price = result['meta']['regularMarketPrice']
                                return price, "Yahoo Finance API", None

    except Exception as e:
        print(f"Yahoo Finance API failed: {e}")

    # Method 2: Try Polygon.io free tier
    try:
        if aiohttp:
            print(f"Trying Polygon.io for {ticker}...")
            # Free tier allows 5 calls per minute
            url = f"https://api.polygon.io/v2/aggs/ticker/{ticker}/prev?apikey=demo"

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'results' in data and data['results']:
                            price = data['results'][0]['c']  # closing price
                            return price, "Polygon.io", None

    except Exception as e:
        print(f"Polygon.io failed: {e}")

    # Method 3: Try Alpha Vantage with demo key
    try:
        if aiohttp:
            print(f"Trying Alpha Vantage for {ticker}...")
            url = f"https://www.alphavantage.co/query?function=GLOBAL_QUOTE&symbol={ticker}&apikey=demo"

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        if "Global Quote" in data and data["Global Quote"]:
                            quote = data["Global Quote"]
                            if "05. price" in quote:
                                price = float(quote["05. price"])
                                return price, "Alpha Vantage", None

    except Exception as e:
        print(f"Alpha Vantage failed: {e}")

    # Method 4: Try yfinance as last resort (with single attempt)
    if yf:
        try:
            print(f"Last resort: Trying yfinance for {ticker}...")
            stock = yf.Ticker(ticker)

            # Try getting info first (faster than history)
            info = stock.info
            if 'regularMarketPrice' in info:
                price = info['regularMarketPrice']
                return price, "yfinance (info)", "⚠️ Limited data source"
            elif 'currentPrice' in info:
                price = info['currentPrice']
                return price, "yfinance (info)", "⚠️ Limited data source"

        except Exception as e:
            print(f"yfinance failed: {e}")

    # Method 5: Enhanced mock data with realistic prices
    print(f"Using mock data for {ticker}...")
    import random
    from datetime import datetime

    # More comprehensive mock data with realistic current prices
    mock_prices = {
        # Tech giants
        "AAPL": 175.00, "GOOGL": 125.00, "GOOG": 127.00, "MSFT": 350.00,
        "AMZN": 145.00, "META": 315.00, "TSLA": 185.00, "NVDA": 450.00,
        # Other popular stocks
        "NFLX": 425.00, "UBER": 65.00, "SPOT": 250.00, "ZOOM": 70.00,
        "PYPL": 75.00, "SQ": 85.00, "ROKU": 55.00, "TWTR": 45.00,
        # Traditional stocks
        "JNJ": 165.00, "PG": 155.00, "KO": 60.00, "PEP": 180.00,
        "WMT": 155.00, "HD": 320.00, "V": 250.00, "MA": 380.00,
        # Crypto-related
        "COIN": 95.00, "MSTR": 1250.00,
        # ETFs
        "SPY": 420.00, "QQQ": 370.00, "IWM": 195.00, "VTI": 240.00
    }

    if ticker in mock_prices:
        base_price = mock_prices[ticker]
        # Add realistic daily variation (+/- 3%)
        variation = random.uniform(-0.03, 0.03)
        mock_price = base_price * (1 + variation)

        # Add timestamp for realism
        timestamp = datetime.now().strftime('%H:%M:%S')

        return mock_price, "Demo Data", f"🎭 Simulated price (updated {timestamp})"

    # Generic price for unknown tickers
    generic_price = random.uniform(50.0, 500.0)
    return generic_price, "Demo Data", f"🎭 Generic simulated price for {ticker}"


async def price(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Get stock price - requires authentication"""
    user_id = update.effective_user.id

    if not is_authenticated(user_id):
        await update.message.reply_text(
            "🔒 **Authentication Required**\n"
            "Please use /login first to access stock prices.",
            parse_mode='Markdown'
        )
        return

    # Rate limiting check
    is_limited, wait_time = is_rate_limited(user_id)
    if is_limited:
        await update.message.reply_text(
            f"⏳ Please wait {wait_time:.1f} more seconds before making another request."
        )
        return

    if not context.args:
        await update.message.reply_text(
            "❗ Please use the format: /price <TICKER>\n"
            "Example: /price AAPL"
        )
        return

    ticker = context.args[0].upper()
    username = authenticated_users[user_id]

    # Log the request
    logging.info(f"User {username} requested price for {ticker}")

    # Check cache first
    cached_data = get_cached_price(ticker)
    if cached_data:
        price, source, warning = cached_data
        message = f"📈 **{ticker}**: ${price:.2f}\n�� Cached data from {source}\n👤 Requested by: {username}"
        if warning:
            message += f"\n{warning}"

        await update.message.reply_text(message, parse_mode='Markdown')
        return

    # Fetch new data with improved error handling
    status_msg = await update.message.reply_text(f"🔍 Fetching {ticker} price...")

    try:
        price, source, warning = await fetch_stock_data_advanced(ticker)

        if price is not None:
            cache_price(ticker, price, source, warning)

            message = (f"📈 **{ticker}**: ${price:.2f}\n"
                       f"📊 Source: {source}\n"
                       f"👤 Requested by: {username}\n"
                       f"🕐 {datetime.now().strftime('%H:%M:%S')}")

            if warning:
                message += f"\n{warning}"

            await status_msg.edit_text(message, parse_mode='Markdown')
        else:
            await status_msg.edit_text(
                f"❌ **Unable to fetch {ticker}**\n"
                f"💡 **Try:**\n"
                f"• Check if ticker symbol is correct\n"
                f"• Popular tickers: AAPL, GOOGL, MSFT, TSLA\n"
                f"• Wait a moment and try again",
                parse_mode='Markdown'
            )

    except Exception as e:
        logging.error(f"Unexpected error fetching {ticker} for user {username}: {e}")
        await status_msg.edit_text(
            f"⚠️ **Unexpected Error**\n"
            f"Please try again in a few minutes.\n"
            f"If the problem persists, contact admin.",
            parse_mode='Markdown'
        )


async def account_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show account information"""
    user_id = update.effective_user.id

    if not is_authenticated(user_id):
        await update.message.reply_text("🔒 Please login first with /login")
        return

    username = authenticated_users[user_id]
    session_start = user_sessions[user_id]
    session_duration = datetime.now() - session_start
    time_left = SESSION_TIMEOUT - session_duration.total_seconds()

    await update.message.reply_text(
        f"👤 **Account Information**\n\n"
        f"🏷️ Username: {username}\n"
        f"🕐 Session started: {session_start.strftime('%H:%M:%S')}\n"
        f"⏱️ Time remaining: {int(time_left / 60)} minutes\n"
        f"🆔 User ID: {user_id}",
        parse_mode='Markdown'
    )


async def logout(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Logout user"""
    user_id = update.effective_user.id

    if user_id in authenticated_users:
        username = authenticated_users[user_id]
        del authenticated_users[user_id]
        if user_id in user_sessions:
            del user_sessions[user_id]

        await update.message.reply_text(
            f"👋 Goodbye, {username}!\n"
            f"✅ You have been logged out successfully.\n"
            f"Use /login to authenticate again.",
            reply_markup=ReplyKeyboardRemove()
        )
    else:
        await update.message.reply_text("❌ You weren't logged in.")


# Helper functions
def is_rate_limited(user_id):
    now = datetime.now()
    if user_id in user_last_request:
        time_since_last = (now - user_last_request[user_id]).total_seconds()
        if time_since_last < RATE_LIMIT_SECONDS:
            return True, RATE_LIMIT_SECONDS - time_since_last
    user_last_request[user_id] = now
    return False, 0


def get_cached_price(ticker):
    if ticker in stock_cache:
        cached_data, timestamp = stock_cache[ticker]
        if (datetime.now() - timestamp).total_seconds() < CACHE_DURATION:
            return cached_data
    return None


def cache_price(ticker, price, source, warning=None):
    stock_cache[ticker] = ((price, source, warning), datetime.now())


# Button handlers
async def handle_buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle keyboard button presses"""
    text = update.message.text

    if text == "📈 Get Stock Price":
        await update.message.reply_text(
            "📊 Enter stock ticker:\n"
            "Format: /price <TICKER>\n"
            "Example: /price AAPL"
        )
    elif text == "📊 My Account":
        await account_info(update, context)
    elif text == "🚪 Logout":
        await logout(update, context)


def main():
    """Main function to run the bot"""
    app = ApplicationBuilder().token(TOKEN).build()

    # Login conversation handler
    login_handler = ConversationHandler(
        entry_points=[CommandHandler("login", start_login)],
        states={
            USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_username)],
            PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_password)],
        },
        fallbacks=[CommandHandler("cancel", cancel_login)],
    )

    # Add handlers
    app.add_handler(login_handler)
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("price", price))
    app.add_handler(CommandHandler("account", account_info))
    app.add_handler(CommandHandler("logout", logout))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_buttons))

    print("✅ Authenticated StockBot is running...")
    print("Demo accounts:")
    print("- user1 / pass1word!")
    print("- user2 / mySecureP@ss")
    print("\nPassword hashes in database:")
    for username, data in USERS_DB.items():
        print(f"- {username}: {data['password_hash']}")

    app.run_polling()


if __name__ == '__main__':
    main()
