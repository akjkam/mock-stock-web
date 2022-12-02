import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Import lookup function to html
app.jinja_env.globals.update(lookup=lookup)

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    portfolio = db.execute("SELECT symbol,stock,shares,price,total FROM portfolio WHERE id = ?", session["user_id"])

    leng = db.execute("SELECT COUNT(*) FROM portfolio WHERE id = ?", session["user_id"])
    length = leng[0]["COUNT(*)"]
    c = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = (c[0]["cash"])
    runningtotal = db.execute("SELECT SUM(total) as totals FROM portfolio WHERE id = ?", session["user_id"])
    if runningtotal[0]["totals"] == None:
        totalforall = 0
    else:
        totalforall = float(runningtotal[0]["totals"]) + cash
    totalforall += cash
    return render_template("index.html", sumtotal = totalforall, cash = cash, portfolio = portfolio, length = length)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)
        if not request.form.get("shares"):
            return apology("must provide number of shares", 403)
        if int(request.form.get("shares")) <= 0:
            return apology("must provide a positive number of shares", 403)
        symbol = request.form.get("symbol")
        shares = float(request.form.get("shares"))
        stock = lookup(symbol)
        if stock == None:
            return apology("symbol does not exist", 403)
        price = float(stock["price"])
        userid = session["user_id"]
        name = stock["name"]
        total = price*(float(shares))
        result = db.execute("SELECT cash FROM users WHERE id = ?", userid)
        cash = result[0]["cash"]
        if cash < price*shares:
            return apology("Not enough cash", 403)
        rows = db.execute("SELECT COUNT(*) FROM portfolio WHERE stock = ? AND id = ?", name, userid)
        row = rows[0]["COUNT(*)"]
        if row == 1:
            totalshares = db.execute("SELECT shares FROM portfolio WHERE stock = ? AND id = ?", name, userid)
            totals = totalshares[0]["shares"]
            shares1 = shares + totals
            totalp = db.execute("SELECT total FROM portfolio WHERE stock = ? AND id = ?", name, userid)
            totalprice = totalp[0]["total"]
            totalprice += total
            db.execute("UPDATE portfolio SET total = ? WHERE id = ? and stock = ?", totalprice, userid, name)
            db.execute("UPDATE portfolio SET shares = ? WHERE id = ? AND stock = ?", shares1, userid, name)
            db.execute("UPDATE portfolio SET price = ? WHERE id = ? AND stock = ?", price, userid, name)

        else:
            db.execute("INSERT INTO portfolio (id, symbol, stock, shares, price, total) VALUES (?,?,?,?,?,?)", userid, symbol, name, shares, price, total)
        date = db.execute("SELECT CURRENT_TIMESTAMP")
        time = date[0]["CURRENT_TIMESTAMP"]
        db.execute("INSERT INTO transactions (id, symbol, stock, shares, price, total, time) VALUES (?,?,?,?,?,?,?)", userid, symbol, name, shares, price, -total, time)
        remainder = float(cash) - total
        db.execute("UPDATE users SET cash = ? WHERE id = ?", remainder, userid)
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    transactions = db.execute("SELECT symbol, shares, price, time FROM transactions WHERE id = ?", session["user_id"])
    result = db.execute("SELECT COUNT(*) FROM transactions WHERE id = ?", session["user_id"])
    length = result[0]["COUNT(*)"]
    return render_template("history.html", transactions = transactions, length = length)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if symbol.isalpha() != True:
            return apology("Not a valid symbol", 400)
        stocks = lookup(symbol)
        if stocks == None:
            return apology("Stock does not exist", 400)
        stockname = stocks["name"]
        stockprice = stocks["price"]
        stocksymbol = stocks["symbol"]
        return render_template("quoted.html", name = stockname, price = stockprice, symbol = stocksymbol)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure username isn't taken
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(rows) == 1:
            return apology("username taken", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure passwords inputted match up
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 400)

        # Insert user into users table
        username = request.form.get("username")
        password = generate_password_hash(request.form.get("password"), method="pbkdf2:sha256", salt_length=8)
        db.execute("INSERT INTO users (username, hash) VALUES (?,?)", username, password)

        # Redirect user to login
        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Must select a stock", 403)
        symbol = request.form.get("symbol")
        answer = lookup(symbol)
        name = answer["name"]
        own = db.execute("SELECT COUNT(*) FROM portfolio WHERE id = ? AND symbol = ?", session["user_id"], symbol)
        owned = own[0]["COUNT(*)"]
        if owned != 1:
            return apology("User does not own stock", 403)
        shares = int(request.form.get("shares"))
        if shares <= 0:
            return apology("Amount of shares must be greater than 0", 403)
        result = db.execute("SELECT shares FROM portfolio WHERE id = ? AND symbol = ?", session["user_id"], symbol)
        usershares = result[0]["shares"]
        if usershares < shares:
            return apology("Not enough shares to sell", 403)
        remainder = usershares - shares
        results = lookup(symbol)
        currentprice = results["price"]
        total = currentprice*float(remainder)
        db.execute("UPDATE portfolio SET shares = ?, total = ? WHERE id = ? AND symbol = ?", remainder, total, session["user_id"], symbol)
        add = float(shares)*currentprice
        current = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = float(current[0]["cash"]) + add
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])
        date = db.execute("SELECT CURRENT_TIMESTAMP")
        time = date[0]["CURRENT_TIMESTAMP"]
        db.execute("INSERT INTO transactions (id, symbol, stock, shares, price, total, time) VALUES (?,?,?,?,?,?,?)", session["user_id"], symbol, name, -shares, currentprice, total, time)
        return redirect("/")

    else:
        symbols = db.execute("SELECT symbol FROM portfolio WHERE id = ?", session["user_id"])
        leng = db.execute("SELECT COUNT(*) FROM portfolio WHERE id = ?", session["user_id"])
        length = leng[0]["COUNT(*)"]
        return render_template("sell.html", symbols = symbols, length = length)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
