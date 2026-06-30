import os
from urllib import response
from flask import Flask, app, logging, session, url_for, make_response
from flask import render_template
from flask import request
from flask import redirect
from twilio.rest import Client
import time 
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from flask import jsonify
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_limiter import Limiter
import user_management as dbHandler
from flask_csp.csp import csp_header
import user_management as sanitiser
import logging


#logger = logging.getLogger(__name__)
#logging.basicConfig(filename='security_log.log', encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(message)s')
if __name__ == '__main__':
    print (f"Does 'password' meet security requirements: {sanitiser.simple_check_password("password")}" )
    #print (f"Make <HTML> web safe: {sanitiser.make_web_safe('<html>')}")
    #print (f"Is 'name@example.com' an email address: {sanitiser.check_email('name@example.com')}")
    #print (f"Is '123!' an name: {sanitiser.validate_name('123!')}")
    #print (f"Is '1234567890' a number: {sanitiser.validate_number('1234567890')}")
    #print ("--PYTHONIC EXCEPTION HANDLING--")
# Code snippet for logging a message
# app.logger.critical("message")
app = Flask(__name__)
csrf = CSRFProtect()
#c = CORS(api)
#app.config["CORS_HEADERS"] = "Content-Type"
app.config['SECRET_KEY'] = "UnsecurePWA"
app.config.update (
    #SESSION_COOKIE_SECURE = True,
    #SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = 'Lax',
)
#limiter = Limiter(
    #get_remote_address,
    #app=api,
    #default_limits=["200 per day", "50 per hour"],
    #storage_uri="memory://",
#)
app.config['MAX_LOGIN_ATTEMPTS'] = 3
#def csrf_app():
    #app = Flask(__name__)
    #csrf.init_app(app)


csrf.init_app(app)
# Enable CORS to allow cross-origin requests (needed for CSRF demo in Codespaces)
CORS(app)
#@app.route('/', methods=['POST', 'GET'])
#@app.route('/index.html', methods=['GET'])
@app.after_request
def security_headers(response):
        response.headers['Content-Security-Policy'] = ("base-uri 'self';"
        "default-src 'self';"
        "style-src 'self' https://fonts.googleapis.com;"
        "font-src 'self' https://fonts.gstatic.com;"
        "style-src-elem 'self' https://fonts.googleapis.com;"
        "script-src 'self';"
        "script-src-elem 'self';"
        #"img-src 'self ';"
        "media-src 'self';"
        "font-src 'self';"
        "object-src 'self';"
        "child-src 'self';"
        "connect-src 'self';"
        "worker-src 'self';"
        "report-uri /csp_report;"
        "frame-ancestors 'none';"
        "form-action 'self';"
        "base-uri 'self';"
        "frame-src 'none';"
)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
            
        
        

#@csp_header({
        #"base-uri": "self",
        #"default-src": "'self'",
        #"style-src": "'self' https://fonts.googleapis.com",
        #"font-src": "'self' https://fonts.gstatic.com",
        #"style-src-elem": "'self' https://fonts.googleapis.com",
        #"script-src": "'self'",
        #"script-src-elem": "'self'",
        #"img-src": "'self '",
        #"media-src": "'self'",
        #"font-src": "self",
        #"object-src": "'self'",
       # "child-src": "'self'",
       # "connect-src": "'self'",
       # "worker-src": "'self'",
        #"report-uri": "/csp_report",
       # "frame-ancestors": "'none'",
       # "form-action": "'self'",
       # "frame-src": "'none'",
      #}) 

@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    if not session.get("isloggedin"):
        return redirect(url_for("home"))
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":
        feedback = request.form["feedback"]
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        app.jinja_env.cache.clear()
        #return render_template("/success.html", state=True, value="Back", username=session.get("username"))
        return render_template("/success.html", state=True, value="Back")
    else:
        dbHandler.listFeedback()
        app.jinja_env.cache.clear()
        return render_template("/success.html", state=True, value="Back", username=session.get("username"))
        #return redirect(url_for("successful_login"))


@app.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def signup():
    # Check if user is already logged in to prevent the user from accessing the signup page unless they logout.
    #if request.method == "GET" and session.get("isloggedin") is True:
        #return redirect(url("successful_login"))
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":
        username = request.form["username"] 
        password = request.form["password"]
        DoB = request.form["dob"]
        try:
            _ = sanitiser.check_password(password).hex()
            if not sanitiser.simple_check_password(password):
                raise ValueError("Password does not meet security requirements.")
        except TypeError:
            #logger.error(f"Type errors for password:{password}")
            print(f"TypeError has been logged for password:{password}")
            #print("TypeError has been logged")
            return render_template("/signup.html", error="Invalid password type. Please enter a valid password.")
        except ValueError as inst: 
            #logger.error(f"Value errors for password:{password} with {inst.args}")
            print(f"ValueError has been logged for password:{password} with {str(inst)}")
            return render_template("/signup.html", error=f"Not a valid password because it has {str(inst)}. Please enter a valid password.")
        except Exception as inst:
            #logger.error(f"Unexpected error for password:{password} with {type(inst)}")
            print(f"Unexpected error has been logged for password:{password} with {type(inst)}")
            return render_template("/signup.html", error=f"An unexpected error occurred. Please enter a valid password.")
        dbHandler.insertUser(username, password, DoB)
        session.clear() # Clear the old cookie to prevent session fixation attacks.
        session["isloggedin"] = True
        session["username"] = username
        return render_template("/success.html", value= username,state="isLoggedIn", username=username)
        #return render_template("/index.html")
    else:
        return render_template("/signup.html")
    
#TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
#TWILIO_AUTH_TOKEN= os.environ.get('TWILIO_AUTH_TOKEN')
#TWILIO_VERIFY_SERVICE = os.environ.get('TWILIO_VERIFY_SERVICE')
#SENDGRID_API_KEY= os.environ.get('SENDGRID_API_KEY') 

#client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

#@app.route('/', methods=['GET', 'POST'])
#def login():
    #if request.method == 'POST':
        #to_email = request.form['email']
        #session['to_email'] = to_email
        #send_verification(to_email)
        #return redirect(url_for('generate_verification_code'))
    #return render_template('index.html')

#def send_verification(to_email):
    #verification = client.verify \
    #    .services(TWILIO_VERIFY_SERVICE) \
        #.verifications \
        #.create(to=to_email, channel='email')
    #print(verification.sid)

#@app.route("/verifyme", methods=['GET', 'POST'])
#def generate_verification_code():
    #to_email = session['to_email']
    #error = None
    #if request.method == 'POST':
        #verification_code = request.form['verificationcode']
        #if check_verification_token(to_email, verification_code):
            #print("Successful code")
            #return render_template('success.html', email = to_email)
            #return ('Success')
        #else:
        error = "Invalid verification code. Please try again."
            #return render_template('verifypage.html', error = error)
    #return render_template('verifypage.html', email = to_email)

#def check_verification_token(phone, token):
    #check = client.verify \
        #.services(TWILIO_VERIFY_SERVICE) \
        #.verification_checks \
        #.create(to=phone, code=token)    
    #return check.status == 'approved'


@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
def home():
    # Simple Dynamic menu
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    # Pass message to front end
    elif request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("/index.html", msg=msg)
    elif request.method == "POST":
        current_time = time.time() # The current time in seconds when the user logins.
        end_time = 60 # The time in seconds that the user will be locked out for.
        # If failed login attempts exceed the maximum limit, lock the user out for the specific time and record the time since the user was locked out.
        if 'login_attempts' in session and session.get("login_attempts") >= app.config['MAX_LOGIN_ATTEMPTS']:
            lockedout = session.get("lockedout", 0)
            time_since_lockedout = current_time - lockedout
            # If the user is still locked out, return the error message. Otherwise, reset the login attempts and lockedout status so the user is not locked out anymore.
            if time_since_lockedout < end_time:
             return render_template("/index.html", msg=f"Too many login attempts. Please try again later.")
            else:
                session["login_attempts"] = 0
                session.pop("lockedout", None)
        username = request.form["username"]
        password = request.form["password"]
        try:
            if not isinstance(username, str) or not isinstance(password, str):
                raise TypeError("Username and password must be strings.")
        except TypeError as inst:
            #logger.error(f"Type errors for username:{username} or password:{password} with {inst.args}")
            return render_template("/index.html", msg="Invalid input type. Please enter valid credentials.") # Return an error message to the user 
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        # If the user is logged in, set the session variables and reset the login attempts and lockedout status. Else, increment the login attempts and check if the user has exceeded the maximum login attempts. If the user has exceeded it then lock the user out. 
        if isLoggedIn:
            session.clear() # Clear the old cookie completely to prevent session fixation attacks
            session["isloggedin"] = True # Set the session variable to indicate that the user has logged in successfully.
            session["username"] = username # Set the session variable to store the username of the logged in user. 
            session["login_attempts"] = 0 # Reset login attempts to 0 upon a successful login
            session.pop("lockedout", None) # Reset lockedout status upon a successful login
            dbHandler.listFeedback() # Show the feedback after successfully logging in.
            #return render_template("/success.html", value=username, state=isLoggedIn) 
            return redirect(url_for("successful_login")) # Redirect the user to the login page after successfully logging in
        
        else:
            session["login_attempts"] = session.get("login_attempts", 0 ) + 1
            if session.get("login_attempts") >= app.config['MAX_LOGIN_ATTEMPTS']:
                session["lockedout"] = current_time
                return render_template("/index.html", msg="Too many login attempts. Please try again later.")
            remaining_attempts = app.config["MAX_LOGIN_ATTEMPTS"] - session.get("login_attempts")
            return render_template("/index.html", msg=f"Invalid username or password. You have {remaining_attempts} attempts remaining.")
    else:
        session.clear()
        return render_template("/index.html")

@app.route("/successful_login", methods=["GET"])
def successful_login():
    # Check if the user is logged in before redirecting to the feedback page. If the user is not logged in, redirect them to the login page. Prevents users from accessing the feedback page without logging in first.
    if session.get("isloggedin") is not True:  
        return redirect(url_for("home"))
    return render_template("/success.html", value=session.get("username"), state=True)
# Logout route to clear the session data and log the user out
@app.route("/logout", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def logout():
     session.clear() # Clear the session data to log the user out
     #session.modified = True 
     response = make_response(redirect(url_for("home")))
     #return redirect(url_for("home")) # Redirect the user to the login page after logging out
     response.set_cookie('session', '', expires=0, max_age=0)  
     return response


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
    #ssl_context="adhoc"
