import os
from urllib import response
from flask import Flask, app,logging, session, url_for, session, render_template, request, redirect, make_response
from flask_session import Session
#from flask import render_template
#from flask import request
#from flask import redirect
#from twilio.rest import Client
import time 
from pathlib import Path
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from flask import jsonify
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_limiter import Limiter
import pyotp
import user_management as dbHandler
#from flask_csp.csp import csp_header
import user_management as sanitiser

api = Flask(__name__) # Create a flask application 
csrf = CSRFProtect() # Initialise CSRF protection for the Flask progressive web application to prevent cross-site request forgery attacks by ensuring that requests made to the server are from authenticated users.
#c = CORS(api)
#app.config["CORS_HEADERS"] = "Content-Type"
api.config['SECRET_KEY'] = "UnsecurePWA" # Secret key for session management and cross-site request forgery protection.

api.config["SESSION_TYPE"] = "filesystem" # The session type has been configured to use the filesystem for storing session data as this allows for better security and scalability compared to using cookies.
api.config['SESSION_FILE_DIR'] = './flask_session/' # The directory where session files will be stored on the server's filesystem. This is used when the session type is set to "filesystem."

api.config.update (
    SESSION_COOKIE_HTTPONLY = True, #Browsers will not allow Javascript access to cookies marked as "HTTP Only" for security against session fixation by preventing them from being read using Javascript.
    SESSION_COOKIE_SAMESITE = 'Lax', #Prevents cookies from being sent with CSRF-prone requests from external sites, protecting against cross-site request forgery attacks.
)
 
#Rate limiting to protect against race conditions and brute-force attacks by restricting the amount of requests to prevent overloading.
limiter = Limiter(
    get_remote_address,
    app=api,
    storage_uri="memory://",
)
#The max login attempts is set to 3 to prevent brute-force attacks by restricting the amount of times someone can fail a login before being locked out.
api.config['MAX_LOGIN_ATTEMPTS'] = 3
#def csrf_app():
    #app = Flask(__name__)
    #csrf.init_app(app)
Session(api)

csrf.init_app(api)
#Enable CORS to allow cross-origin requests (needed for CSRF demo in Codespaces)
CORS(api)

@api.after_request
def security_headers(response):
        response.headers['X-Frame-Options'] = 'SAMEORIGIN' #Prevents external sites from embedding the progressive web app in an iframe, protecting it from cross-frame scripting.
        ##Content-security-policy to protect against cross-site scripting, cross-frame scripting and SQL injection
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
         # Prevents caching of sensitive information in the browser to protect against unauthorised access to sensitive data by ensuring that the browser does not store any cached copies of the progressive web application's pages or resources.
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0' 
        return response
@api.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    # If user is not logged in then redirect them back to the homepage to prevent users from being able to access the feedback page without authentication.
    if not session.get("isloggedin"):
        return redirect(url_for("home"))
    # If the request method is GET and a URL parameter is provided, redirect the user to that URL. This allows for dynamic redirection based on user input.
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    # If the request method is POST, retrieve the feedback from the form data, insert it into the database, and clear the Jinja2 template cache to ensure that the latest feedback is displayed. This then renders the feedback page and the username of the logged-in user.
    if request.method == "POST":
        feedback = request.form["feedback"]
        dbHandler.insertFeedback(feedback) # Insert the feedback into the database using the insertFeedback function from the dbHandler module.
        dbHandler.listFeedback() # List the feedback from the database using the listFeedback function from the dbHandler module. 
        api.jinja_env.cache.clear() # Clear the Jinja2 template cache to ensure that the latest feedback is displayed on the feedback page.
        #return render_template("/success.html", state=True, value="Back", username=session.get("username"))
        return render_template("/success.html", state=True, value="Back")
    else:
        dbHandler.listFeedback() # List the feedback from the database using the listFeedback function from the dbHandler module
        api.jinja_env.cache.clear() # Clear the Jinja2 template cache to ensure that the latest feedback is displayed on the feedback page.
        return render_template("/success.html", state=True, value="Back", username=session.get("username")) 
        #return redirect(url_for("successful_login"))


@api.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def signup():
    # Check if user is already logged in to prevent the user from accessing the signup page unless they logout.
    #if request.method == "GET" and session.get("isloggedin") is True:
        #return redirect(url("successful_login"))
    # If the request method is GET and a URL parameter is provided, redirect the user to that URL. This allows for dynamic redirection based on user input.
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    # If the request method is POST, retrieve the username, password, and date of birth from the form data, validate the password using the sanitiser module, and insert the user into the database.
    if request.method == "POST":
        #username = request.form["username"] 
        #password = request.form["password"]
        #DoB = request.form["dob"]
        username = request.form.get("username")
        password = request.form.get("password")
        DoB = request.form.get("dob")
        try:
            _ = sanitiser.check_password(password).hex() # Check if the password is valid and can be converted to a hexadecimal representation. If not, raise a ValueError in order to prevent brute-force attacks and broken authentication.
            if not sanitiser.simple_check_password(password): # Check if the password meets the security requirements using the simple_check_password function from the sanitiser module. If not, raise a ValueError to prevent brute-force attacks and broken authentication by ensuring that the password is complex enough to resist common attacks.
                raise ValueError("Password does not meet security requirements.")
        except TypeError:
            #logger.error(f"Type errors for password:{password}")
            print(f"TypeError has been logged for password:{password}") # Log the TypeError for debugging purposes.
            #print("TypeError has been logged")
            return render_template("/signup.html", error="Invalid password type. Please enter a valid password.") # Return an error message to the user if the password is not a string to prevent brute-force attacks and broken authentication by ensuring that the password is a valid string.
        except ValueError as inst: 
            #logger.error(f"Value errors for password:{password} with {inst.args}")
            print(f"ValueError has been logged for password:{password} with {str(inst)}") # Log the ValueError for debugging purposes. 
            return render_template("/signup.html", error=f"Not a valid password because it has {str(inst)}. Please enter a valid password.") # Return an error message to the user if the password does not meet the security requirements to prevent brute-force attacks and broken authentication by ensuring that the password is complex enough to resist common attacks.
        except Exception as inst:
            #logger.error(f"Unexpected error for password:{password} with {type(inst)}")
            print(f"Unexpected error has been logged for password:{password} with {type(inst)}") # Log the unexpected error for debugging purposes.
            return render_template("/signup.html", error=f"An unexpected error occurred. Please enter a valid password.") # Return an error message to the user if an unexpected error occurred to prevent brute-force attacks and broken authentication by ensuring that the password is valid.
        dbHandler.insertUser(username, password, DoB,) # Insert the user into the database using the insertUser function from the dbHandler module.
        api.session_interface.regenerate(session) # Regenerate the session ID to prevent session fixation attacks by creating a new session ID upon successful signup.
        session["isloggedin"] = True # Set the session variable to indicate that the user has logged in successfully after signing up. This prevents the user from having to log in again after signing up.
        session["username"] = username # Set the session variable to store the username of the logged in user after signing up. This allows the application to personalise the user experience by displaying the username on the feedback page.
        return render_template("/success.html", value= username,state="isLoggedIn", username=username) # Render the success page after signing up successfully.
        #return render_template("/index.html")
    else:
        return render_template("/signup.html") # Render the signup page if the request method is not POST to allow the user to sign up for an account.
    
        

@api.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@api.route("/", methods=["POST", "GET"])
@limiter.limit("5 per minute", methods=["POST"])
def home():
    current_time = time.time() # The current time in seconds when the user logins.
    end_time = 180 # The time in seconds that the user will be locked out for.
    # If the request method is GET and a URL parameter is provided, redirect the user to that URL. This allows for dynamic redirection based on user input.
    if request.method == "GET" and request.args.get("url"):
            url = request.args.get("url", "")
            return redirect(url, code=302)
    is_locked_out = False # If the user is locked out, this variable will be set to True in order to prevent the user from logging in until the lockout period has expired. This is used to prevent brute-force attacks and broken authentication by limiting the amount of failed login attempts.
    remaining_lockedouttime = 0 # The variable for the remaining time in seconds that the user will be locked out for. 
    # If the user has exceeded the maximum login attempts, check if they are still locked out. If they are, set the is_locked_out variable to True and calculate the remaining time in seconds that the user will be locked out for. If they are not locked out, reset the login attempts and lockedout status so the user is not locked out anymore.
    if 'login_attempts' in session and session.get("login_attempts") >= api.config['MAX_LOGIN_ATTEMPTS']:
               lockedout = session.get("lockedout", 0)
               time_since_lockedout = current_time - lockedout
               if time_since_lockedout < end_time:
                 is_locked_out = True
                 remaining_lockedouttime = int(end_time - time_since_lockedout)
               else:
                 api.session_interface.regenerate(session)
                 session["login_attempts"] = 0
                 session.pop("lockedout", None)
    # If the request method is GET, check if the user is locked out. If they are, return an error message. If they are not, retrieve any message from the URL parameters and render the login page with that message. 
    if request.method == "GET":
        if is_locked_out:
            return render_template("index.html", msg=f"Too many login attempts. Please try again later.")
        else:
            msg = request.args.get("msg", "")
        return render_template("index.html", msg=msg)
        
        #msg = request.args.get("msg", "")
        #return render_template("index.html", msg=msg)
    # Pass message to front end
    elif request.method == "GET":
            msg = request.args.get("msg", "")
            return render_template("/index.html", msg=msg)
    # If the request method is POST, check if the user is locked out. If they are, return an error message.
    elif request.method == "POST":
        if is_locked_out:
            msg = f"Too many login attempts. Please try again later in {remaining_lockedouttime} seconds."
            return render_template("/index.html", msg=msg) # Return an error message to the user if they are locked out due to too many failed login attempts and prevents them from bypassing validation by refrehsing or switiching to signup page.
            
        username = request.form["username"] # Retrieve the username from the form data submitted which is used to authenticate the user and check if they are registered in the database.
        password = request.form["password"] # Retrieve the password from the form data submitted which is used to authenticate the user and check if they are registered in the database.
        #to_email = username
        try:
            if not isinstance(username, str) or not isinstance(password, str): # Check if the username and password are strings. If not, raise a TypeError to prevent brutre-force attacks and broken authentication by ensuring that the username and password are valid strings.
                raise TypeError("Username and password must be strings.")
        except TypeError as inst:
            #logger.error(f"Type errors for username:{username} or password:{password} with {inst.args}")
            return render_template("/index.html", msg="Invalid input type. Please enter valid credentials.") # Return an error message to the user 
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        # If the user is logged in, set the session variables and reset the login attempts and lockedout status. Else, increment the login attempts and check if the user has exceeded the maximum login attempts. If the user has exceeded it then lock the user out. 
        if isLoggedIn:
            api.session_interface.regenerate(session) # Regenerate the session ID to prevent session fixation attacks by creating a new session ID upon successful login.
            session["isloggedin"] = True # Set the session variable to indicate that the user has logged in successfully.
            session["username"] = username # Set the session variable to store the username of the logged in user. 
            session["login_attempts"] = 0 # Reset login attempts to 0 upon a successful login
            session.pop("lockedout", None) # Reset lockedout status upon a successful login
            dbHandler.listFeedback() # Show the feedback after successfully logging in.
            return redirect(url_for("successful_login")) # Redirect the user to the login page after successfully logging in
        
        else:
            session["login_attempts"] = session.get("login_attempts", 0 ) + 1 # Increment the login attempts by 1 upon a failed login attempt
            if session.get("login_attempts") >= api.config['MAX_LOGIN_ATTEMPTS']: # If the user has exceeded the maximum login attempts, lock the user out for a specific time and record the time since the user was locked out.
                session["lockedout"] = current_time
                return render_template("/index.html", msg="Too many login attempts. Please try again later.")
            remaining_attempts = api.config["MAX_LOGIN_ATTEMPTS"] - session.get("login_attempts")
            return redirect(url_for("home", msg=f"Invalid username or password. You have {remaining_attempts} attempts remaining."))
    else:
       return render_template("/index.html") # Return the login page if the request method is not GET or POST
# Route to handle successful login and ensure that users cannot access the feedback page without logging in first. 
@api.route("/successful_login", methods=["GET"])
def successful_login():
    # Check if the user is logged in before redirecting to the feedback page. If the user is not logged in, redirect them to the login page. Prevents users from accessing the feedback page without logging in first.
    if session.get("isloggedin") is not True:  
        return redirect(url_for("home"))
    return render_template("/success.html", value=session.get("username"), state=True)
# Logout route to clear the session data and log the user out
@api.route("/logout", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def logout():
     session.clear() # Clear the session data to log the user out
     #session.modified = True 
     response = make_response(redirect(url_for("home")))
     #return redirect(url_for("home")) # Redirect the user to the login page after logging out
     response.set_cookie('session', '', expires=0, max_age=0)  
     return response
#Rate limitation error handler to handle 429 Too Many Requests errors and return a custom error message to the user when they exceed the rate limit, preventing race_conditions and brute-force attacks.
@api.errorhandler(429)
def rate_limiter(error):
    return render_template("/index.html", msg="Too many requests. Please try again later."), 429

if __name__ == "__main__":
    api.config["TEMPLATES_AUTO_RELOAD"] = True # Enable template auto-reloading to allow for changes to be reflected without restarting the server.
    api.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0 # Disable caching of static files to ensure that the latest version of the files is always served to the user.
    api.run(debug=True, host="0.0.0.0", port=5000) # Run the Flask application.
    #ssl_context="adhoc"
