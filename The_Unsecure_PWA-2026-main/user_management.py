import datetime
from datetime import datetime, timedelta
import sqlite3 as sql
import time
import random
import os
import html as html
from datetime import date, datetime, timedelta
from time import sleep
from flask import render_template
import re
import bcrypt

start_time = datetime.now()
end_time = start_time + timedelta(milliseconds=5)

# Function to check if a URL is relative or absolute in order to prevent open redirect vulnerabilities and ensure that users are redirected to safe and trusted locations within the application.
def is_relative(url):
  return re.match(r"^\/[^\/\\]", url)
# Function to insert a new user into the database with their username, hashed password, date of birth and salt for secure password storage and authentication, mitigating the negative impacts of a data breach due to SQL injection.
def insertUser(username, password, DoB):
    BASE_DIR = os.path.dirname(os.path.abspath(__file__)) # Get the base directory of the current file to construct the path to the database file.
    db_path = os.path.join(BASE_DIR, "database_files", "database.db") # Construct the path to the database file by joining the base directory with the relative path to the database file.
    con = sql.connect(db_path) # Connect to the SQLite database using the constructed path to the database file.
    cur = con.cursor() # Create a cursor object to execute SQL queries on the connected database.
    bytes = password.encode('utf-8') # Encode the password as bytes using UTF-8 encoding to prepare it for hashing with bcrypt, which requires byte input for secure password storage.
    salt = bcrypt.gensalt() # Generate a random salt using bcrypt to add an additional layer of security, making it more difficult for attackers to crack hashed passwords in the event of a data breach due to SQL injectioon.
    hash = bcrypt.hashpw(bytes,salt) # Hash the password using bcrypt with the generated salt to securely store the password in the database.
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth, salt) VALUES (?,?,?,?)", # SQL query to insert a new user into the users table with their username, hashed password, date of birth and salt.
        (username, hash, DoB, salt),
    )
    con.commit() # Commit the changes to the database to save the new user record and ensure that the data is persisted in the database.
    con.close()
# Function to perform a simple check on the password to ensure that it meets the minimum security requirements, such as length, character types and absence of spaces, to prevent weak passwords and enhance the overall security of user accounts against brute-force attacks and broken authentication.
def simple_check_password(password: str) -> bool:
    if not isinstance(password, str): # Check if the password is a string to ensure that the input is of the expected type and prevent potential errors or unexpected behaviour during password validation.
        return False
    if len(password) < 8: # Check if the password is at least 8 characters long to enforce a minimum length requirement for stronger passwords and reduce the risk of brute-force attacks.
        return False
    if len(password) > 20: # Check if the password is no more than 20 characters long to enforce a maximum length requirement for passwords and prevent issues with excessively long passwords such as buffer overflows or performance degradation during authentication.
        return False
    if re.search(r"[ ]", password): # Check if the password contains any space characters to enforce a restriction on spaces in passwords and prevent potential issues with password parsing or validation during authentication.
        return False
    if not re.search(r"[A-Z]", password): # Check if the password contains at least one uppercase letter to enforce a requirement for mixed case in passwords and enhance the overall complexcity of passwords to make them more resistant to brute-force attacks.
        return False
    if not re.search(r"[a-z]", password): # Check if the password contains at least one lowercase letter to enforce a requirement for mixed case in passwords and enhance the overall complexity of passwords to make them more resistant to brute-force attacks.
        return False
    if not re.search(r"[0-9]", password): # Check if the password contains at least one digit to enforce a requirement for numeric characters in passwords and enhance the overall complexity of passwords to protect against brute-force attacks.
        return False
    if not re.search(r"[@$!%*?&]", password): # Check if the password contains at least one special character to enforce a requirement for special characters in passwords and enhance the overall complexity of passwords to make them more resistant to brute-force attacks.
        return False
    return True    

# Function to check the password against specific security requirements and return the encoded password if it meets the criteria, raising appropriate exceptions for invalid input or unmet requirements to ensure that only strong and secure passwords are accepted for user authentication.
def check_password(password: str) -> bytes:
    if not isinstance(password, str): # Check if the password is a string to ensure that the input is of the expected type and prevent potential errors or unexpected behaviour during password valisation.
        raise TypeError("Expected a string")
    if len(password) < 8: # Check if the password is at least 8 characters long to enforce a minimum length requirement for stronger passwords and reduce the risk of brute-force attacks.
        raise ValueError("less than 8 characters")
    if len(password) > 20: # Check if the password is no more than 20 characters long to enfore a maximum length requirement for passwords.
        raise ValueError("more than 20 characters")
    if re.search(r"[ ]", password): # Check if the password contains any space characters to enforce a restriction on spaces in passwords.
        raise ValueError("contains ' ' space characters")
    if not re.search(r"[A-Z]", password): # Check if the password contains at least one uppercase letter to enforce a requirement for mixed case in passwords and enhance the overall complexity of passwords.
        raise ValueError("does not contain uppercase letters")
    if not re.search(r"[a-z]", password): # Check if the password contains at least one lowercase letter to enforce a requirement for mixed case in passwords and enhance the overall complexity of passwords.
        raise ValueError("does not contain lowercase letters")
    if not re.search(r"[0-9]", password): # Check if the password contains at least one digit to enforce a requirement for numeric characters in passwords and enhance the overall complexity of passwords.
        raise ValueError("does not contain a digit '0123456789'")
    if not re.search(r"[@$!%*?&]", password): # Check if the password contains at least one special character to enforce a requirement for special characters in passwords and enhance the overall complexity of passwords.
        raise ValueError("does not contain one of '@$!%*?&' special characters")
    # Password is returned encoded so it can't be accidently logged in a human readable format
    return password.encode()

def retrieveUsers(username, password):
    #start_time = datetime.now()
    #duration = random.randint(150,300)
    #end_time = start_time + timedelta(milliseconds=duration)
    #authentication = False
    #sleep(random.randint(80, 90) / 1000)
    BASE_DIR = os.path.dirname(os.path.abspath(__file__)) # Get the base directory of the current file to construct the path to the database file.
    db_path = os.path.join(BASE_DIR, "database_files", "database.db") # Construct the path to the database file by joining the base directory with the relative path to the database file.
    con = sql.connect(db_path) # Connect to the SQLite dataabase using the constructed path to the database file.
    cur = con.cursor() # Create a cursor object to execute SQL queries on the connected database.
    #cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
    cur.execute("SELECT * FROM users WHERE username = ?", (username, )) #SQL and Parameter is sent off seperately to the database driver, preventing SQL injection.
    row = cur.fetchone() # Fetch the first row of the result set returned by the SQL query to retrieve the user record with the specified username from the database.
    con.close()
    if row is None: # Check if the row is None to determine if the user with the specified username exists in the database. This is to ensure that users cannot bypass authentication by providing a password that another user has using a different username.
      return False
    db_hashed_password = row[2] # Retrieve the hashed password from the user record to compare it with the provided password for authentication.
    # Ensure that the hashed password is in bytes format for bcrypt comparison to prevent potential errors or unexpected behaviour during password validation.
    if isinstance(db_hashed_password, str):
           db_hashed_password = db_hashed_password.encode('utf-8')

    if bcrypt.checkpw(password.encode('utf-8'), db_hashed_password): # Check if the provided password matches the hashed password stored in the database using bcrypt to securely authenticate the user and prevent unauthorised access to their account.
           return True
    else:
        #cur.execute(f"SELECT * FROM users WHERE password = '{password}'")
        #cur.execute("SELECT * FROM users WHERE password = ?", (password, )) #SQL and Parameter is sent off seperately to the database driver.
        # Plain text log of visitor count as requested by Unsecure PWA management
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        v_path = os.path.join(BASE_DIR, "visitor_log.txt")
        try: # Open the visitor log file in read mode to retrieve the current visitor count and increment it by 1 to keep track of failed login attempts for security monitoring and analysis.
          with open(v_path) as file:
            number = int(file.read().strip())
        except FileNotFoundError:
            number = 0
        number += 1
        with open(v_path, 'w') as file:
            file.write(str(number))
        # Simulate response time of heavy app for testing purposes
        time.sleep(random.randint(80, 90) / 1000)
        return False
        #if cur.fetchone() == None:
            #con.close()
            #return False
        #else:
            #con.close()
            #return True
def insertFeedback(feedback):
    BASE_DIR = os.path.dirname(os.path.abspath(__file__)) # Get the base directory of the current file to construct the path to the database file.
    db_path = os.path.join(BASE_DIR, "database_files", "database.db") # Construct the path to the database file by joining the base directory with the relative path to the database file.
    con = sql.connect(db_path) # Connect to the SQLite database using the constructed path to the database file.
    cur = con.cursor() # Create a cursor object to execute SQL queries on the connected database.
    #cur.execute(f"INSERT INTO feedback (feedback) VALUES ('{feedback}')")
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,)) #SQL and Parameter is sent off seperately to the database driver, preventing SQL injection.
    con.commit()
    con.close()


def listFeedback():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__)) # Get the base directory of the current file to construct the path to the database file.
    db_path = os.path.join(BASE_DIR, "database_files", "database.db") # Construct the path to the database file by joining the base directory with the relative path to the database file.
    con = sql.connect(db_path) # Connect to the SQLite database using the constructed path to the database file.
    cur = con.cursor() # Create a cursor object to execute SQL queries on the connected database.
    data = cur.execute("SELECT * FROM feedback").fetchall() # Fetch all rows from the feedback table in the database to retrieve all user feedback records for display or analysis.
    con.close()
    f_path = os.path.join(BASE_DIR, "templates", "partials", "success_feedback.html") # Construct the path to the success_feedback.html template file by joining the base directory with the relative path.
    f = open(f_path, "w") # Open the success_feedback.html template file in write mode to overwrite its contents with the retrieved user feedback records for display on the feedback page.
    for row in data: # Iterate through each row of the retrieved user feedback records to process and write them to the success_feedback.html template file for display on the feedback page.
        safe_feedback = html.escape(row[1]) # Escape the feedback content to prevent XSS attacks and ensure that any special characters in the feedback are properly encoded for safe display on the feedback page, preventing cross-site scripting attacks.
        f.write("<p>\n") 
        f.write(f"{safe_feedback}\n") # Write the escaped feedback content to the success_feedback.html template file for display on the feedback page.
        f.write("</p>\n")
    f.close()
def authenticate_user (username, password):
    #authentication to be implemented with random duration and placements of pauses during computation
    while datetime.now() < end_time:
        return render_template("/result.html")