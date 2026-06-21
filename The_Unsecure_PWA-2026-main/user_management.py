import datetime
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


def is_relative(url):
  return re.match(r"^\/[^\/\\]", url)
def insertUser(username, password, DoB):
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(BASE_DIR, "database_files", "database.db")
    con = sql.connect(db_path)
    cur = con.cursor()
    bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(bytes,salt)
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth, salt) VALUES (?,?,?,?)",
        (username, hash, DoB, salt),
    )
    con.commit()
    con.close()
def simple_check_password(password: str) -> bool:
    if not issubclass(type(password), str):
        return False
    if len(password) < 8:
        return False
    if len(password) > 20:
        return False
    if re.search(r"[ ]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[@$!%*?&]", password):
        return False
    return True    
def check_password(password: str) -> bytes:
    if not issubclass(type(password), str):
        raise TypeError("Expected a string")
    if len(password) < 8:
        raise ValueError("less than 8 characters")
    if len(password) > 20:
        raise ValueError("more than 10 characters")
    if re.search(r"[ ]", password):
        raise ValueError("contains ' ' space characters")
    if not re.search(r"[A-Z]", password):
        raise ValueError("does not contain uppercase letters")
    if not re.search(r"[a-z]", password):
        raise ValueError("does not contain lowercase letters")
    if not re.search(r"[0-9]", password):
        raise ValueError("does not contain a digit '0123456789'")
    if not re.search(r"[@$!%*?&]", password):
        raise ValueError("does not contain one of '@$!%*?&' special characters")
    # Password is returned encoded so it can't be accidently logged in a human readable format
    return password.encode()

def retrieveUsers(username, password):
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(BASE_DIR, "database_files", "database.db")
    con = sql.connect(db_path)
    cur = con.cursor()
    #cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
    cur.execute("SELECT * FROM users WHERE username = ?", (username, )) #SQL and Parameter is sent off seperately to the database driver.
    if cur.fetchone() == None:
        con.close()
        return False
    else:
        cur.execute("SELECT * FROM users WHERE password = ?", (password, )) #SQL and Parameter is sent off seperately to the database driver.
        # Plain text log of visitor count as requested by Unsecure PWA management
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        v_path = os.path.join(BASE_DIR, "visitor_log.txt")
        with open(v_path) as file:
            number = int(file.read().strip())
            number += 1
        with open(v_path, 'w') as file:
            file.write(str(number))
        # Simulate response time of heavy app for testing purposes
        time.sleep(random.randint(80, 90) / 1000)
        if cur.fetchone() == None:
            con.close()
            return False
        else:
            con.close()
            return True


def insertFeedback(feedback):
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(BASE_DIR, "database_files", "database.db")
    con = sql.connect(db_path)
    cur = con.cursor()
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
    con.commit()
    con.close()


def listFeedback():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(BASE_DIR, "database_files", "database.db")
    con = sql.connect(db_path)
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    f_path = os.path.join(BASE_DIR, "templates", "partials", "success_feedback.html")
    f = open(f_path, "w")
    for row in data:
        safe_feedback = html.escape(row[1])
        f.write("<p>\n")
        f.write(f"{safe_feedback}\n")
        f.write("</p>\n")
    f.close()
def authenticate_user (username, password):
    #authentication to be implemented with random duration and placements of pauses during computation
    while datetime.now() < end_time:
        return render_template("/result.html")