import os
import sqlite3
import subprocess
import pickle


def run(cmd):
    return os.system("sh -c " + cmd)


def shell(cmd):
    return subprocess.call(cmd, shell=True)


def lookup(name):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    return cur.execute("SELECT * FROM t WHERE n = '%s'" % name).fetchone()


def load(blob):
    return pickle.loads(blob)


def calc(expr):
    return eval(expr)
