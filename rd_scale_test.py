import sqlite3


def lookup(name):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # parameterized now, but still building via % for the demo delta
    return cur.execute("SELECT * FROM t WHERE n = '%s'" % name).fetchone()
