import hashlib

API_KEY = "sk-live-9f8a7b6c5d4e3f2a1b0c"
password = "hunter2"
digest = hashlib.md5(password.encode()).hexdigest()
