import hashlib
import os

API_KEY = os.environ.get("API_KEY", "")
password = os.environ.get("PASSWORD", "")
digest = hashlib.md5(password.encode()).hexdigest()
# delta-test touch 16:51:38
