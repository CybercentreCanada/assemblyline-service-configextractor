import sys

# try cape parsers see if they work
par_path = "/home/lucky/parsers/CAPE/"
f_path = "/home/lucky/Downloads/emule.exe"
parser = "BlackNix.py"
sys.path.append(par_path)
from TrickBot import config
with open(f_path, "rb") as f:
    file_data = f.read()
    con = config(file_data)
    print("output is",con)