import os
import sys

# Set current directory and python path to inner project folder
nested_dir = os.path.join(os.path.dirname(__file__), "EH new")
sys.path.insert(0, nested_dir)
os.chdir(nested_dir)

import run

if __name__ == "__main__":
    run.main()

