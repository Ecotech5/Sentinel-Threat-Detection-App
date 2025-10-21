# main.py
from dotenv import load_dotenv
load_dotenv()
from gui import SentinelURLApp

if __name__ == "__main__":
    app = SentinelURLApp()
    app.mainloop()
