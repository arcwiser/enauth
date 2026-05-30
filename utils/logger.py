import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

# Setup rotating file logger
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
log_file = 'server.log'

my_handler = RotatingFileHandler(log_file, mode='a', maxBytes=5*1024*1024, 
                                 backupCount=2, encoding=None, delay=0)
my_handler.setFormatter(log_formatter)
my_handler.setLevel(logging.INFO)

app_log = logging.getLogger('root')
app_log.setLevel(logging.INFO)
app_log.addHandler(my_handler)

async def log_action(db, action: str, *,
                     license_key: str = None,
                     app_id: str = None,
                     ip: str = None,
                     hwid: str = None,
                     details: str = None):
    """Insert a row into the logs table and write to rotating file."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    
    # Write to DB
    await db.execute(
        """INSERT INTO logs (license_key, app_id, action, ip, hwid, details, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (license_key, app_id, action, ip, hwid, details, now),
    )
    await db.commit()
    
    # Write to file for audit
    log_msg = f"[{action.upper()}] IP:{ip} HWID:{hwid} App:{app_id} Key:{license_key} - {details or 'No details'}"
    app_log.info(log_msg)
