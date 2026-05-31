import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from pathlib import Path

# Setup rotating file logger
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
log_file = os.getenv("LOG_FILE", "server.log")
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
log_max_bytes = int(os.getenv("LOG_MAX_BYTES", str(5 * 1024 * 1024)))
log_backup_count = int(os.getenv("LOG_BACKUP_COUNT", "2"))

Path(log_file).parent.mkdir(parents=True, exist_ok=True)

my_handler = RotatingFileHandler(
    log_file,
    mode='a',
    maxBytes=log_max_bytes,
    backupCount=log_backup_count,
    encoding=None,
    delay=0,
)
my_handler.setFormatter(log_formatter)
my_handler.setLevel(getattr(logging, log_level, logging.INFO))

app_log = logging.getLogger('root')
app_log.setLevel(getattr(logging, log_level, logging.INFO))
if not any(getattr(handler, "baseFilename", None) == my_handler.baseFilename for handler in app_log.handlers):
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
