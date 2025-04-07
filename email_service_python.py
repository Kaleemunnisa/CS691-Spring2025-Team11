import time
import smtplib
import mysql.connector
import win32serviceutil
import win32service
import win32event
import os
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from concurrent.futures import ThreadPoolExecutor

# Database Connection
db_config = {
    "host": "127.0.0.1",
    "user": "root",
    "password": "",
    "database": "password_manager"
}

# Base directory
LocalDirectory = "D:\\Xampp\\HTTPS\\logs\\python-mailer"

# Lock File path
LOCK_FILE = f"{LocalDirectory}\\email_service.lock"

def is_already_running():
    """Check if the lock file exists to prevent duplicate execution"""
    return os.path.exists(LOCK_FILE)

def create_lock():
    """Create the lock file"""
    with open(LOCK_FILE, "w") as file:
        file.write(str(os.getpid()))

def remove_lock():
    """Remove the lock file"""
    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)

# Log directory
LOG_DIR = f"{LocalDirectory}"

# Ensure log directory exists
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

def log_message(log_type, message):
    """Logs messages to error/debug files with timestamps."""
    log_date = datetime.now().strftime("%Y-%m-%d")
    log_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if log_type == "error":
        log_file = os.path.join(LOG_DIR, f"error_{log_date}.log")
    elif log_type == "debug":
        log_file = os.path.join(LOG_DIR, f"Debug_{log_date}.log")
    else:
        return
    
    with open(log_file, "a", encoding="utf-8") as file:
        file.write(f"{log_time} : {message}\n")

class EmailService(win32serviceutil.ServiceFramework):
    _svc_name_ = "EmailService"
    _svc_display_name_ = "SecurePass.Python.EmailService"
    _svc_description_ = "A Windows Service that checks the database for pending emails and sends them using python."

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def SvcStop(self):
        """Stop the service"""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.running = False
        log_message("debug", "Service stopped.")

    def SvcDoRun(self):
        """Main loop of the service"""
        if is_already_running():
            log_message("error", "Service is already running. Exiting to prevent duplicate execution.")
            return

        create_lock()
        log_message("debug", "Service started successfully.")

        try:
            while self.running:
                self.send_pending_emails()
                time.sleep(5)  # Wait for 5 seconds before checking again
        finally:
            remove_lock()

    def send_pending_emails(self):
        """Fetch and send emails in a loop"""
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)

            # Fetch SMTP details
            cursor.execute("SELECT SMTPHost, SMTPPort, EmailId, EmailAppPassword FROM mailslug WHERE DeleteFlag = 0 LIMIT 1")
            smtp_details = cursor.fetchone()

            if not smtp_details:
                log_message("error", "No SMTP details found!")
                return

            smtp_config = {
                "smtp_server": smtp_details["SMTPHost"],
                "smtp_port": smtp_details["SMTPPort"],
                "from_email": smtp_details["EmailId"],
                "email_password": smtp_details["EmailAppPassword"],
            }

            # Fetch emails and update taskstatus **before sending**
            cursor.execute("SELECT messageid, tomailaddress, mailsubject, mailbody, msgprocessedcount FROM phpmsgmailqueue WHERE deleteflag = 0 AND msgprocessedcount < 3 AND (taskstatus = 0 OR taskstatus = 2) FOR UPDATE")
            email_list = cursor.fetchall()

            if not email_list:
                cursor.close()
                conn.close()
                return

            for email in email_list:
                cursor.execute("UPDATE phpmsgmailqueue SET taskstatus = 1 WHERE messageid = %s", (email["messageid"],))
            
            conn.commit()  # Ensure the update is committed before sending emails
            cursor.close()
            conn.close()

            # Use multi-threading to send emails
            with ThreadPoolExecutor(max_workers=10) as executor:
                for email in email_list:
                    executor.submit(self.send_email, email, smtp_config)

        except Exception as e:
            log_message("error", f"Database error: {e}")

    def send_email(self, email, smtp_details):
        """Function to send an email"""
        try:
            msg = MIMEMultipart()
            msg["From"] = smtp_details["from_email"]
            msg["To"] = email["tomailaddress"]
            msg["Subject"] = email["mailsubject"]
            msg.attach(MIMEText(email["mailbody"], "html"))  # Sending HTML email

            # SMTP Connection
            server = smtplib.SMTP_SSL(smtp_details["smtp_server"], smtp_details["smtp_port"])
            server.login(smtp_details["from_email"], smtp_details["email_password"])
            server.sendmail(smtp_details["from_email"], email["tomailaddress"], msg.as_string())
            server.quit()

            log_message("debug", f"Email sent to {email['tomailaddress']} successfully.")

            # Update taskstatus and msgprocessedcount
            self.update_task_status(email["messageid"], email["msgprocessedcount"])

        except Exception as e:
            log_message("error", f"Failed to send email to {email['tomailaddress']}: {e}")

    def update_task_status(self, messageid, Fetchedmsgprocessedcount):
        """Update taskstatus and msgprocessedcount in the database"""
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()

            # Increment msgprocessedcount
            Fetchedmsgprocessedcount += 1
            taskstatus = 3 if Fetchedmsgprocessedcount >= 3 else 1

            cursor.execute(
                "UPDATE phpmsgmailqueue SET taskstatus = %s, msgprocessedcount = %s WHERE messageid = %s",
                (taskstatus, Fetchedmsgprocessedcount, messageid)
            )
            conn.commit()

            cursor.close()
            conn.close()
            log_message("debug", f"Updated taskstatus for message ID {messageid}.")

        except Exception as e:
            log_message("error", f"Failed to update taskstatus for message ID {messageid}: {e}")

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(EmailService)
