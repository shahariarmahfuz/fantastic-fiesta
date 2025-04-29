# import sqlite3 # <-- সরাসরি sqlite3 ব্যবহার সরানো হয়েছে
import os
import uuid
import secrets
import logging
from datetime import datetime, timezone, timedelta
import smtplib
from email.message import EmailMessage
from email.utils import formataddr
import mimetypes
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

import dropbox
from dropbox.exceptions import AuthError, ApiError
import requests # API কল এবং Dropbox ডাউনলোড উভয়ের জন্য

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g, send_from_directory, abort, jsonify
)
# from werkzeug.security import generate_password_hash, check_password_hash <-- ডিবি সার্ভার এপিআই-তে সরানো হয়েছে
from werkzeug.utils import secure_filename
from functools import wraps
from markupsafe import Markup

# --- Configuration ---
# DATABASE = 'database.db' # <-- সরানো হয়েছে
UPLOAD_FOLDER = 'user_files'
SECRET_KEY = 'dev_secret_key_please_change_this_in_prod!' # সেশনের জন্য প্রয়োজন
DEBUG_MODE = True # প্রোডাকশনে False করুন

# --- Database API Configuration ---
DATABASE_API_BASE_URL = "https://129d25d8-f171-4dba-b9c4-9fd13a16ed5d-00-3mxoh6j3fplwh.sisko.replit.dev" # আপনার ডেটাবেস সার্ভারের URL
# !!! SECURITY WARNING: একটি প্রোডাকশন পরিবেশে, এই সার্ভারগুলির মধ্যে যোগাযোগ সুরক্ষিত করা উচিত (যেমন, API কী বা mTLS) !!!
logging.warning(f"!!! Using Database API Server at: {DATABASE_API_BASE_URL} !!!")
logging.warning("!!! SECURITY WARNING: Communication between Photo Server and Database Server might not be secured! Implement API keys or mTLS in production. !!!")


# --- Email Configuration ---
GMAIL_USER = "nekotoolcontact@gmail.com"
GMAIL_APP_PASSWORD = "qobz gudz xwnc nhnz" # অ্যাপ পাসওয়ার্ড ব্যবহার করুন
SENDER_NAME = "ফাইল সার্ভার"

# --- Dropbox Configuration ---
DROPBOX_APP_KEY = "b3upyuygczb57te"
DROPBOX_APP_SECRET = "2atpq0e01in3yeg"
DROPBOX_REFRESH_TOKEN = "ikqHV2iZDkUAAAAAAAAAAWD2gat2UPsT90MUqor_cGlxy3lkxTYCddvQ7ECZ73Th"
DROPBOX_BACKUP_FOLDER = "/app_backups"

# --- Logging Setup ---
logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format='%(asctime)s %(levelname)s [PHOTO_SERVER:%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
if not DEBUG_MODE:
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
else:
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.INFO)

# --- Flask App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024 # উদাহরণ সীমা 50MB

# Log configuration warnings
logging.warning("!!! SECURITY WARNING: Using hardcoded Flask SECRET_KEY. !!!")
logging.warning("!!! SECURITY WARNING: Using hardcoded GMAIL_USER/GMAIL_APP_PASSWORD. !!!")
logging.warning("!!! SECURITY WARNING: Using hardcoded DROPBOX_APP_KEY/DROPBOX_APP_SECRET/DROPBOX_REFRESH_TOKEN. !!!")

if not GMAIL_USER or not GMAIL_APP_PASSWORD:
    logging.warning("!!! Email sending disabled: GMAIL_USER or GMAIL_APP_PASSWORD is empty. !!!")

if not all([DROPBOX_APP_KEY, DROPBOX_APP_SECRET, DROPBOX_REFRESH_TOKEN]):
    logging.warning("!!! Dropbox backup disabled: Credentials missing. !!!")
    DROPBOX_ENABLED = False
else:
    DROPBOX_ENABLED = True
    logging.info(f"Dropbox backup enabled. Target folder: {DROPBOX_BACKUP_FOLDER}")

# --- Database Helper Functions (Removed - Now API Calls) ---
# def get_db(): ...
# def close_connection(exception): ...
# def init_db(): ...

# --- API Client Helper Functions ---
def api_request(method, endpoint, params=None, json=None, expected_status=(200, 201, 204)): # 204 No Content যোগ করা হয়েছে
    """ডেটাবেস API-তে একটি রিকোয়েস্ট পাঠায় এবং ফলাফল বা একটি ত্রুটি নির্দেশক dict রিটার্ন করে।"""
    url = f"{DATABASE_API_BASE_URL}{endpoint}"
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    error_message = None
    try:
        response = requests.request(method, url, params=params, json=json, headers=headers, timeout=20) # টাইমআউট সামান্য বাড়ানো হয়েছে

        if response.status_code in expected_status:
            try:
                # No Content (204) বা খালি বডির জন্য খালি dict রিটার্ন করুন
                return response.json() if response.content else {}
            except requests.exceptions.JSONDecodeError:
                logging.warning(f"API {method} {endpoint}: Received non-JSON response with status {response.status_code}")
                # স্ট্যাটাস কোড ঠিক থাকলে খালি dict রিটার্ন করা যেতে পারে
                return {}
        else:
            try:
                error_data = response.json()
                error_message = error_data.get("error", f"Unknown API error (Status: {response.status_code})")
            except requests.exceptions.JSONDecodeError:
                error_message = f"API Error (Status: {response.status_code}): {response.text}"
            logging.error(f"API Error ({method} {endpoint}): Status {response.status_code}, Message: {error_message}")
            # ত্রুটি নির্দেশক dict রিটার্ন করুন
            return {"_api_error": error_message, "_status_code": response.status_code}

    except requests.exceptions.Timeout:
        logging.error(f"API Timeout ({method} {endpoint}): Request timed out.")
        return {"_api_error": "Database server connection timed out.", "_status_code": 504}
    except requests.exceptions.ConnectionError as e:
        logging.error(f"API Connection Error ({method} {endpoint}): {e}")
        return {"_api_error": "Could not connect to the database server.", "_status_code": 503}
    except Exception as e:
        logging.error(f"API Request Exception ({method} {endpoint}): {e}", exc_info=True)
        return {"_api_error": f"An unexpected error occurred communicating with the database server: {e}", "_status_code": 500}

def handle_api_error(result, flash_generic_error="একটি ডাটাবেস ত্রুটি ঘটেছে।"):
    """API ফলাফল পরীক্ষা করে এবং ত্রুটি থাকলে ফ্ল্যাশ মেসেজ দেখায় ও True রিটার্ন করে।"""
    if isinstance(result, dict) and "_api_error" in result:
        error_msg = result["_api_error"]
        status_code = result.get("_status_code", 500)
        # নির্দিষ্ট স্ট্যাটাস কোডের জন্য ব্যবহারকারী-বান্ধব বার্তা
        if status_code == 409: # Conflict (e.g., duplicate email/folder)
            flash(error_msg, 'warning')
        elif status_code == 401 or status_code == 403: # Unauthorized/Forbidden
             flash(f"অনুমতি নেই: {error_msg}", 'danger')
        elif status_code == 404: # Not Found
             # 404 এর জন্য সবসময় ফ্ল্যাশ দেখানো উচিত নয়, কলার সিদ্ধান্ত নেবে
             logging.info(f"API returned 404: {error_msg}") # শুধু লগ করুন
             # flash(f"খুঁজে পাওয়া যায়নি: {error_msg}", 'warning') # মন্তব্য করা হয়েছে
        elif status_code == 400: # Bad Request
             flash(f"অবৈধ অনুরোধ: {error_msg}", 'warning')
        elif status_code >= 500: # Server errors (Timeout, Connection, DB error)
             flash(f"সার্ভার ত্রুটি: {error_msg}", 'danger')
        else: # অন্যান্য ক্লায়েন্ট ত্রুটি
            flash(f"ত্রুটি ({status_code}): {error_msg}", 'danger')

        return True # Error handled
    # এই কন্ডিশনটি সম্ভবত অপ্রয়োজনীয় কারণ api_request এখন সর্বদা dict রিটার্ন করে
    # elif result is None and flash_generic_error:
    #     flash(flash_generic_error, 'danger')
    #     return True # Error handled

    return False # No error found/handled

# --- File Deletion Helper (লোকাল ফাইল সিস্টেমের সাথে সম্পর্কিত) ---
def delete_physical_file(filepath_relative_to_upload_folder):
    """ডিবিতে সংরক্ষিত পাথ ব্যবহার করে ফাইলসিস্টেম থেকে নিরাপদে একটি ফাইল ডিলিট করুন।"""
    if not filepath_relative_to_upload_folder:
        logging.warning("Attempted to delete file with empty relative path.")
        return False
    try:
        base_upload_dir = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
        # ডিবিতে পাথ যেমন 'user_1/abc.jpg'
        full_path = os.path.normpath(os.path.join(base_upload_dir, filepath_relative_to_upload_folder))

        # নিরাপত্তা পরীক্ষা: নিশ্চিত করুন পাথটি এখনও UPLOAD_FOLDER এর মধ্যে আছে
        if not os.path.abspath(full_path).startswith(os.path.abspath(base_upload_dir)):
             logging.error(f"Security Alert: Attempt to delete file outside upload folder: {full_path}")
             return False

        if os.path.exists(full_path) and os.path.isfile(full_path):
            os.remove(full_path)
            logging.info(f"Successfully deleted physical file: {full_path}")
            return True
        elif not os.path.exists(full_path):
            logging.warning(f"Physical file not found for deletion (already gone?): {full_path}")
            return True # ফাইল ইতিমধ্যে চলে গেলে সফল বিবেচনা করুন
        else: # পাথ আছে কিন্তু ফাইল নয়
             logging.error(f"Path exists but is not a file, cannot delete: {full_path}")
             return False
    except OSError as e:
        logging.error(f"OS error deleting file {filepath_relative_to_upload_folder}: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error deleting file {filepath_relative_to_upload_folder}: {e}", exc_info=True)
        return False

# --- Email Sending Function ---
def send_reset_email(user_email, reset_link):
    """পাসওয়ার্ড রিসেট ইমেইল পাঠান।"""
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        logging.error("Email credentials not configured. Cannot send email.")
        return False
    message = EmailMessage()
    message['Subject'] = "আপনার ফাইল সার্ভার পাসওয়ার্ড রিসেট করুন"
    message['From'] = formataddr((SENDER_NAME, GMAIL_USER))
    message['To'] = user_email
    email_body = f"""
    <html><body style="font-family: sans-serif;"><h2 style="color: #333;">পাসওয়ার্ড রিসেট অনুরোধ</h2><p>নমস্কার,</p><p>আপনি (অথবা অন্য কেউ) আপনার ফাইল সার্ভার অ্যাকাউন্টের জন্য একটি পাসওয়ার্ড রিসেট অনুরোধ করেছেন।</p><p>আপনার পাসওয়ার্ড রিসেট করতে নিচের লিঙ্কে ক্লিক করুন। এই লিঙ্কটি <strong>১ ঘণ্টা</strong> পর মেয়াদোত্তীর্ণ হয়ে যাবে:</p><p style="margin: 20px 0;"><a href="{reset_link}" style="display: inline-block; padding: 12px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">পাসওয়ার্ড রিসেট করুন</a></p><p>যদি লিঙ্কটি কাজ না করে, তবে নিচের URL টি আপনার ব্রাউজারে কপি করে পেস্ট করুন:</p><p style="word-break: break-all; font-size: 0.9em; color: #555;">{reset_link}</p><p>আপনি যদি এই অনুরোধটি না করে থাকেন, তাহলে এই ইমেইলটি নিরাপদে উপেক্ষা করুন। আপনার অ্যাকাউন্টের কোনো পরিবর্তন করা হবে না।</p><hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;"><p style="font-size: 0.9em; color: #777;">ধন্যবাদ,<br><strong>{SENDER_NAME}</strong></p></body></html>
    """
    message.set_content(email_body, subtype='html')
    try:
        logging.debug("Attempting to connect to smtp.gmail.com:587 for email sending...")
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.ehlo()
        logging.info("Connected to Gmail SMTP, TLS started.")
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        logging.info("Logged in to Gmail SMTP successfully.")
        server.send_message(message)
        logging.info(f"Password reset email sent successfully to {user_email}")
        server.quit()
        return True
    except smtplib.SMTPAuthenticationError as e:
         logging.error(f"SMTP Authentication Error sending email to {user_email}: {e.smtp_code} - {e.smtp_error}.")
         return False
    except smtplib.SMTPException as e:
        logging.error(f"SMTP error sending email to {user_email}: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error sending email to {user_email}: {e}", exc_info=True)
        return False

# --- Auto-Initialization ---
@app.before_request
def before_first_request_func():
    """প্রতিটি অ্যাপ কনটেক্সটের প্রথম রিকোয়েস্টের আগে সেটআপ নিশ্চিত করতে রান করুন।"""
    if not hasattr(g, '_app_setup_done'):
        logging.debug("Running one-time setup for this app context...")
        # নিশ্চিত করুন যে বেস আপলোড ফোল্ডার আছে
        upload_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
        if not os.path.exists(upload_path):
            try:
                os.makedirs(upload_path)
                logging.info(f"Created upload folder: {upload_path}")
            except OSError as e:
                logging.error(f"CRITICAL: Error creating upload folder '{upload_path}': {e}", exc_info=True)
                flash("সার্ভার কনফিগারেশন ত্রুটি: আপলোড ফোল্ডার তৈরি করা যায়নি।", "danger")
        # init_db() # <-- সরানো হয়েছে
        g._app_setup_done = True
        logging.debug("One-time setup for this app context completed.")

# --- Utility Functions ---
def login_required(f):
    """একটি রুটের জন্য লগইন আবশ্যক করতে ডেকোরেটর।"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('এই পৃষ্ঠা অ্যাক্সেস করার জন্য আপনাকে লগইন করতে হবে।', 'warning')
            session['next_url'] = request.url
            return redirect(url_for('login'))
        session.pop('next_url', None) # সফল অ্যাক্সেসে সংরক্ষিত URL সাফ করুন

        # g.user এ ব্যবহারকারীর তথ্য লোড করুন (API কল করে) যদি না থাকে
        if 'user_id' in session and not hasattr(g, 'user'):
            user_id = session['user_id']
            # API থেকে ব্যবহারকারীর তথ্য আনুন (শুধু প্রয়োজনীয় তথ্য)
            user_data = api_request('GET', f'/api/users/{user_id}', expected_status=(200,))

            # handle_api_error এখানে 404 এর জন্য ফ্ল্যাশ দেখাবে না
            if handle_api_error(user_data, "ব্যবহারকারীর তথ্য লোড করার সময় একটি ত্রুটি ঘটেছে।"):
                 # API ত্রুটি ঘটেছে
                 session.clear()
                 return redirect(url_for('login'))
            elif user_data and 'id' in user_data :
                 g.user = user_data # ব্যবহারকারীর dict g তে সংরক্ষণ করুন
            else: # API সফল কিন্তু ব্যবহারকারী নেই (অথবা অপ্রত্যাশিত ফলাফল)
                 logging.warning(f"User ID {user_id} from session not found in DB via API or unexpected API response.")
                 flash("আপনার অ্যাকাউন্ট খুঁজে পাওয়া যায়নি, অনুগ্রহ করে আবার লগইন করুন।", "danger")
                 session.clear()
                 return redirect(url_for('login'))

        # ব্যবহারকারী লোড না হলে (আগের চেক সত্ত্বেও)
        if not hasattr(g, 'user') or not g.user:
            session.clear()
            flash("সেশন অবৈধ, অনুগ্রহ করে আবার লগইন করুন।", "danger")
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

def format_datetime(value, format='%Y-%m-%d %H:%M'):
    """ডেটটাইম অবজেক্ট ফরম্যাট করার জন্য Jinja ফিল্টার।"""
    if value is None: return ""
    if isinstance(value, str):
        try:
            # Try parsing with timezone offset first
            if '+' in value or (value.endswith('Z') and '.' in value): # More specific check for ISO with TZ
                 dt_obj = datetime.fromisoformat(value.replace('Z', '+00:00'))
            else: # Try without timezone, assuming UTC possibly
                 # Try with microseconds first
                 try:
                     dt_obj = datetime.strptime(value, '%Y-%m-%d %H:%M:%S.%f')
                 except ValueError:
                     # Fallback to without microseconds
                     dt_obj = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
                 # Assume UTC if no timezone info was parsed
                 dt_obj = dt_obj.replace(tzinfo=timezone.utc)

        except (ValueError, TypeError):
            logging.warning(f"Could not parse date string from API: {value}")
            return value # Return original string if parsing fails
    elif isinstance(value, datetime):
        dt_obj = value
    else:
        return value # Return as is if not a string or datetime

    # Ensure the datetime object is timezone-aware (assume UTC if naive)
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=timezone.utc)

    # Convert to local timezone (e.g., Dhaka time = UTC+6) for display
    try:
        local_tz = timezone(timedelta(hours=6)) # আপনার লোকাল টাইমজোন
        dt_local = dt_obj.astimezone(local_tz)
        return dt_local.strftime(format)
    except Exception as e:
         logging.error(f"Error formatting/converting datetime {value}: {e}")
         return value # ফলব্যাক হিসাবে আসল মান ফেরত দিন


# ফিল্টারটি Jinja-এর সাথে রেজিস্টার করুন
app.jinja_env.filters['datetimeformat'] = format_datetime

# --- Dropbox Helper Functions ---
def get_dropbox_client():
    """Initializes and returns a Dropbox client instance."""
    if not DROPBOX_ENABLED:
        logging.warning("Attempted to get Dropbox client, but backups are disabled.")
        return None
    try:
        # Use Refresh Token for long-term access without user interaction
        dbx = dropbox.Dropbox(
            app_key=DROPBOX_APP_KEY,
            app_secret=DROPBOX_APP_SECRET,
            oauth2_refresh_token=DROPBOX_REFRESH_TOKEN
        )
        dbx.users_get_current_account() # Test authentication
        logging.debug("Dropbox client initialized successfully.")
        return dbx
    except AuthError as e:
        logging.error(f"CRITICAL: Dropbox Authentication Error: {e}. Check credentials/token.")
        return None
    except Exception as e:
        logging.error(f"Error initializing Dropbox client: {e}", exc_info=True)
        return None

def _generate_direct_dropbox_link(url):
    """Modifies a Dropbox share URL to make it a direct download link (dl=1)."""
    if not url:
        return None
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        query_params['dl'] = ['1'] # Set dl=1 for direct download
        new_query = urlencode(query_params, doseq=True)
        # Reconstruct the URL
        direct_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))
        logging.debug(f"Generated direct Dropbox link: {direct_url}")
        return direct_url
    except Exception as e:
        logging.error(f"Failed to modify Dropbox URL '{url}' to direct link: {e}")
        return url # ফলব্যাক হিসাবে আসল URL ফেরত দিন

def backup_to_dropbox(local_filepath, saved_filename_db, file_id, user_id):
    """ফাইল Dropbox এ আপলোড করে, লিংক তৈরি করে এবং API এর মাধ্যমে DB আপডেট করে।"""
    if not DROPBOX_ENABLED:
        logging.info(f"Dropbox backup skipped (disabled) for file ID: {file_id}")
        return

    dbx = get_dropbox_client()
    if not dbx:
        logging.error(f"Dropbox backup failed for file ID {file_id}: Could not get client.")
        return

    dropbox_path = f"{DROPBOX_BACKUP_FOLDER}/{saved_filename_db}" # Use the unique saved filename
    logging.info(f"Starting Dropbox backup for file ID {file_id} to path: {dropbox_path}")

    direct_download_url = None
    final_dropbox_path = None

    try:
        # Upload the file (handles chunking for large files)
        with open(local_filepath, 'rb') as f:
            # Consider adjusting timeout for very large files if needed (SDK might handle?)
            file_metadata = dbx.files_upload(f.read(), dropbox_path, mode=dropbox.files.WriteMode('overwrite'))
        logging.info(f"File ID {file_id} successfully uploaded to Dropbox: {file_metadata.path_display}")
        final_dropbox_path = file_metadata.path_display # Store the path for API update

        # Create/get a shared link
        try:
            links = dbx.sharing_list_shared_links(path=final_dropbox_path, direct_only=True).links
            if links:
                shared_link_metadata = links[0]
                logging.debug(f"Found existing share link for {final_dropbox_path}")
            else:
                settings = dropbox.sharing.SharedLinkSettings(requested_visibility=dropbox.sharing.RequestedVisibility.public)
                shared_link_metadata = dbx.sharing_create_shared_link_with_settings(final_dropbox_path, settings=settings)
                logging.info(f"Created new share link for {final_dropbox_path}")

            original_url = shared_link_metadata.url
            direct_download_url = _generate_direct_dropbox_link(original_url)

        except ApiError as e_link:
            logging.error(f"Dropbox API error creating/getting share link for {final_dropbox_path} (File ID: {file_id}): {e_link}", exc_info=True)
            # Proceed without link if creation fails, but path exists
        except Exception as e_link_general:
             logging.error(f"Unexpected error during Dropbox link processing for file ID {file_id}: {e_link_general}", exc_info=True)

        # Update the database record via API (only if upload succeeded)
        if final_dropbox_path:
            update_payload = {
                "dropbox_link": direct_download_url, # Can be None if link failed
                "dropbox_path": final_dropbox_path
            }
            # Use expected_status=(200,) for PUT
            update_result = api_request('PUT', f'/api/users/{user_id}/files/{file_id}/dropbox_info', json=update_payload, expected_status=(200,))
            if isinstance(update_result, dict) and "_api_error" in update_result:
                logging.error(f"Failed to update Dropbox info in DB via API for file ID {file_id}: {update_result['_api_error']}")
                # Difficult to notify user here, just log
            else:
                logging.info(f"Successfully updated Dropbox info in DB via API for file ID {file_id}")
        else:
             logging.error(f"Cannot update DB with Dropbox info as upload might have failed or path is missing for file ID {file_id}.")


    except ApiError as e_upload:
        logging.error(f"Dropbox API error uploading file {local_filepath} to {dropbox_path} (File ID: {file_id}): {e_upload}", exc_info=True)
    except IOError as e_io:
        logging.error(f"IOError reading local file {local_filepath} for Dropbox upload (File ID: {file_id}): {e_io}", exc_info=True)
    except Exception as e_general_upload:
        logging.error(f"Unexpected error during Dropbox upload for file ID {file_id}: {e_general_upload}", exc_info=True)


# --- সਹੀ করা restore_from_dropbox ফাংশন ---
def restore_from_dropbox(dropbox_link, expected_local_path):
    """একটি Dropbox সরাসরি লিঙ্ক থেকে লোকাল পাথে ফাইল ডাউনলোড করে।"""
    if not dropbox_link:
        logging.warning(f"Restore attempt failed: No Dropbox link provided for {expected_local_path}.")
        return False

    logging.info(f"Attempting to restore file from Dropbox link to: {expected_local_path}")
    try:
        # লক্ষ্য ডিরেক্টরি বিদ্যমান আছে কিনা নিশ্চিত করুন
        os.makedirs(os.path.dirname(expected_local_path), exist_ok=True)

        # Use requests to download the direct link
        # ডাউনলোডের জন্য টাইমআউট বাড়ানো যেতে পারে
        response = requests.get(dropbox_link, stream=True, timeout=300) # ডাউনলোডের জন্য 5 মিনিটের টাইমআউট
        response.raise_for_status() # খারাপ প্রতিক্রিয়ার জন্য HTTPError উত্থাপন করুন (4xx বা 5xx)

        with open(expected_local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        logging.info(f"Successfully restored file from Dropbox to {expected_local_path}")
        return True

    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to download from Dropbox link {dropbox_link}: {e}")
        # Clean up potentially incomplete file
        if os.path.exists(expected_local_path):
            try:
                os.remove(expected_local_path)
                logging.debug(f"Cleaned up incomplete file after RequestException: {expected_local_path}")
            except OSError as ose: # নির্দিষ্ট ত্রুটি ধরুন এবং লগ করুন
                logging.warning(f"Could not remove incomplete file {expected_local_path} after RequestException: {ose}")
            except Exception as ex_clean: # অন্য কোনো ক্লীনআপ ত্রুটি ধরুন
                 logging.error(f"Unexpected error cleaning up file {expected_local_path} after RequestException: {ex_clean}")
        return False
    except IOError as e:
        logging.error(f"Failed to write restored file to {expected_local_path}: {e}")
         # এখানে ফাইল লেখার ত্রুটি হয়েছে, তাই সাধারণত ক্লীনআপের প্রয়োজন নেই কারণ ফাইল তৈরি/লেখা হয়নি
         # তবে যদি আংশিক লেখা হয়ে থাকে, তাহলে ডিলিট করা যেতে পারে
        if os.path.exists(expected_local_path):
            try:
                os.remove(expected_local_path)
                logging.debug(f"Cleaned up potentially incomplete file after IOError: {expected_local_path}")
            except OSError as ose:
                logging.warning(f"Could not remove incomplete file {expected_local_path} after IOError: {ose}")
            except Exception as ex_clean:
                 logging.error(f"Unexpected error cleaning up file {expected_local_path} after IOError: {ex_clean}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error during Dropbox restore to {expected_local_path}: {e}", exc_info=True)
        # Clean up potentially incomplete file
        if os.path.exists(expected_local_path):
            try:
                os.remove(expected_local_path)
                logging.debug(f"Cleaned up potentially incomplete file after general Exception: {expected_local_path}")
            except OSError as ose:
                logging.warning(f"Could not remove incomplete file {expected_local_path} after general Exception: {ose}")
            except Exception as ex_clean:
                 logging.error(f"Unexpected error cleaning up file {expected_local_path} after general Exception: {ex_clean}")
        return False

# --- Routes (Modified to use API calls) ---

# --- Authentication ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session: return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')
        name = request.form.get('name', '').strip()

        error = None
        if not email or '@' not in email or '.' not in email.split('@')[-1]: error = 'অনুগ্রহ করে একটি বৈধ ইমেইল ঠিকানা লিখুন।'
        elif not password: error = 'পাসওয়ার্ড প্রয়োজন।'
        elif len(password) < 6: error = 'পাসওয়ার্ড অন্তত ৬ অক্ষরের হতে হবে।'
        elif password != password_confirm: error = 'পাসওয়ার্ড দুটি মিলছে না।'
        elif len(name) > 50: error = 'নাম ৫০ অক্ষরের বেশি হতে পারবে না।'

        if error:
            flash(error, 'danger')
        else:
            # API কল করুন ব্যবহারকারী তৈরি করার জন্য
            payload = {"email": email, "password": password, "name": name or None}
            result = api_request('POST', '/api/users/signup', json=payload, expected_status=(201,))

            # handle_api_error এখানে ফ্ল্যাশ মেসেজ দেখাবে যদি সমস্যা হয়
            if not handle_api_error(result, "সাইন আপ করার সময় একটি ত্রুটি ঘটেছে।"):
                # API কল সফল (no error handled)
                logging.info(f"User signed up via API: {email}, Result: {result}")
                flash('সাইন আপ সফল হয়েছে! এখন লগইন করুন।', 'success')
                return redirect(url_for('login'))
            # else: API error was handled (flashed) by handle_api_error

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session: return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        error = None

        if not email or not password:
            error = 'অনুগ্রহ করে ইমেইল এবং পাসওয়ার্ড দিন।'
            flash(error, 'danger')
        else:
            # API কল করুন লগইন করার জন্য
            payload = {"email": email, "password": password}
            result = api_request('POST', '/api/users/login', json=payload, expected_status=(200,))

            # API ফলাফল পরীক্ষা করুন
            if isinstance(result, dict) and "_api_error" in result:
                 # API কল ব্যর্থ, কিন্তু নির্দিষ্ট ত্রুটি API থেকে আসতে পারে
                 if result.get("_status_code") == 401:
                     flash('ভুল ইমেইল অথবা পাসওয়ার্ড।', 'danger')
                 else:
                     # অন্যান্য API ত্রুটি handle_api_error দ্বারা হ্যান্ডেল হবে
                     handle_api_error(result, "লগইন করার সময় একটি ত্রুটি ঘটেছে।")
            elif result and 'id' in result:
                # লগইন সফল
                session.clear()
                session['user_id'] = result['id']
                session['email'] = result['email']
                session['user_name'] = result.get('name') # API থেকে নাম পান
                logging.info(f"User logged in: {session['email']} (ID: {session['user_id']})")
                next_url = session.pop('next_url', None)
                flash('লগইন সফল হয়েছে!', 'success')
                return redirect(next_url or url_for('home'))
            else:
                 # অপ্রত্যাশিত ফলাফল API থেকে
                 flash("লগইন করার সময় একটি অপ্রত্যাশিত ত্রুটি ঘটেছে।", 'danger')
                 logging.error(f"Unexpected API response during login for {email}: {result}")

    return render_template('login.html', login_page=True)

@app.route('/logout')
@login_required
def logout():
    user_email = session.get('email', 'Unknown User')
    user_id = session.get('user_id')
    session.clear()
    flash('আপনি সফলভাবে লগ আউট হয়েছেন।', 'info')
    logging.info(f"User logged out: {user_email} (ID: {user_id})")
    return redirect(url_for('login'))

# --- Account Management ---
@app.route('/account')
@login_required
def account():
    # g.user ইতিমধ্যে login_required ডেকোরেটরে API থেকে লোড করা হয়েছে
    if not g.user:
        flash("ব্যবহারকারীর তথ্য লোড করা যায়নি।", "warning")
        return redirect(url_for('login'))
    # g.user এখন একটি dictionary
    return render_template('account.html', user=g.user)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    user_id = session['user_id']
    new_name = request.form.get('name', '').strip()

    if len(new_name) > 50:
        flash("নাম ৫০ অক্ষরের বেশি হতে পারবে না।", "warning")
        return redirect(url_for('account'))

    # API কল করুন প্রোফাইল আপডেট করার জন্য
    payload = {"name": new_name or None}
    result = api_request('PUT', f'/api/users/{user_id}/profile', json=payload, expected_status=(200,))

    if not handle_api_error(result, "প্রোফাইল আপডেট করার সময় একটি ত্রুটি ঘটেছে।"):
        session['user_name'] = new_name or None # সেশন আপডেট করুন
        # g.user ও আপডেট করা উচিত যদি এটি এই রিকোয়েস্টে আবার ব্যবহার করা হয়
        if hasattr(g, 'user') and g.user: g.user['name'] = new_name or None
        flash('আপনার প্রোফাইল সফলভাবে আপডেট করা হয়েছে।', 'success')
        logging.info(f"User profile updated for ID: {user_id}. New name: '{new_name or None}'")

    return redirect(url_for('account'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    user_id = session['user_id']

    error = None
    if not current_password or not new_password or not confirm_password: error = 'অনুগ্রহ করে সমস্ত পাসওয়ার্ড ফিল্ড পূরণ করুন।'
    elif new_password != confirm_password: error = 'নতুন পাসওয়ার্ড দুটি মিলছে না।'
    elif len(new_password) < 6: error = 'নতুন পাসওয়ার্ড অন্তত ৬ অক্ষরের হতে হবে।'

    if error:
        flash(error, 'danger')
        return redirect(url_for('account'))

    # API কল করুন পাসওয়ার্ড পরিবর্তন করার জন্য (বর্তমান পাসওয়ার্ড সহ)
    payload = {"current_password": current_password, "new_password": new_password}
    result = api_request('PUT', f'/api/users/{user_id}/password_change', json=payload, expected_status=(200,))

    # handle_api_error এখানে ভুল বর্তমান পাসওয়ার্ড (401) বা অন্যান্য ত্রুটি হ্যান্ডেল করবে
    if not handle_api_error(result, "পাসওয়ার্ড পরিবর্তন করার সময় একটি ত্রুটি ঘটেছে।"):
         flash('আপনার পাসওয়ার্ড সফলভাবে পরিবর্তন করা হয়েছে।', 'success')
         logging.info(f"User changed password successfully for ID: {user_id}")
    # else: API error (like wrong current password) handled by handle_api_error

    return redirect(url_for('account'))

# --- Forgot/Reset Password ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password_request():
    if 'user_id' in session: return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email or '@' not in email:
            flash('অনুগ্রহ করে একটি বৈধ ইমেইল ঠিকানা লিখুন।', 'warning'); return redirect(url_for('forgot_password_request'))

        # API থেকে ব্যবহারকারী খুঁজুন (শুধুমাত্র আইডি দরকার)
        user_data = api_request('GET', '/api/users/by_email', params={'email': email}, expected_status=(200,))

        # API ত্রুটি হ্যান্ডেল করুন (যেমন সার্ভার ডাউন)
        if isinstance(user_data, dict) and "_api_error" in user_data:
            handle_api_error(user_data, "ব্যবহারকারী খোঁজার সময় ডাটাবেস ত্রুটি ঘটেছে।")
            # এখানে লগইন পেজে রিডাইরেক্ট করা ভালো হতে পারে
            return redirect(url_for('login'))

        flash_message = "যদি এই ইমেইল ঠিকানাটি দিয়ে কোনো অ্যাকাউন্ট খোলা হয়ে থাকে, তবে পাসওয়ার্ড রিসেট করার লিঙ্ক সহ একটি ইমেইল পাঠানো হয়েছে।"
        email_sent_or_skipped = False # ইমেইল পাঠানো হয়েছে বা ব্যবহারকারী নেই তা ট্র্যাক করতে

        # API কল সফল হয়েছে এবং ব্যবহারকারী পাওয়া গেছে (ফলাফল খালি নয় এবং আইডি আছে)
        if user_data and isinstance(user_data, dict) and 'id' in user_data:
            user_id = user_data['id']
            token = secrets.token_urlsafe(32)
            # UTC তে সময় নিন
            expiry_time = datetime.now(timezone.utc) + timedelta(hours=1)
            # API এর জন্য ISO ফরম্যাট স্ট্রিং
            expiry_iso = expiry_time.isoformat()

            # API কল করুন রিসেট টোকেন সেট করার জন্য
            token_payload = {"token": token, "expiry": expiry_iso}
            # PUT এর জন্য 200 আশা করা হচ্ছে
            token_result = api_request('PUT', f'/api/users/{user_id}/reset_token', json=token_payload, expected_status=(200,))

            if not handle_api_error(token_result, "পাসওয়ার্ড রিসেট প্রক্রিয়া শুরু করতে সমস্যা হয়েছে।"):
                reset_url = url_for('reset_password', token=token, _external=True)
                logging.info(f"Generated password reset token for email: {email}")
                if send_reset_email(email, reset_url):
                     email_sent_or_skipped = True
                else:
                     flash("পাসওয়ার্ড রিসেট ইমেইল পাঠাতে সমস্যা হয়েছে।", "danger")
            # else: API error handled while setting token

        else: # ব্যবহারকারী পাওয়া যায়নি (API 200 OK কিন্তু খালি ফলাফল) বা অন্য কোনো সমস্যা
             logging.info(f"Forgot password attempt for non-existent or failed API lookup email: {email}")
             email_sent_or_skipped = True # ব্যবহারকারী না থাকলেও ইমেইল না পাঠিয়ে স্কিপ করা হয়েছে

        # যদি কোনো গুরুতর ত্রুটি না ঘটে থাকে, তবে জেনেরিক মেসেজ দেখান
        # Check if messages were flashed *within this request*
        flashed_messages = session.get('_flashed_messages', [])
        # যদি ইমেইল পাঠানো হয়ে থাকে বা ব্যবহারকারী না থাকায় স্কিপ করা হয়ে থাকে এবং আগে কোনো danger মেসেজ না দেখানো হয়ে থাকে
        if email_sent_or_skipped and not any('danger' in msg[0] for msg in flashed_messages if isinstance(msg, tuple)):
             flash(flash_message, 'info')

        return redirect(url_for('login'))

    return render_template('forgot_password_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if 'user_id' in session: return redirect(url_for('home'))

    # API কল করে টোকেন যাচাই করুন এবং ব্যবহারকারী পান
    # GET এর জন্য 200 আশা করা হচ্ছে
    user_data = api_request('GET', f'/api/users/by_token/{token}', expected_status=(200,))

    # handle_api_error 404 এর জন্য ফ্ল্যাশ দেখাবে না, কিন্তু আমরা এখানে দেখাতে চাই
    if isinstance(user_data, dict) and "_api_error" in user_data:
        if user_data.get("_status_code") == 404:
             flash('পাসওয়ার্ড রিসেট লিঙ্কটি অবৈধ অথবা মেয়াদোত্তীর্ণ। অনুগ্রহ করে আবার চেষ্টা করুন।', 'danger')
        else:
             handle_api_error(user_data, "টোকেন যাচাই করার সময় একটি ত্রুটি ঘটেছে।")
        return redirect(url_for('forgot_password_request'))
    elif not user_data or 'id' not in user_data: # অপ্রত্যাশিত ফলাফল বা খালি
        flash('পাসওয়ার্ড রিসেট লিঙ্কটি অবৈধ অথবা মেয়াদোত্তীর্ণ। অনুগ্রহ করে আবার চেষ্টা করুন।', 'danger')
        return redirect(url_for('forgot_password_request'))


    user_id = user_data['id']
    user_email = user_data['email'] # ফর্ম দেখানোর জন্য প্রয়োজন হতে পারে

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        submitted_token = request.form.get('token') # Hidden field

        if token != submitted_token:
             logging.warning(f"Token mismatch during password reset POST. URL: {token}, Form: {submitted_token}")
             flash('অবৈধ অনুরোধ। লিঙ্ক পরিবর্তন করা হয়েছে।', 'danger')
             return redirect(url_for('forgot_password_request'))

        error = None
        if not new_password or not confirm_password: error = 'অনুগ্রহ করে উভয় পাসওয়ার্ড ফিল্ড পূরণ করুন।'
        elif new_password != confirm_password: error = 'পাসওয়ার্ড দুটি মিলছে না।'
        elif len(new_password) < 6: error = 'নতুন পাসওয়ার্ড অন্তত ৬ অক্ষরের হতে হবে।'

        if error:
            flash(error, 'danger')
            # ইমেইল পাস করুন টেমপ্লেটে যদি প্রয়োজন হয়
            return render_template('reset_password_form.html', token=token, email=user_email)

        # API কল করুন পাসওয়ার্ড রিসেট করার জন্য
        reset_payload = {"new_password": new_password}
        # PUT এর জন্য 200 আশা করা হচ্ছে
        reset_result = api_request('PUT', f'/api/users/{user_id}/password_reset', json=reset_payload, expected_status=(200,))

        if not handle_api_error(reset_result, "পাসওয়ার্ড রিসেট করার সময় ডাটাবেস ত্রুটি ঘটেছে।"):
            flash('আপনার পাসওয়ার্ড সফলভাবে রিসেট করা হয়েছে। এখন লগইন করুন।', 'success')
            logging.info(f"User password reset successful for: {user_email} (ID: {user_id})")
            return redirect(url_for('login'))
        # else: API error handled, show form again

    # GET request: show the form
    logging.debug(f"Displaying password reset form for token: {token} (User ID: {user_id})")
    return render_template('reset_password_form.html', token=token, email=user_email)


# --- Core Functionality Routes ---

@app.route('/')
@login_required
def home():
    user_id = session['user_id']
    folders = []
    root_files = []

    # API থেকে ফোল্ডার পান
    folders_result = api_request('GET', f'/api/users/{user_id}/folders', expected_status=(200,))
    # 404 এখানে ত্রুটি নয়, শুধু খালি তালিকা হতে পারে
    if isinstance(folders_result, dict) and "_api_error" in folders_result:
         handle_api_error(folders_result, "ফোল্ডার লোড করার সময় ত্রুটি ঘটেছে।")
    elif isinstance(folders_result, list):
         folders = folders_result

    # API থেকে রুট ফাইল পান
    files_result = api_request('GET', f'/api/users/{user_id}/files/root', expected_status=(200,))
    if isinstance(files_result, dict) and "_api_error" in files_result:
         handle_api_error(files_result, "ফাইল লোড করার সময় ত্রুটি ঘটেছে।")
    elif isinstance(files_result, list):
         root_files = files_result

    logging.debug(f"Home page loaded for user {user_id}. Folders: {len(folders)}, Root Files: {len(root_files)}")
    # ফলাফল এখন dict এর লিস্ট
    return render_template('home.html', folders=folders, root_files=root_files)

@app.route('/folder/<int:folder_id>')
@login_required
def view_folder(folder_id):
    user_id = session['user_id']
    folder = None
    files_in_folder = []
    folders_list = [] # Move modal এর জন্য

    # API থেকে ফোল্ডারের বিবরণ পান
    # GET এর জন্য 200 আশা করা হচ্ছে
    folder_result = api_request('GET', f'/api/users/{user_id}/folders/{folder_id}', expected_status=(200,))
    # 404 এর জন্য handle_api_error ফ্ল্যাশ দেখাবে না, আমরা এখানে রিডাইরেক্ট করব
    if isinstance(folder_result, dict) and folder_result.get("_status_code") == 404:
         flash('ফোল্ডার খুঁজে পাওয়া যায়নি অথবা আপনার এই ফোল্ডার দেখার অনুমতি নেই।', 'danger')
         return redirect(url_for('home'))
    elif handle_api_error(folder_result, f"ফোল্ডার {folder_id} লোড করার সময় ত্রুটি ঘটেছে।"):
         # অন্যান্য API ত্রুটি
         return redirect(url_for('home'))
    else:
         folder = folder_result # folder is a dict

    # API থেকে এই ফোল্ডারের ফাইল পান
    files_result = api_request('GET', f'/api/users/{user_id}/folders/{folder_id}/files', expected_status=(200,))
    if isinstance(files_result, dict) and "_api_error" in files_result:
         handle_api_error(files_result, f"ফোল্ডার {folder_id} এর ফাইল লোড করার সময় ত্রুটি ঘটেছে।")
    elif isinstance(files_result, list):
         files_in_folder = files_result

    # API থেকে সব ফোল্ডারের তালিকা পান (Move modal এর জন্য)
    all_folders_result = api_request('GET', f'/api/users/{user_id}/folders', expected_status=(200,))
    if isinstance(all_folders_result, dict) and "_api_error" in all_folders_result:
         handle_api_error(all_folders_result, "ফোল্ডার তালিকা লোড করার সময় ত্রুটি ঘটেছে।")
    elif isinstance(all_folders_result, list):
         folders_list = all_folders_result

    folder_name = folder.get('name', 'N/A') if folder else 'N/A'
    logging.debug(f"Folder view loaded: User={user_id}, Folder={folder_id} ('{folder_name}'), Files: {len(files_in_folder)}")
    # folder এবং files এখন dict/list of dicts
    return render_template('folder_view.html', folder=folder, files=files_in_folder, folders=folders_list)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    user_id = session['user_id']
    if 'file_upload' not in request.files:
        flash('কোনো ফাইল নির্বাচন করা হয়নি।', 'warning')
        return redirect(request.referrer or url_for('home'))

    file = request.files['file_upload']
    folder_id_str = request.form.get('folder_id') # 'root' বা আইডি হতে পারে

    if file.filename == '':
        flash('কোনো ফাইল নির্বাচন করা হয়নি।', 'warning')
        return redirect(request.referrer or url_for('home'))

    original_filename = secure_filename(file.filename)
    file_ext = ''
    if '.' in original_filename:
        file_ext = original_filename.rsplit('.', 1)[1].lower()
    # UUID ব্যবহার করে অনন্য ফাইলের নাম তৈরি করুন
    unique_filename = f"{uuid.uuid4()}{'.' + file_ext if file_ext else ''}"

    # ব্যবহারকারী-নির্দিষ্ট আপলোড ডিরেক্টরি তৈরি করুন (লোকাল)
    user_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], f'user_{user_id}')
    try:
        os.makedirs(user_upload_dir, exist_ok=True)
    except OSError as e:
        logging.error(f"Could not create upload directory '{user_upload_dir}': {e}", exc_info=True)
        flash("আপলোড ডিরেক্টরি তৈরি করা যায়নি।", "danger")
        return redirect(request.referrer or url_for('home'))

    # ফাইল সংরক্ষণের জন্য সম্পূর্ণ লোকাল পাথ
    saved_filepath_on_disk = os.path.join(user_upload_dir, unique_filename)
    # ডিবিতে সংরক্ষণের জন্য আপেক্ষিক পাথ (API তে পাঠানো হবে)
    db_filepath = os.path.join(f'user_{user_id}', unique_filename).replace("\\", "/") # ফরওয়ার্ড স্ল্যাশ ব্যবহার করুন
    # MIME টাইপ নির্ধারণ করুন
    mime_type = file.mimetype or mimetypes.guess_type(original_filename)[0] or 'application/octet-stream'

    logging.info(f"Upload prep: User={user_id}, Original='{original_filename}', SavePath='{saved_filepath_on_disk}', DBPath='{db_filepath}', Mime='{mime_type}'")

    local_save_success = False
    api_record_success = False
    new_file_id = None

    try:
        # ১. ফাইল লোকালি সেভ করুন
        file.save(saved_filepath_on_disk)
        local_save_success = True
        logging.info(f"File saved to disk: {saved_filepath_on_disk}")

        # ২. API কল করে ডাটাবেসে রেকর্ড তৈরি করুন
        folder_id = None # রুটের জন্য ডিফল্ট
        if folder_id_str and folder_id_str != 'root':
            try:
                folder_id = int(folder_id_str)
                # folder_id এর বৈধতা API এন্ডপয়েন্টে পরীক্ষা করা হবে
            except ValueError:
                flash('অবৈধ ফোল্ডার আইডি ফর্ম্যাটে। ফাইলটি রুটে সেভ করা হচ্ছে।', 'warning');
                folder_id = None

        payload = {
            "original_filename": original_filename,
            "saved_filename": unique_filename,
            "filepath": db_filepath, # লোকাল সার্ভারের পাথ
            "mime_type": mime_type,
            "folder_id": folder_id # None অথবা integer
        }
        # POST এর জন্য 201 আশা করা হচ্ছে
        api_result = api_request('POST', f'/api/users/{user_id}/files', json=payload, expected_status=(201,))

        # handle_api_error এখানে অবৈধ folder_id (400) বা অন্যান্য ত্রুটি হ্যান্ডেল করবে
        if not handle_api_error(api_result, "ফাইল রেকর্ড তৈরি করার সময় ডাটাবেস ত্রুটি ঘটেছে।"):
             if api_result and 'id' in api_result:
                 new_file_id = api_result['id']
                 api_record_success = True
                 flash(f"ফাইল '{original_filename}' সফলভাবে আপলোড হয়েছে!", 'success')
                 logging.info(f"File record created via API for user {user_id}, file {unique_filename}, DB ID: {new_file_id}")
             else:
                 # এটি ঘটা উচিত নয় যদি স্ট্যাটাস 201 হয়, কিন্তু নিরাপদ থাকার জন্য চেক করুন
                 logging.error(f"API did not return file ID after creating record for {unique_filename}, Response: {api_result}")
                 flash("ফাইল আপলোড হয়েছে কিন্তু ডাটাবেসে সংরক্ষণে সমস্যা হয়েছে।", "danger")
        # else: API error handled (e.g., invalid folder id sent)

        # ৩. Dropbox ব্যাকআপ ট্রিগার করুন (যদি লোকাল সেভ এবং API রেকর্ড সফল হয়)
        # নিশ্চিত করুন new_file_id পাওয়া গেছে
        if local_save_success and api_record_success and new_file_id is not None:
             # ব্যাকগ্রাউন্ড টাস্ক বিবেচনা করুন যদি এটি দীর্ঘ হয়
             backup_to_dropbox(saved_filepath_on_disk, unique_filename, new_file_id, user_id)
        elif not api_record_success and local_save_success:
            # লোকাল ফাইল সেভ হয়েছে কিন্তু ডিবিতে যায়নি, লোকাল ফাইল ডিলিট করা উচিত?
            logging.warning(f"API record creation failed for {unique_filename} after local save. Orphaned file exists: {saved_filepath_on_disk}. Consider cleanup.")
            # আপাতত ফাইল রেখে দিন
            # delete_physical_file(db_filepath) # <-- বিবেচনা করুন

    except Exception as e:
        # লোকাল ফাইল সেভ করার সময় ত্রুটি হতে পারে
        logging.error(f"Upload Unexpected Error (likely during file save or pre-API): {e}", exc_info=True)
        flash(f"ফাইল '{original_filename}' আপলোড করার সময় একটি অপ্রত্যাশিত ত্রুটি ঘটেছে।", 'danger')
        # যদি লোকাল ফাইল তৈরি হয়ে থাকে কিন্তু পরে ত্রুটি হয়
        if os.path.exists(saved_filepath_on_disk):
            delete_physical_file(db_filepath) # ক্লীনআপের চেষ্টা করুন
    finally:
        # যদি API রেকর্ড ব্যর্থ হয় কিন্তু লোকাল ফাইল সেভ সফল হয় (উপরের elif দ্বারা কভার করা)
        # যদি লোকাল সেভ ব্যর্থ হয়, ফাইল তৈরি হবে না
        pass

    return redirect(request.referrer or url_for('home'))


@app.route('/create_folder', methods=['POST'])
@login_required
def create_folder():
    user_id = session['user_id']
    folder_name = request.form.get('folder_name', '').strip()

    error = None
    if not folder_name: error = 'ফোল্ডারের নাম খালি রাখা যাবে না।'
    elif len(folder_name) > 100: error = "ফোল্ডারের নাম ১০০ অক্ষরের বেশি হতে পারবে না।"

    if error:
        flash(error, 'warning')
    else:
        # API কল করুন ফোল্ডার তৈরি করার জন্য
        payload = {"name": folder_name}
        # POST এর জন্য 201 আশা করা হচ্ছে
        result = api_request('POST', f'/api/users/{user_id}/folders', json=payload, expected_status=(201,))

        # handle_api_error ডুপ্লিকেট ফোল্ডার (409) বা অন্যান্য ত্রুটি হ্যান্ডেল করবে
        if not handle_api_error(result, "ফোল্ডার তৈরি করার সময় ডাটাবেস ত্রুটি ঘটেছে।"):
             # সফল হলে API থেকে আইডি পাওয়া যেতে পারে (result['id'])
             flash(f"ফোল্ডার '{folder_name}' তৈরি হয়েছে!", 'success')
             logging.info(f"Folder '{folder_name}' created for user {user_id} via API. Result: {result}")
        # else: API error (like duplicate) handled

    return redirect(request.referrer or url_for('home'))

# --- ফাইল পরিবেশন, ডাউনলোড, শেয়ারিং রুটগুলি ---

@app.route('/serve_file/<filename>')
def serve_file(filename):
    """ফাইল পরিবেশন করে, প্রয়োজনে Dropbox থেকে পুনরুদ্ধার করে। API থেকে মেটাডেটা পায়।"""
    logging.debug(f"Attempting to serve file: {filename}")
    user_id = session.get('user_id') # লগইন করা ব্যবহারকারীর আইডি (যদি থাকে)

    # API থেকে ফাইলের তথ্য পান (পরিবেশনের জন্য প্রয়োজনীয়: filepath, user_id, share_token, dropbox_link)
    # GET এর জন্য 200 আশা করা হচ্ছে
    file_info_result = api_request('GET', f'/api/files/serve_info/{filename}', expected_status=(200,))

    # handle_api_error 404 এর জন্য ফ্ল্যাশ দেখাবে না
    if isinstance(file_info_result, dict) and file_info_result.get("_status_code") == 404:
        logging.warning(f"File info not found via API for serving: {filename}")
        abort(404)
    elif handle_api_error(file_info_result, f"ফাইল '{filename}' এর তথ্য পেতে ত্রুটি।"):
        # অন্যান্য API ত্রুটি
        abort(500) # অথবা 404? সার্ভার ত্রুটি হলে 500 উপযুক্ত
    elif not file_info_result or 'filepath' not in file_info_result:
        # অপ্রত্যাশিত ফলাফল
        logging.error(f"Unexpected API response for serve_info/{filename}: {file_info_result}")
        abort(404)

    file_info = file_info_result # এটি এখন একটি dict

    # অনুমতি পরীক্ষা (আগের মতোই, কিন্তু file_info এখন dict)
    is_owner = user_id is not None and file_info.get('user_id') == user_id
    request_token = request.args.get('token')
    is_shared_access = file_info.get('share_token') is not None and file_info['share_token'] == request_token

    # অনুমতি পরীক্ষা করুন
    # যদি মালিক হন অথবা একটি বৈধ শেয়ার টোকেন লিঙ্কের মাধ্যমে অ্যাক্সেস করা হয় তবে অনুমতি দিন
    if not is_owner and not is_shared_access:
        logging.warning(f"Unauthorized attempt to access file '{filename}' by user '{user_id or 'anonymous'}'")
        abort(403) # Forbidden


    base_directory = os.path.abspath(os.path.join(app.root_path, app.config['UPLOAD_FOLDER']))
    relative_filepath = file_info['filepath'] # API থেকে পাওয়া পাথ
    expected_file_path = os.path.normpath(os.path.join(base_directory, relative_filepath))

    # --- Dropbox Restore Logic (অপরিবর্তিত) ---
    if not os.path.isfile(expected_file_path):
        logging.warning(f"Local file not found: {expected_file_path}. Attempting Dropbox restore.")
        dropbox_link = file_info.get('dropbox_link') # API ফলাফল থেকে লিঙ্ক পান
        if dropbox_link:
            if not restore_from_dropbox(dropbox_link, expected_file_path):
                logging.error(f"Dropbox restore failed for {filename}. File unavailable.")
                abort(404) # পুনরুদ্ধার ব্যর্থ হলে ফাইল অনুপলব্ধ
        else:
            # লোকাল ফাইল নেই এবং ড্রপবক্স লিঙ্কও নেই
            logging.error(f"Local file missing and no Dropbox link found via API for {filename}. File unavailable.")
            abort(404) # ফাইল সত্যিই হারিয়ে গেছে
    # --- End Dropbox Restore Logic ---

    # ফাইল এখন বিদ্যমান থাকা উচিত
    if not os.path.isfile(expected_file_path):
         logging.error(f"Physical file still not found after restore check at: {expected_file_path}")
         abort(404) # যদি কোনো কারণে পুনরুদ্ধার ব্যর্থ হয় বা চেক কাজ না করে

    try:
        # ফাইল পরিবেশন করুন (ব্রাউজার দেখানোর চেষ্টা করবে)
        return send_from_directory(base_directory, relative_filepath, as_attachment=False)
    except Exception as e:
        logging.error(f"Error sending file '{relative_filepath}' (filename: {filename}): {e}", exc_info=True)
        abort(500)


@app.route('/view_file/<int:file_id>')
@login_required
def view_file(file_id):
    user_id = session['user_id']

    # API থেকে ফাইলের বিবরণ পান (সবকিছু দরকার হতে পারে)
    # GET এর জন্য 200 আশা করা হচ্ছে
    file_info_result = api_request('GET', f'/api/users/{user_id}/files/{file_id}', expected_status=(200,))

    # handle_api_error 404 হ্যান্ডেল করবে (ফ্ল্যাশ ছাড়া)
    if isinstance(file_info_result, dict) and file_info_result.get("_status_code") == 404:
        flash('ফাইলটি খুঁজে পাওয়া যায়নি অথবা দেখার অনুমতি নেই।', 'danger')
        return redirect(request.referrer or url_for('home'))
    elif handle_api_error(file_info_result, "ফাইল দেখার সময় ত্রুটি ঘটেছে।"):
        return redirect(request.referrer or url_for('home'))
    elif not file_info_result: # অপ্রত্যাশিত ফলাফল
        flash('ফাইল দেখার সময় একটি অপ্রত্যাশিত ত্রুটি ঘটেছে।', 'danger')
        return redirect(request.referrer or url_for('home'))

    file_info = file_info_result # এটি একটি dict

    # MIME টাইপের উপর ভিত্তি করে প্রিভিউ টাইপ নির্ধারণ করুন
    mime_type = file_info.get('mime_type', '')
    preview_type = None
    if mime_type.startswith('image/'): preview_type = 'image'
    elif mime_type.startswith('video/'): preview_type = 'video'
    elif mime_type.startswith('audio/'): preview_type = 'audio'
    elif mime_type == 'application/pdf': preview_type = 'pdf'
    elif mime_type.startswith('text/'): preview_type = 'text'

    logging.debug(f"Viewing file ID {file_id}: Mime='{mime_type}', PreviewType='{preview_type}'")

    # ফাইল পরিবেশন করার URL তৈরি করুন (serve_file রুট ব্যবহার করে)
    file_serve_url = url_for('serve_file', filename=file_info['saved_filename'])

    return render_template('view_file.html', file=file_info, preview_type=preview_type, file_serve_url=file_serve_url)


@app.route('/download_file/<int:file_id>')
@login_required
def download_file(file_id):
    user_id = session['user_id']

    # API থেকে ফাইলের তথ্য পান (filepath, original_filename, dropbox_link প্রয়োজন)
    # GET এর জন্য 200 আশা করা হচ্ছে
    file_info_result = api_request('GET', f'/api/users/{user_id}/files/{file_id}', expected_status=(200,))

    # handle_api_error 404 হ্যান্ডেল করবে (ফ্ল্যাশ ছাড়া)
    if isinstance(file_info_result, dict) and file_info_result.get("_status_code") == 404:
        flash('ফাইলটি ডাউনলোড করার জন্য খুঁজে পাওয়া যায়নি বা অনুমতি নেই।', 'danger')
        return redirect(request.referrer or url_for('home'))
    elif handle_api_error(file_info_result, "ফাইল ডাউনলোডের জন্য তথ্য পেতে ত্রুটি ঘটেছে।"):
        return redirect(request.referrer or url_for('home'))
    elif not file_info_result or 'filepath' not in file_info_result:
        flash('ফাইল ডাউনলোডের জন্য তথ্য পেতে একটি অপ্রত্যাশিত ত্রুটি ঘটেছে।', 'danger')
        return redirect(request.referrer or url_for('home'))

    file_info = file_info_result # এটি একটি dict
    base_directory = os.path.abspath(os.path.join(app.root_path, app.config['UPLOAD_FOLDER']))
    relative_filepath = file_info['filepath']
    expected_file_path = os.path.normpath(os.path.join(base_directory, relative_filepath))
    original_filename = file_info.get('original_filename', 'download') # ডিফল্ট নাম

    # --- Dropbox Restore Logic (ডাউনলোডের জন্যও প্রয়োজন) ---
    if not os.path.isfile(expected_file_path):
         logging.warning(f"Local file {expected_file_path} not found for download. Attempting restore.")
         dropbox_link = file_info.get('dropbox_link') # API থেকে পাওয়া লিঙ্ক
         if dropbox_link:
              if not restore_from_dropbox(dropbox_link, expected_file_path):
                   logging.error(f"Restore failed for download of file ID {file_id}.")
                   flash('দুঃখিত, ফাইলটি সার্ভারে পাওয়া যায়নি এবং পুনরুদ্ধার করা সম্ভব হয়নি।', 'error')
                   return redirect(request.referrer or url_for('home'))
              # পুনরুদ্ধার সফল হলে, নিচে এগিয়ে যান
         else:
              # লোকাল ফাইল নেই, লিঙ্কও নেই
              logging.error(f"Local file missing and no Dropbox link for download of file ID {file_id}.")
              flash('দুঃখিত, ফাইলটি সার্ভারে খুঁজে পাওয়া যাচ্ছে না।', 'error')
              return redirect(request.referrer or url_for('home'))
    # --- End Dropbox Restore Logic ---

    # ফাইল এখন বিদ্যমান থাকা উচিত
    if not os.path.isfile(expected_file_path):
         logging.error(f"File still not found at {expected_file_path} even after restore check for download.")
         flash('ফাইল ডাউনলোড করার সময় একটি অপ্রত্যাশিত ত্রুটি ঘটেছে।', 'danger')
         return redirect(request.referrer or url_for('home'))

    try:
        logging.info(f"User {user_id} downloading file ID {file_id} ('{original_filename}')")
        # ডাউনলোড করতে বাধ্য করুন
        return send_from_directory(
            base_directory,
            relative_filepath,
            as_attachment=True,
            download_name=original_filename # আসল নাম ব্যবহার করুন
        )
    except Exception as e:
        logging.error(f"Error sending file for download '{relative_filepath}' (ID: {file_id}): {e}", exc_info=True)
        flash('ফাইল ডাউনলোড করার সময় একটি ত্রুটি ঘটেছে।', 'danger')
        return redirect(request.referrer or url_for('home'))


@app.route('/move_file/<int:file_id>', methods=['POST'])
@login_required
def move_file(file_id):
    user_id = session['user_id']
    target_folder_id_str = request.form.get('target_folder_id') # 'root' বা একটি আইডি হতে পারে

    target_folder_id = None # রুটের জন্য ডিফল্ট
    if target_folder_id_str != 'root':
        try:
            target_folder_id = int(target_folder_id_str)
        except (ValueError, TypeError):
            flash('অবৈধ টার্গেট ফোল্ডার আইডি।', 'danger')
            return redirect(request.referrer or url_for('home'))

    # API কল করুন ফাইল মুভ করার জন্য
    payload = {"target_folder_id": target_folder_id} # None অথবা integer
    # PUT এর জন্য 200 আশা করা হচ্ছে
    result = api_request('PUT', f'/api/users/{user_id}/files/{file_id}/move', json=payload, expected_status=(200,))

    # handle_api_error 404 (file not found) বা 400 (invalid target folder) হ্যান্ডেল করবে
    if not handle_api_error(result, "ফাইল মুভ করার সময় ডাটাবেস ত্রুটি ঘটেছে।"):
         flash('ফাইল সফলভাবে মুভ করা হয়েছে।', 'success')
         logging.info(f"File ID {file_id} moved to folder {target_folder_id} by user {user_id} via API")
    # else: API error handled

    return redirect(request.referrer or url_for('home'))


@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    user_id = session['user_id']

    # API কল করুন ফাইল ট্র্যাশে পাঠানোর জন্য (সফট ডিলিট)
    # PUT এর জন্য 200 আশা করা হচ্ছে
    result = api_request('PUT', f'/api/users/{user_id}/files/{file_id}/trash', expected_status=(200,))

    # handle_api_error 404 (file not found) হ্যান্ডেল করবে
    if not handle_api_error(result, "ফাইল ট্র্যাশে পাঠানোর সময় ডাটাবেস ত্রুটি ঘটেছে।"):
         flash('ফাইলটি ট্র্যাশে পাঠানো হয়েছে।', 'success')
         logging.info(f"File ID {file_id} moved to trash by user {user_id} via API")
    # else: API error handled

    return redirect(request.referrer or url_for('home'))


@app.route('/trash')
@login_required
def trash():
    user_id = session['user_id']
    deleted_files = []

    # API থেকে ট্র্যাশ করা ফাইলগুলির তালিকা পান
    # GET এর জন্য 200 আশা করা হচ্ছে
    result = api_request('GET', f'/api/users/{user_id}/trash', expected_status=(200,))

    if isinstance(result, dict) and "_api_error" in result:
         handle_api_error(result, "ট্র্যাশ লোড করার সময় ত্রুটি ঘটেছে।")
    elif isinstance(result, list):
         # তারিখ ফরম্যাটিং করার জন্য ডেটাবেস থেকে আসা স্ট্রিং ব্যবহার করা হবে Jinja ফিল্টারে
         deleted_files = result

    logging.debug(f"Trash view loaded for user {user_id}. Items: {len(deleted_files)}")
    # deleted_files এখন dict এর লিস্ট
    return render_template('trash.html', deleted_files=deleted_files)


@app.route('/restore_file/<int:file_id>', methods=['POST'])
@login_required
def restore_file(file_id):
    user_id = session['user_id']

    # API কল করুন ফাইল পুনরুদ্ধার করার জন্য
    # PUT এর জন্য 200 আশা করা হচ্ছে
    result = api_request('PUT', f'/api/users/{user_id}/files/{file_id}/restore', expected_status=(200,))

    # handle_api_error 404 (file not in trash) হ্যান্ডেল করবে
    if not handle_api_error(result, "ফাইল পুনরুদ্ধার করার সময় ডাটাবেস ত্রুটি ঘটেছে।"):
         restored_to_root = result.get('restored_to_root', False)
         # পুনরুদ্ধার সফল
         if restored_to_root:
              flash('ফাইলটির মূল ফোল্ডারটি আর নেই, তাই ফাইলটি রুটে রিস্টোর করা হচ্ছে।', 'warning')
         flash('ফাইলটি সফলভাবে রিস্টোর করা হয়েছে।', 'success')
         logging.info(f"File ID {file_id} restored by user {user_id} via API")
    # else: API error handled

    return redirect(url_for('trash'))


@app.route('/delete_permanently/<int:file_id>', methods=['POST'])
@login_required
def delete_permanently(file_id):
    user_id = session['user_id']

    # সীমাবদ্ধতা: আমরা এখানে ফাইলের লোকাল পাথ নির্ভরযোগ্যভাবে জানি না।
    # তাই, আমরা শুধু ডিবি রেকর্ড ডিলিট করার জন্য API কল করব।
    # ফিজিক্যাল ফাইল ডিলিট এই মুহূর্তে সম্ভব নয়।

    logging.warning(f"Attempting permanent delete for file ID {file_id}. Only DB record will be deleted via API. Physical file may remain.")

    # API কল করুন ডিবি রেকর্ড স্থায়ীভাবে ডিলিট করার জন্য
    # DELETE এর জন্য 200 বা 204 আশা করা হচ্ছে
    result = api_request('DELETE', f'/api/users/{user_id}/files/{file_id}', expected_status=(200, 204))

    # handle_api_error 404 (file not in trash) হ্যান্ডেল করবে
    if not handle_api_error(result, "ফাইল স্থায়ীভাবে ডিলিট করার সময় ডাটাবেস ত্রুটি ঘটেছে।"):
         flash('ফাইল রেকর্ড ডাটাবেস থেকে স্থায়ীভাবে মুছে ফেলা হয়েছে।', 'success')
         logging.info(f"File record ID {file_id} permanently deleted by user {user_id} via API")
         # ব্যবহারকারীকে ফিজিক্যাল ফাইল সম্পর্কে সতর্ক করুন
         flash('দ্রষ্টব্য: ডিস্ক থেকে সংশ্লিষ্ট ফাইলটি সরানো হয়নি কারণ এটি এই সার্ভারে পরিচালনা করা হয় না।', 'info')
    # else: API error handled

    return redirect(url_for('trash'))


@app.route('/share/file/<int:file_id>', methods=['POST'])
@login_required
def create_share_link(file_id):
    user_id = session['user_id']

    # ১. ফাইল তথ্য পান (বর্তমান টোকেন এবং নাম জানার জন্য) - শুধুমাত্র অ্যাক্টিভ ফাইল শেয়ার করা উচিত
    # GET এর জন্য 200 আশা করা হচ্ছে
    file_info_result = api_request('GET', f'/api/users/{user_id}/files/{file_id}', expected_status=(200,))

    # handle_api_error 404 হ্যান্ডেল করবে
    if isinstance(file_info_result, dict) and file_info_result.get("_status_code") == 404:
         flash('শেয়ার করার জন্য ফাইলটি খুঁজে পাওয়া যায়নি বা অনুমতি নেই।', 'danger')
         return redirect(request.referrer or url_for('home'))
    elif handle_api_error(file_info_result, "ফাইল তথ্য পেতে ত্রুটি ঘটেছে।"):
         return redirect(request.referrer or url_for('home'))
    elif not file_info_result or 'id' not in file_info_result: # অপ্রত্যাশিত ফলাফল
         flash('ফাইল তথ্য পেতে একটি অপ্রত্যাশিত ত্রুটি ঘটেছে।', 'danger')
         return redirect(request.referrer or url_for('home'))

    file_info = file_info_result # এটি একটি dict
    # ফাইল ডিলিটেড কিনা তা পরীক্ষা করুন (API থেকে is_deleted পাওয়া উচিত)
    if file_info.get('is_deleted'):
         flash('ট্র্যাশে থাকা ফাইল শেয়ার করা যাবে না।', 'warning')
         return redirect(request.referrer or url_for('home'))


    share_token = file_info.get('share_token')
    original_filename = file_info.get('original_filename', 'ফাইল')

    if not share_token:
        # ২. নতুন টোকেন তৈরি করুন
        share_token = secrets.token_urlsafe(16)
        # ৩. API কল করে টোকেন আপডেট করুন
        payload = {"share_token": share_token}
        # PUT এর জন্য 200 আশা করা হচ্ছে
        update_result = api_request('PUT', f'/api/users/{user_id}/files/{file_id}/share_token', json=payload, expected_status=(200,))

        # handle_api_error এখানে 404 বা অন্যান্য ত্রুটি হ্যান্ডেল করবে
        if handle_api_error(update_result, "শেয়ার লিঙ্ক তৈরি করার সময় ডাটাবেস ত্রুটি ঘটেছে।"):
            # টোকেন সেট করা যায়নি, তাই লিঙ্ক তৈরি করা যাবে না
            return redirect(request.referrer or url_for('home'))
        logging.info(f"Share token created for file ID {file_id} by user {user_id} via API")
        # API সফলভাবে টোকেন সেট করেছে

    # শেয়ার URL তৈরি করুন (আগের মতোই)
    share_url = url_for('view_shared_file_page', token=share_token, _external=True)
    flash_message = Markup(f"'{original_filename}' শেয়ার করার লিঙ্ক (যে কেউ দেখতে পারবে): <br><a href=\"{share_url}\" target=\"_blank\" class=\"alert-link\" style=\"word-break: break-all;\">{share_url}</a>")
    flash(flash_message, 'info')

    return redirect(request.referrer or url_for('home'))


# শেয়ার্ড ফাইলের পৃষ্ঠা দেখার রুট
@app.route('/shared/<token>')
def view_shared_file_page(token):
    if not token: abort(404)
    logging.debug(f"Attempting to view shared file page with token: {token}")

    # API থেকে টোকেন দ্বারা ফাইল তথ্য পান
    # GET এর জন্য 200 আশা করা হচ্ছে
    file_info_result = api_request('GET', f'/api/files/by_share_token/{token}', expected_status=(200,))

    # handle_api_error 404 হ্যান্ডেল করবে (ফ্ল্যাশ ছাড়া)
    if isinstance(file_info_result, dict) and file_info_result.get("_status_code") == 404:
        logging.warning(f"Invalid or expired share token accessed: {token}")
        abort(404) # লিঙ্ক অবৈধ বা মেয়াদোত্তীর্ণ হলে 404 দেখান
    elif handle_api_error(file_info_result, "শেয়ার্ড ফাইল দেখার সময় ত্রুটি ঘটেছে।"):
        abort(500) # অন্যান্য API ত্রুটি
    elif not file_info_result or 'id' not in file_info_result: # অপ্রত্যাশিত ফলাফল
         logging.error(f"Unexpected API response for share token {token}: {file_info_result}")
         abort(404)

    file_info = file_info_result # এটি একটি dict

    # MIME টাইপের উপর ভিত্তি করে প্রিভিউ টাইপ নির্ধারণ করুন
    mime_type = file_info.get('mime_type', '')
    preview_type = None
    if mime_type.startswith('image/'): preview_type = 'image'
    elif mime_type.startswith('video/'): preview_type = 'video'
    elif mime_type.startswith('audio/'): preview_type = 'audio'
    elif mime_type == 'application/pdf': preview_type = 'pdf'
    elif mime_type.startswith('text/'): preview_type = 'text'

    logging.debug(f"Shared file page: ID {file_info.get('id')}, Mime='{mime_type}', PreviewType='{preview_type}'")

    # পরিবেশন এবং ডাউনলোড URL তৈরি করুন
    # serve_file রুটে টোকেন যোগ করা জরুরি যাতে অনুমতি চেক কাজ করে
    file_serve_url = url_for('serve_file', filename=file_info['saved_filename'], token=token)
    download_url = url_for('download_shared_file', token=token)

    # file_info এখন dict
    return render_template('view_shared_file.html', file=file_info, preview_type=preview_type, file_serve_url=file_serve_url, download_url=download_url)


# শেয়ার্ড ফাইল ডাউনলোড রুট
@app.route('/download_shared/<token>')
def download_shared_file(token):
    if not token: abort(404)

    # API থেকে টোকেন দ্বারা ফাইল তথ্য পান (filepath, original_filename, dropbox_link প্রয়োজন)
    # GET এর জন্য 200 আশা করা হচ্ছে
    file_info_result = api_request('GET', f'/api/files/by_share_token/{token}', expected_status=(200,))

    # handle_api_error 404 হ্যান্ডেল করবে (ফ্ল্যাশ ছাড়া)
    if isinstance(file_info_result, dict) and file_info_result.get("_status_code") == 404:
        logging.warning(f"Attempt to download with invalid/expired share token: {token}")
        abort(404)
    elif handle_api_error(file_info_result, "শেয়ার্ড ফাইল ডাউনলোডের জন্য তথ্য পেতে ত্রুটি ঘটেছে।"):
        abort(500)
    elif not file_info_result or 'filepath' not in file_info_result:
        logging.error(f"Unexpected API response or missing filepath for shared download token {token}: {file_info_result}")
        abort(404)


    file_info = file_info_result # এটি একটি dict
    base_directory = os.path.abspath(os.path.join(app.root_path, app.config['UPLOAD_FOLDER']))
    relative_filepath = file_info['filepath']
    expected_file_path = os.path.normpath(os.path.join(base_directory, relative_filepath))
    original_filename = file_info.get('original_filename', 'download') # ডিফল্ট নাম

    # --- Dropbox Restore Logic (এখানেও প্রয়োজন) ---
    if not os.path.isfile(expected_file_path):
        logging.warning(f"Local file not found for shared download: {expected_file_path}. Attempting Dropbox restore.")
        dropbox_link = file_info.get('dropbox_link') # API থেকে পাওয়া লিঙ্ক
        if dropbox_link:
            if not restore_from_dropbox(dropbox_link, expected_file_path):
                logging.error(f"Dropbox restore failed for shared download (token: {token}). File unavailable.")
                abort(404) # পুনরুদ্ধার ব্যর্থ
        else:
            # লোকাল নেই, লিঙ্কও নেই
            logging.error(f"Local file missing and no Dropbox link for shared download (token: {token}). File unavailable.")
            abort(404) # ফাইল অনুপলব্ধ
    # --- End Dropbox Restore Logic ---

    # ফাইল এখন বিদ্যমান থাকা উচিত
    if not os.path.isfile(expected_file_path):
         logging.error(f"File still not found at {expected_file_path} after restore check for shared download.")
         abort(404)

    try:
        logging.info(f"Shared file download initiated for token {token} ('{original_filename}')")
        # ডাউনলোড করতে বাধ্য করুন
        return send_from_directory(
            base_directory,
            relative_filepath,
            as_attachment=True,
            download_name=original_filename # আসল নাম ব্যবহার করুন
        )
    except Exception as e:
        logging.error(f"Error sending shared file for download '{relative_filepath}' (token: {token}): {e}", exc_info=True)
        abort(500)

# --- Health Check for Photo Server ---
@app.route('/health')
def health_check():
    """ফটো সার্ভারের এবং ডেটাবেস এপিআই এর স্বাস্থ্য পরীক্ষা করে।"""
    db_status = "error"
    db_details = "Not checked"
    # Database API সার্ভারের সাথে সংযোগ পরীক্ষা করুন
    try:
        api_health = api_request('GET', '/health', expected_status=(200,))
        if isinstance(api_health, dict) and "_api_error" in api_health:
            db_status = "error"
            db_details = api_health['_api_error']
            logging.warning(f"Health check: Database API connection failed: {db_details}")
        elif api_health and 'database' in api_health:
            db_status = api_health['database'] # 'connected' বা অন্য স্ট্যাটাস
            db_details = api_health.get('status', 'ok')
            logging.info(f"Health check: Database API status: {db_status}")
        else:
             db_status = "unknown_response"
             db_details = str(api_health)
             logging.warning(f"Health check: Unknown response from Database API health check: {db_details}")

    except Exception as e:
        db_status = "client_error"
        db_details = str(e)
        logging.error(f"Health check: Error checking Database API health: {e}", exc_info=True)

    return jsonify({
        "photo_server_status": "ok",
        "database_api_status": db_status,
        "database_api_details": db_details,
        "dropbox_enabled": DROPBOX_ENABLED,
        "email_configured": bool(GMAIL_USER and GMAIL_APP_PASSWORD)
     }), 200


# --- Main Execution ---
if __name__ == '__main__':
    # অ্যাপ চালু করার আগে একবার সেটআপ রান করুন (যেমন আপলোড ফোল্ডার তৈরি)
    with app.app_context():
        before_first_request_func()

    logging.info("--- Starting Photo Server ---")
    logging.info(f" Mode: {'Debug' if DEBUG_MODE else 'Production'}")
    # সাধারণত ফটো সার্ভারটি মূল অ্যাপ্লিকেশন পোর্ট ব্যবহার করবে
    logging.info(f" Listening on: http://0.0.0.0:5001 (Adjust host/port as needed)")
    logging.info(f" Upload Folder: {os.path.abspath(app.config['UPLOAD_FOLDER'])}")
    logging.info(f" Database API URL: {DATABASE_API_BASE_URL}")
    if DROPBOX_ENABLED:
        logging.info(f" Dropbox Backup: Enabled (Target Folder: {DROPBOX_BACKUP_FOLDER})")
    else:
        logging.warning(" Dropbox Backup: Disabled (Check credentials)")
    logging.warning("!!! Reminder: Credentials and Secret Key might be hardcoded. Use environment variables for production deployment! !!!")
    logging.warning("!!! SECURITY WARNING: Communication with Database API is likely unsecured. Use API keys/mTLS in production. !!!")
    logging.info("-----------------------------------")

    # ডিবাগ মোড True থাকলে অটো রিলোডার কাজ করবে
    # প্রোডাকশনে Gunicorn বা Waitress এর মতো WSGI সার্ভার ব্যবহার করা উচিত
    app.run(host="0.0.0.0", port=5001, debug=DEBUG_MODE)
