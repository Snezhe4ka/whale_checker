from flask import Flask, request, jsonify, abort
import hmac
import hashlib
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import logging
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)


EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
SIGNING_KEY = os.environ.get("SIGNING_KEY")

# check for missing environment variables
if not all([EMAIL_USER, EMAIL_RECEIVER, SENDGRID_API_KEY, SIGNING_KEY]):
    raise EnvironmentError("One or more required environment variables are missing.")

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')


def send_email(subject, content):
    """Send an email using SendGrid."""
    message = Mail(
        from_email=EMAIL_USER,
        to_emails=EMAIL_RECEIVER,
        subject=subject,
        html_content=content
    )

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        logging.info("Email sent successfully. Status code: %s", response.status_code)
    except Exception as e:
        logging.error("Error sending email: %s", e)


def is_valid_signature_for_string_body(body: str, signature: str) -> bool:
    """verify the signature matches the HMAC SHA-256 hash of the body."""
    digest = hmac.new(
        bytes(SIGNING_KEY, "utf-8"),
        msg=bytes(body, "utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()
    return signature == digest


@app.route('/alchemy-webhook', methods=['POST'])
def alchemy_webhook():
    signature = request.headers.get('X-Alchemy-Signature')
    if not signature:
        abort(403)  # forbidden if signature is missing

    # verify the signature
    str_body = request.get_data(as_text=True)
    if not is_valid_signature_for_string_body(str_body, signature):
        abort(403)

    # parse json data
    data = request.json
    if data is None or data.get('type') != 'ADDRESS_ACTIVITY':
        return jsonify({"error": "Invalid JSON data"}), 400

    # process each activity item in the response
    activities = data['event']['activity']
    for activity in activities:
        from_address = activity.get("fromAddress")
        to_address = activity.get("toAddress")
        value = activity.get("value")
        asset = activity.get("asset")
        transaction_hash = activity.get("hash")
        block_num = activity.get("blockNum")

        logging.info("Processing activity: %s", activities)

        # email content
        subject = f"New Transaction Detected: {asset}"
        content = f"""
        <h1>Transaction Alert</h1>
        <p><b>From:</b> {from_address}</p>
        <p><b>To:</b> {to_address}</p>
        <p><b>Asset:</b> {asset}</p>
        <p><b>Value:</b> {value}</p>
        <p><b>Transaction Hash:</b> <a href="https://etherscan.io/tx/{transaction_hash}">{transaction_hash}</a></p>
        <p><b>Block Number:</b> {block_num}</p>
        """

        # send the email
        send_email(subject, content)

    return jsonify({"status": "success"}), 200

if __name__ == '__main__':
    debug_mode = os.environ.get("FLASK_DEBUG", "False") == "True"
    app.run(port=5000, debug=debug_mode)

