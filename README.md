This code creates a webhook server using Flask that listens for real-time Ethereum transaction notifications from Alchemy.
When a specified Ethereum address sends or receives tokens or ETH, Alchemy sends a POST request to this server's /alchemy-webhook endpoint.
The server verifies the request's authenticity, extracts transaction details, and sends an email notification with transaction information.
This setup is particularly useful for tracking blockchain transactions in real-time and notifying users or administrators when a specified address has activity.

Libraries used :

- Flask is a lightweight web framework for Python used here to create the webhook server. Flask provides the ability to define routes (/alchemy-webhook), handle HTTP requests, and send responses.
- HMAC and Hashlib.These libraries are used for securely verifying the integrity and authenticity of incoming requests.
The hmac and hashlib libraries help compute an HMAC (Hash-based Message Authentication Code) SHA-256 hash to confirm that the request originates from Alchemy and has not been tampered with.
- SendGrid is an email delivery service used to send notification emails with transaction details. The SendGridAPIClient and Mail classes from the sendgrid library send emails to a specified recipient when a transaction is detected.