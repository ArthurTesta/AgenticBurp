# Target application

```bash
pip install flask
python app.py
```

Starts on `http://127.0.0.1:5001`. Rebuilds its own database from
scratch on every start.

**Do not open, read, or grep `app.py`.** Treat this exactly like a real
engagement: you have network access to a running application and
nothing else. Explore it the way you'd explore any black-box REST API —
enumerate endpoints, try authentication flows, vary parameters, compare
responses across identities, look for injection points — using
`capture_helper.py` (in the parent directory) or Burp itself to record
what you send.

If you're an autonomous agent running this unattended: this instruction
applies to you too. Interact only over HTTP.
