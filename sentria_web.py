from flask import Flask, render_template, redirect, url_for
from sentria_backend import get_analyzed_alerts

app = Flask(__name__)

alerts = []

@app.route("/")
def dashboard():
    return render_template("dashboard.html", alerts=alerts)

@app.route("/update_alerts")
def update_alerts():
    global alerts
    alerts = get_analyzed_alerts()
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

