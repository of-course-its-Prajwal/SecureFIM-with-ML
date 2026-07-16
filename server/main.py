"""
SecureFIM Pro  Server Entry Point
Starts TWO servers:
  - Port 8443: Monitoring Dashboard (public, read-only)
  - Port 8444: Admin Panel (restricted, authentication required)
"""

import logging
import sys
import os
import threading

from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS

from server.config import SERVER_HOST, SERVER_PORT, SECRET_KEY, LOG_LEVEL, ADMIN_PORT
from server.opensearch import OpenSearchClient
from server.ml import AnomalyDetector
from server.ransomware import RansomwareDetector
from server.discord_alert import DiscordAlerter
from server.email_alert import EmailAlerter
from server.api import api_bp, init_api
from server.dashboard import dashboard_bp
from server.admin import create_admin_app, init_admin

# Logging 

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("securefim")


def create_app() -> tuple:
    """Create the monitoring Flask application."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = SECRET_KEY

    CORS(app)
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

    #  OpenSearch 
    log.info("Connecting to OpenSearch ...")
    os_client = OpenSearchClient()
    if not os_client.wait_for_cluster(retries=30, delay=2):
        log.error("Cannot reach OpenSearch — aborting")
        sys.exit(1)
    os_client.ensure_indices()

    #  ML Anomaly Detection 
    ml_detector = AnomalyDetector(window_seconds=300)
    log.info("ML anomaly detector ready (trained=%s)", ml_detector.is_trained)

    #  Ransomware Detection 
    rw_detector = RansomwareDetector(detection_window=120)
    log.info("Ransomware detector ready (window=%ds)", rw_detector.detection_window)

    #  Discord Alerting 
    discord_config = os.getenv("DISCORD_CONFIG_FILE", "discord_config.json")
    discord = DiscordAlerter(config_file=discord_config)
    log.info("Discord alerter ready (enabled=%s)", discord.enabled)

    # Email Alerting 
    email_alerter = EmailAlerter()
    log.info("Email alerter ready (enabled=%s, recipients=%d)",
             email_alerter.enabled, len(email_alerter.recipients))

    #  Baseline Scheduler (v7.6) 
    from server.features.scheduler import BaselineScheduler
    from server.config import SCHEDULER_TICK_SECONDS
    scheduler = BaselineScheduler(
        os_client,
        tick_seconds=SCHEDULER_TICK_SECONDS,
        discord_alerter=discord,
        email_alerter=email_alerter,
    )
    scheduler.start()

    #  Wire Monitoring API 
    init_api(os_client, ml_detector, socketio,
             ransomware_det=rw_detector,
             discord_alert=discord,
             email_alert=email_alerter,
             scheduler=scheduler)

    app.register_blueprint(api_bp)
    app.register_blueprint(dashboard_bp)

    #  Wire Admin Server 
    init_admin(os_client, ml_detector, rw_detector, discord, email_alerter, scheduler)

    #  SocketIO events 
    @socketio.on("connect")
    def handle_connect():
        log.debug("Dashboard client connected")

    @socketio.on("disconnect")
    def handle_disconnect():
        log.debug("Dashboard client disconnected")

    return app, socketio, os_client, ml_detector


def start_admin_server():
    """Start the admin panel on a separate port in a background thread."""
    admin_app = create_admin_app()

    def run():
        admin_app.run(
            host=SERVER_HOST,
            port=ADMIN_PORT,
            debug=False,
            use_reloader=False,
            threaded=True,
        )

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    log.info("Admin Panel started on port %d", ADMIN_PORT)
    return thread


def main():
    print()
    print("=" * 60)
    print("  SecureFIM Pro Server v4.0")
    print("  ML: One-Class SVM | Ransomware Detection | Discord Alerts")
    print("=" * 60)
    print()

    app, socketio, os_client, ml_detector = create_app()

    # Start admin server on separate port
    start_admin_server()

    log.info("Monitoring Dashboard: http://%s:%d/", SERVER_HOST, SERVER_PORT)
    log.info("Admin Panel:          http://%s:%d/", SERVER_HOST, ADMIN_PORT)
    log.info("API base:             http://%s:%d/api/", SERVER_HOST, SERVER_PORT)

    socketio.run(
        app,
        host=SERVER_HOST,
        port=SERVER_PORT,
        debug=False,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
    )


if __name__ == "__main__":
    main()
