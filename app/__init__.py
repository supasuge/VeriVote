# app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import logging
from .config import Config

db = SQLAlchemy()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    with app.app_context():
        from . import models
        from .routes import main
        app.register_blueprint(main)
        db.create_all()

    # Logging setup
    logging.basicConfig(level=logging.INFO)
    app.logger.setLevel(logging.INFO)

    return app



    from flask_migrate import Migrate


