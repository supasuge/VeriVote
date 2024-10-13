# app/__init__.py

import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from .config import Config

db = SQLAlchemy()
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

# Import models and routes to register them with the app
from app import models, routes

# Set up logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)
