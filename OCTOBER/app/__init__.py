from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__, template_folder='templates')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'you-will-never-guess'

    UPLOAD_FOLDER = 'static/uploads/documents'
    PROFILE_PHOTOS_FOLDER = 'static/uploads/profile_photos'
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['PROFILE_PHOTOS_FOLDER'] = PROFILE_PHOTOS_FOLDER
    app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
    app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

    os.makedirs(os.path.join(app.root_path, UPLOAD_FOLDER), exist_ok=True)
    os.makedirs(os.path.join(app.root_path, PROFILE_PHOTOS_FOLDER), exist_ok=True)

    app.config['ADMIN_USERNAME'] = os.environ.get('ADMIN_USERNAME') or 'admin'
    app.config['ADMIN_PASSWORD'] = os.environ.get('ADMIN_PASSWORD') or '734yhdn'

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    with app.app_context():
        from . import routes
        from .models import User  # Import User model here
        db.create_all()
        app = routes.init_routes(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app