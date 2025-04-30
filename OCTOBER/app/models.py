from flask_sqlalchemy import SQLAlchemy
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.ext.hybrid import hybrid_property
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False)
    professional_profile = db.relationship('ServiceProfessional', backref='user', uselist=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Service(db.Model):
    __tablename__ = 'services'
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(50), nullable=False)
    base_price = db.Column(db.Float, nullable=False)
    time_required = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False)
    pin_code = db.Column(db.String(10), nullable=False)

class ServiceProfessional(db.Model):
    __tablename__ = 'service_professionals'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False)
    experience = db.Column(db.Integer, nullable=False)
    verified = db.Column(db.Boolean, default=False)
    average_rating = db.Column(db.Float, default=0.0)
    document = db.Column(db.String(255))
    profile_photo = db.Column(db.String(255), nullable=True)
    service = db.relationship('Service', backref='professionals')

class Request(db.Model):
    __tablename__ = 'requests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('service_professionals.id'), nullable=False)
    request_datetime = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected, completed
    location = db.Column(db.Text, nullable=False)
    remarks = db.Column(db.Text, nullable=True)
    pin_code = db.Column(db.Integer, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    request_group_id = db.Column(db.String(50), nullable=True)  # To group related requests sent to multiple professionals

    user = db.relationship('User', backref='requests')
    service = db.relationship('Service', backref='requests')
    professional = db.relationship('ServiceProfessional', backref='requests')

    review = db.relationship('Review',
                           backref=db.backref('parent_request', uselist=False),
                           uselist=False,
                           cascade="all, delete-orphan")

    @property
    def needs_review(self):
        return (self.status == 'completed' and (not self.review or not self.review.is_submitted))

    @property
    def has_submitted_review(self):
        return bool(self.review and self.review.is_submitted)

class Review(db.Model):
    __tablename__ = 'reviews'
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('requests.id'), nullable=False, unique=True)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_submitted = db.Column(db.Boolean, default=False)  # New column to track submission status

    request = db.relationship('Request')

class Admin(db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(130))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)