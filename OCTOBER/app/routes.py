from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, send_file
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash
from . import db
from .models import User, Service, ServiceProfessional, Request, Admin, Review
from datetime import datetime
from sqlalchemy.exc import IntegrityError
import os
import uuid
from werkzeug.utils import secure_filename
from .utils import allowed_file, allowed_image, admin_required

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session or not session['admin_logged_in']:
            flash('You need to be logged in as an admin to access this page.', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def init_routes(app):
    @app.before_request
    def load_user():
        user_id = session.get('user_id')
        if user_id is None:
            g.user = None
        else:
            g.user = User.query.get(user_id)
    @app.route('/')
    def index():
        if g.user:
            return render_template('index.html', user=g.user)
        return render_template('index.html')

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        print("Starting signup route")  # Debug log
        services = Service.query.all()
        if request.method == 'POST':
            print("POST request received")  # Debug log

            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            role = request.form.get('role')

            print(f"Form data received - Username: {username}, Email: {email}, Role: {role}")  # Debug log

            if not all([username, email, password, role]):
                print("Missing required fields")  # Debug log
                flash('Please fill in all fields', 'danger')
                return redirect(url_for('signup'))

            existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
            if existing_user:
                print("User already exists")  # Debug log
                flash('Username or email already exists', 'danger')
                return redirect(url_for('signup'))

            try:
                print("Creating new user")  # Debug log
                new_user = User(username=username, email=email, role=role)
                new_user.set_password(password)
                db.session.add(new_user)

                if role == 'service_professional':
                    print("Processing service professional data")  # Debug log
                    service_id = request.form.get('service')
                    if not service_id:
                        flash('Please select a service', 'danger')
                        return redirect(url_for('signup'))

                    document_path = None
                    profile_photo_path = None

                    if 'document' in request.files:
                        file = request.files['document']
                        if file and file.filename != '':
                            if allowed_file(file.filename):
                                filename = secure_filename(file.filename)
                                unique_filename = f"{uuid.uuid4()}_{filename}"
                                file_path = os.path.join('uploads', 'documents', unique_filename)
                                full_path = os.path.join(app.root_path, 'static', file_path)
                                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                                file.save(full_path)
                                document_path = unique_filename

                    if 'profile_photo' in request.files:
                        photo_file = request.files['profile_photo']
                        if photo_file and photo_file.filename != '':
                            if allowed_image(photo_file.filename):
                                photo_filename = secure_filename(photo_file.filename)
                                unique_photo_filename = f"{uuid.uuid4()}_{photo_filename}"
                                photo_path = os.path.join('uploads', 'profile_photos', unique_photo_filename)
                                full_photo_path = os.path.join(app.root_path, 'static', photo_path)
                                os.makedirs(os.path.dirname(full_photo_path), exist_ok=True)
                                photo_file.save(full_photo_path)
                                profile_photo_path = unique_photo_filename

                    new_professional = ServiceProfessional(
                        user=new_user,
                        service_id=service_id,
                        experience=0,
                        document=document_path,
                        profile_photo=profile_photo_path
                    )
                    db.session.add(new_professional)

                print("Committing to database")  # Debug log
                db.session.commit()

                print("Setting up user session")  # Debug log
                login_user(new_user)
                session['user_id'] = new_user.id

                flash('Account created successfully', 'success')

                if role == 'customer':
                    print("Redirecting to customer dashboard")  # Debug log
                    return redirect(url_for('customer_dashboard'))
                else:
                    print("Redirecting to service professional dashboard")  # Debug log
                    return redirect(url_for('serviceprofessional_dashboard'))

            except Exception as e:
                print(f"Error during signup: {str(e)}")  # Debug log
                db.session.rollback()
                flash('An error occurred. Please try again.', 'danger')
                return redirect(url_for('signup'))

        return render_template('signup.html', services=services)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                session['user_id'] = user.id  # Store user_id in session
                flash('Logged in successfully', 'success')

                if user.role == 'customer':
                    return redirect(url_for('customer_dashboard'))
                elif user.role == 'service_professional':
                    return redirect(url_for('serviceprofessional_dashboard'))
                else:
                    return redirect(url_for('index'))
            else:
                flash('Invalid username or password', 'danger')

        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out', 'success')
        return redirect(url_for('index'))

    @app.route('/admin/login', methods=['GET', 'POST'])
    def admin_login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            if username == app.config['ADMIN_USERNAME'] and password == app.config['ADMIN_PASSWORD']:
                session['admin_logged_in'] = True
                flash('Logged in successfully as admin', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid credentials', 'danger')
        return render_template('admin_login.html')

    @app.route('/admin/dashboard')
    @admin_required
    def admin_dashboard():
        return render_template('admin/dashboard.html')

    @app.route('/admin/manage_customers')
    @admin_required
    def manage_customers():
        search_query = request.args.get('search', '')

        if search_query:
            # Search in both username and email
            customers = User.query.filter_by(role='customer').filter(
                db.or_(
                    User.username.ilike(f'%{search_query}%'),
                    User.email.ilike(f'%{search_query}%')
                )
            ).all()
        else:
            customers = User.query.filter_by(role='customer').all()

        return render_template('admin/manage_customers.html', customers=customers, search_query=search_query)

    @app.route('/admin/manage_professionals')
    @admin_required
    def manage_professionals():
        search_query = request.args.get('search', '')

        if search_query:
            # Join ServiceProfessional with User and filter by username or email
            professionals = ServiceProfessional.query.join(User).filter(
                db.or_(
                    User.username.ilike(f'%{search_query}%'),
                    User.email.ilike(f'%{search_query}%')
                )
            ).all()
        else:
            professionals = ServiceProfessional.query.join(User).all()

        return render_template('admin/manage_professionals.html', professionals=professionals)

    @app.route('/admin/view_document/<int:professional_id>')
    @admin_required
    def view_document(professional_id):
        professional = ServiceProfessional.query.get_or_404(professional_id)

        if not professional.document:
            flash('No document found for this professional.', 'error')
            return redirect(url_for('manage_professionals'))

        file_path = os.path.join(app.root_path, 'static', 'uploads', 'documents', professional.document)

        if not os.path.exists(file_path):
            flash('Document file not found.', 'error')
            return redirect(url_for('manage_professionals'))

        if file_path.lower().endswith('.pdf'):
            document_url = url_for('static', filename=f'uploads/documents/{professional.document}')
            return render_template('admin/view_document.html',
                                professional=professional,
                                document_url=document_url,
                                is_pdf=True)
        else:
            # For other file types, show document info and provide download option
            document_url = url_for('static', filename=f'uploads/documents/{professional.document}')
            return render_template('admin/view_document.html',
                                professional=professional,
                                document_url=document_url,
                                is_pdf=False)

    @app.route('/admin/download_document/<int:professional_id>')
    @admin_required
    def download_document(professional_id):
        professional = ServiceProfessional.query.get_or_404(professional_id)

        if not professional.document:
            flash('No document found for this professional.', 'error')
            return redirect(url_for('manage_professionals'))

        try:
            file_path = os.path.join(app.root_path, 'static', 'uploads', 'documents', professional.document)
            return send_file(
                file_path,
                as_attachment=True,
                download_name=os.path.basename(professional.document)
            )
        except Exception as e:
            flash('Error downloading document.', 'error')
            return redirect(url_for('manage_professionals'))

    @app.route('/admin/approve_professional/<int:id>')
    @admin_required
    def approve_professional(id):
        professional = ServiceProfessional.query.get_or_404(id)

        if not professional.document:
            flash('Cannot approve professional without uploaded document.', 'error')
            return redirect(url_for('manage_professionals'))

        professional.verified = True
        db.session.commit()
        flash('Service Professional approved successfully.', 'success')
        return redirect(url_for('manage_professionals'))

    @app.route('/admin/block_user/<int:id>')
    @admin_required
    def block_user(id):
        user = User.query.get_or_404(id)
        user.is_active = not user.is_active  # Toggle the is_active status
        db.session.commit()
        action = "blocked" if not user.is_active else "unblocked"
        flash(f'User {action} successfully.', 'success')
        if user.role == 'customer':
            return redirect(url_for('manage_customers'))
        else:
            return redirect(url_for('manage_professionals'))

    @app.route('/admin/services')
    @admin_required
    def manage_services():
        services = Service.query.all()
        return render_template('admin/manage_services.html', services=services)

    @app.route('/admin/services/new', methods=['GET', 'POST'])
    @admin_required
    def new_service():
        if request.method == 'POST':
            service_name = request.form['service_name']
            base_price = float(request.form['base_price'])
            time_required = int(request.form['time_required'])
            description = request.form['description']
            pin_code = request.form.get('pin_code')

            if not pin_code:
                flash('Pin code is required', 'error')
                return render_template('admin/new_service.html')

            new_service = Service(service_name=service_name, base_price=base_price, time_required=time_required, description=description, pin_code=pin_code)

            db.session.add(new_service)
            try:
                db.session.commit()
                flash('New service created successfully', 'success')
                return redirect(url_for('manage_services'))
            except IntegrityError:
                db.session.rollback()
                flash('An error occurred while creating the service. Please try again.', 'error')
                return render_template('admin/new_service.html')

        return render_template('admin/new_service.html')

    @app.route('/admin/services/edit/<int:id>', methods=['GET', 'POST'])
    @admin_required
    def edit_service(id):
        service = Service.query.get_or_404(id)
        if request.method == 'POST':
            service.service_name = request.form['service_name']
            service.base_price = float(request.form['base_price'])
            service.time_required = int(request.form['time_required'])
            service.description = request.form['description']

            db.session.commit()
            flash('Service updated successfully', 'success')
            return redirect(url_for('manage_services'))

        return render_template('admin/edit_service.html', service=service)

    @app.route('/admin/services/delete/<int:id>', methods=['POST'])
    @admin_required
    def delete_service(id):
        service = Service.query.get_or_404(id)
        db.session.delete(service)
        db.session.commit()
        flash('Service deleted successfully', 'success')
        return redirect(url_for('manage_services'))

    @app.route('/admin/logout')
    def admin_logout():
        session.pop('admin_logged_in', None)
        flash('Logged out successfully', 'success')
        return redirect(url_for('index'))

    @app.route('/customer_dashboard')
    @login_required
    def customer_dashboard():
        if not current_user.is_authenticated:
            print("User not authenticated")
            flash('Please log in first', 'danger')
            return redirect(url_for('login'))

        if current_user.role != 'customer':
            print(f"Invalid role: {current_user.role}")
            flash('Access denied', 'danger')
            return redirect(url_for('index'))

        completed_requests = Request.query.filter_by(
            user_id=current_user.id,
            status='completed'
        ).options(
            db.joinedload(Request.review)  # Eager load the reviews
        ).all()

        unrated_requests = [req for req in completed_requests if req.needs_review]
        rated_requests = [req for req in completed_requests if req.has_submitted_review]

        return render_template('customer_dashboard.html', user=current_user, unrated_requests=unrated_requests, rated_requests=rated_requests)

    @app.route('/services', methods=['GET'])
    def list_services():
        if g.user.role != 'customer':
            flash('Access denied', 'danger')
            return redirect(url_for('index'))

        search_query = request.args.get('search', '')
        search_pin = request.args.get('pin_code', '')

        services = Service.query

        if search_query:
            services = services.filter(Service.service_name.ilike(f'%{search_query}%'))

        if search_pin:
            services = services.filter(Service.pin_code == search_pin)

        services = services.all()
        no_services_found = len(services) == 0
        return render_template('services.html', services=services, search_query=search_query, search_pin=search_pin, no_services_found=no_services_found)

    @app.route('/open_service_request/<int:service_id>', methods=['POST'])
    @login_required
    def open_service_request(service_id):
        if current_user.role != 'customer':
            flash('Access denied', 'danger')
            return redirect(url_for('index'))

        service = Service.query.get_or_404(service_id)
        new_request = Request(user_id=current_user.id, service_id=service_id, status='pending')
        db.session.add(new_request)
        db.session.commit()
        flash('Service request opened successfully', 'success')
        return redirect(url_for('customer_current_bookings'))

    @app.route('/close_service_request/<int:request_id>', methods=['POST'])
    @login_required
    def close_service_request(request_id):
        if current_user.role != 'customer':
            flash('Access denied', 'danger')
            return redirect(url_for('index'))

        service_request = Request.query.get_or_404(request_id)
        if service_request.user_id != current_user.id:
            flash('Access denied', 'danger')
            return redirect(url_for('customer_current_bookings'))

        service_request.status = 'closed'
        db.session.commit()
        flash('Service request closed successfully', 'success')
        return redirect(url_for('customer_current_bookings'))

    @app.route('/book_service/<int:service_id>', methods=['GET', 'POST'])
    @login_required
    def book_service(service_id):
        if current_user.role != 'customer':
            flash('Access denied. You must be a customer to book a service.', 'danger')
            return redirect(url_for('index'))

        service = Service.query.get_or_404(service_id)

        if request.method == 'POST':
            request_type = request.form.get('request_type', 'specific')
            request_datetime_str = request.form['request_datetime']
            location = request.form['location']
            remarks = request.form['remarks']
            pin_code = request.form['pin_code']

            request_datetime = datetime.strptime(request_datetime_str, '%Y-%m-%dT%H:%M')

            if request_type == 'all':
                # Send request to all verified professionals in this service category
                verified_professionals = ServiceProfessional.query.filter_by(
                    service_id=service_id,
                    verified=True
                ).all()

                if not verified_professionals:
                    flash('No verified professionals found for this service.', 'warning')
                    return redirect(url_for('book_service', service_id=service_id))

                # Generate a unique group ID for this set of requests
                request_group_id = str(uuid.uuid4())

                for professional in verified_professionals:
                    new_request = Request(
                        user_id=current_user.id,
                        service_id=service_id,
                        professional_id=professional.id,
                        request_datetime=request_datetime,
                        location=location,
                        remarks=remarks,
                        pin_code=pin_code,
                        status='pending',
                        request_group_id=request_group_id
                    )
                    db.session.add(new_request)

                flash(f'Service request sent to {len(verified_professionals)} professionals!', 'success')
            else:
                # Send request to specific professional
                professional_id = request.form['professional_id']

                # Verify that the professional exists and is verified
                professional = ServiceProfessional.query.get_or_404(professional_id)
                if not professional.verified:
                    flash('Selected professional is not verified.', 'danger')
                    return redirect(url_for('book_service', service_id=service_id))

                new_request = Request(
                    user_id=current_user.id,
                    service_id=service_id,
                    professional_id=professional_id,
                    request_datetime=request_datetime,
                    location=location,
                    remarks=remarks,
                    pin_code=pin_code,
                    status='pending'
                )
                db.session.add(new_request)
                flash('Service request sent successfully!', 'success')

            db.session.commit()
            return redirect(url_for('customer_dashboard'))

        # Get all verified professionals for this service
        professionals = ServiceProfessional.query.filter_by(service_id=service_id).all()
        return render_template('book_service.html', service=service, professionals=professionals)

    @app.route('/customer/profile')
    def customer_profile():
        if not g.user:
            flash('Please log in first', 'danger')
            return redirect(url_for('login'))
        if g.user.role != 'customer':
            flash('Access denied', 'danger')
            return redirect(url_for('login'))
        return render_template('customer_profile.html', user=g.user)

    @app.route('/customer/edit_profile', methods=['GET', 'POST'])
    def edit_profile():
        if g.user.role != 'customer':
            flash('Access denied', 'danger')
            return redirect(url_for('index'))

        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']

            if username and email:
                g.user.username = username
                g.user.email = email
                if password:
                    g.user.password = generate_password_hash(password)

                db.session.commit()
                flash('Your profile has been updated!', 'success')
                return redirect(url_for('customer_profile'))
            else:
                flash('Username and email are required.', 'danger')

        return render_template('edit_profile.html', user=g.user)

    @app.route('/serviceprofessional_dashboard')
    @login_required
    def serviceprofessional_dashboard():
        if current_user.role != 'service_professional':
            flash('Access denied. You must be a service professional to view this page.', 'danger')
            return redirect(url_for('index'))

        professional = ServiceProfessional.query.filter_by(user_id=current_user.id).first()
        if not professional:
            flash('Service Professional profile not found. Please contact admin.', 'danger')
            return redirect(url_for('index'))

        # Only show pending requests that haven't been cancelled
        pending_requests = Request.query.filter_by(professional_id=professional.id, status='pending').all()

        accepted_requests = Request.query.filter_by(professional_id=professional.id, status='accepted').all()

        completed_services = Request.query.filter_by(
            professional_id=professional.id,
            status='completed'
        ).options(
            db.joinedload(Request.review)  # Eager load the reviews
        ).order_by(
            Request.completed_at.desc()
        ).all()

        rated_services = [service for service in completed_services
                        if service.review and service.review.is_submitted]
        if rated_services:
            total_rating = sum(service.review.rating for service in rated_services)
            professional.average_rating = total_rating / len(rated_services)
            db.session.commit()

        return render_template('serviceprofessional_dashboard.html', user=current_user, professional=professional, pending_requests=pending_requests, accepted_requests=accepted_requests, completed_services=completed_services)

    @app.route('/accept_request/<int:request_id>', methods=['POST'])
    def accept_request(request_id):
        if g.user.role != 'service_professional':
            flash('Access denied', 'danger')
            return redirect(url_for('index'))

        service_request = Request.query.get_or_404(request_id)

        # Check if this is part of a group request
        if service_request.request_group_id:
            # Check if any request in this group has already been accepted
            already_accepted = Request.query.filter_by(
                request_group_id=service_request.request_group_id,
                status='accepted'
            ).first()

            if already_accepted:
                flash('This request has already been accepted by another professional.', 'warning')

                # Mark all other pending requests in this group as 'cancelled'
                pending_group_requests = Request.query.filter_by(
                    request_group_id=service_request.request_group_id,
                    status='pending'
                ).all()

                for req in pending_group_requests:
                    req.status = 'cancelled'

                db.session.commit()
                return redirect(url_for('serviceprofessional_dashboard'))

            # If no one has accepted yet, accept this request and cancel all others
            service_request.status = 'accepted'

            # Cancel all other pending requests in this group
            other_pending_requests = Request.query.filter(
                Request.request_group_id == service_request.request_group_id,
                Request.id != service_request.id,
                Request.status == 'pending'
            ).all()

            for req in other_pending_requests:
                req.status = 'cancelled'

            db.session.commit()
            flash('Request accepted successfully! All other pending requests for this service have been cancelled.', 'success')
        else:
            # This is a direct request to this professional
            service_request.status = 'accepted'
            db.session.commit()
            flash('Request accepted successfully', 'success')

        return redirect(url_for('serviceprofessional_dashboard'))

    @app.route('/edit_professional_experience', methods=['GET', 'POST'])
    @login_required
    def edit_professional_experience():
        professional = ServiceProfessional.query.filter_by(user_id=current_user.id).first()

        if not professional:
            flash('You are not registered as a service professional.', 'error')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            experience = request.form.get('experience')

            if experience and experience.isdigit():
                professional.experience = int(experience)

                # Handle profile photo upload
                if 'profile_photo' in request.files:
                    photo_file = request.files['profile_photo']
                    if photo_file and photo_file.filename != '':
                        if allowed_image(photo_file.filename):
                            # Delete old profile photo if it exists
                            if professional.profile_photo:
                                old_photo_path = os.path.join(app.root_path, 'static', 'uploads', 'profile_photos', professional.profile_photo)
                                if os.path.exists(old_photo_path):
                                    try:
                                        os.remove(old_photo_path)
                                    except Exception as e:
                                        print(f"Error removing old profile photo: {str(e)}")

                            # Save new profile photo
                            photo_filename = secure_filename(photo_file.filename)
                            unique_photo_filename = f"{uuid.uuid4()}_{photo_filename}"
                            photo_path = os.path.join('uploads', 'profile_photos', unique_photo_filename)
                            full_photo_path = os.path.join(app.root_path, 'static', photo_path)
                            os.makedirs(os.path.dirname(full_photo_path), exist_ok=True)
                            photo_file.save(full_photo_path)
                            professional.profile_photo = unique_photo_filename
                        else:
                            flash('Invalid file format. Please upload a JPG, JPEG, or PNG file.', 'error')

                db.session.commit()
                flash('Your profile has been updated successfully.', 'success')
                return redirect(url_for('serviceprofessional_dashboard'))
            else:
                flash('Please provide a valid number for your experience.', 'error')

        return render_template('edit_professional_experience.html', professional=professional)

    @app.route('/reject_request/<int:request_id>', methods=['POST'])
    def reject_request(request_id):
        if g.user.role != 'service_professional':
            flash('Access denied', 'danger')
            return redirect(url_for('index'))

        service_request = Request.query.get_or_404(request_id)
        service_request.status = 'rejected'
        db.session.commit()
        flash('Request rejected successfully', 'success')
        return redirect(url_for('serviceprofessional_dashboard'))

    @app.route('/complete_service/<int:request_id>')
    def complete_service(request_id):
        if g.user.role != 'service_professional':
            flash('Access denied', 'danger')
            return redirect(url_for('index'))

        request = Request.query.get_or_404(request_id)
        request.status = 'completed'
        request.completed_at = datetime.utcnow()
        db.session.commit()
        flash('Service marked as completed', 'success')
        return redirect(url_for('serviceprofessional_dashboard'))

    @app.route('/rate_service/<int:request_id>', methods=['GET', 'POST'])
    @login_required
    def rate_service(request_id):
        request_obj = Request.query.get_or_404(request_id)

        if request_obj.user_id != g.user.id:
            flash('Access denied', 'danger')
            return redirect(url_for('customer_dashboard'))

        if request_obj.status != 'completed':
            flash('You can only rate completed services', 'warning')
            return redirect(url_for('customer_dashboard'))

        if request_obj.review and request_obj.review.is_submitted:
            flash('You have already rated this service', 'warning')
            return redirect(url_for('customer_dashboard'))

        if request.method == 'POST':
            rating = int(request.form['rating'])
            comment = request.form['comment']

            if request_obj.review:
                request_obj.review.rating = rating
                request_obj.review.comment = comment
                request_obj.review.is_submitted = True
            else:
                new_review = Review(request_id=request_obj.id, rating=rating, comment=comment, is_submitted=True)
                db.session.add(new_review)

            db.session.commit()
            flash('Thank you for your review!', 'success')
            return redirect(url_for('customer_dashboard'))

        return render_template('rate_service.html', request=request_obj)

    @app.route('/customer/current_bookings')
    @login_required
    def customer_current_bookings():
        if current_user.role != 'customer':
            flash('Access denied. You must be a customer to view this page.', 'danger')
            return redirect(url_for('index'))

        # First, get all requests for this user
        all_requests = Request.query.filter_by(user_id=current_user.id).filter(
            Request.status.in_(['pending', 'accepted', 'cancelled'])
        ).all()

        # Find all request_group_ids that have an accepted request
        accepted_group_ids = set()
        for req in all_requests:
            if req.status == 'accepted' and req.request_group_id:
                accepted_group_ids.add(req.request_group_id)

        # Filter out cancelled requests that belong to a group with an accepted request
        filtered_requests = []
        for req in all_requests:
            # Include the request if:
            # 1. It's not cancelled, OR
            # 2. It's cancelled but doesn't belong to a group with an accepted request
            if req.status != 'cancelled' or (req.request_group_id not in accepted_group_ids):
                filtered_requests.append(req)

        # Sort the requests
        filtered_requests.sort(key=lambda x: (
            1 if x.status == 'accepted' else (2 if x.status == 'pending' else 3),
            x.request_datetime
        ), reverse=True)

        return render_template('customer_current_bookings.html', active_requests=filtered_requests)

    return app