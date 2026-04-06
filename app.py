import os
import secrets
import zipfile
import shutil
import hashlib
import logging
import mimetypes
import sys
import time
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify, after_this_request
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, String, Boolean, DateTime, Text, BigInteger, ForeignKey
import user_agents
from PIL import Image
import boto3

load_dotenv()

# Print startup info for debugging
print(f"Python version: {sys.version}", file=sys.stderr)
print(f"Starting application initialization...", file=sys.stderr)

app = Flask(__name__)

# ==================== CONFIGURATION ====================
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Environment detection
IS_RENDER = bool(os.environ.get('RENDER'))
IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production'

# Session security for production
if IS_PRODUCTION:
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # Extended to 30 days

# File upload limits
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB

# Cloud Storage Configuration (AWS S3 or Cloudflare R2)
USE_CLOUD_STORAGE = os.environ.get('USE_CLOUD_STORAGE', 'false').lower() == 'true'
CLOUD_STORAGE_BUCKET = os.environ.get('CLOUD_STORAGE_BUCKET')
CLOUD_STORAGE_REGION = os.environ.get('CLOUD_STORAGE_REGION', 'us-east-1')
CLOUD_STORAGE_ENDPOINT = os.environ.get('CLOUD_STORAGE_ENDPOINT')

if USE_CLOUD_STORAGE:
    # Initialize S3 client (works with AWS S3, Cloudflare R2, etc.)
    s3_client = boto3.client(
        's3',
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
        region_name=CLOUD_STORAGE_REGION,
        endpoint_url=CLOUD_STORAGE_ENDPOINT or None
    )
    app.config['UPLOAD_FOLDER'] = None
    app.config['THUMBNAIL_FOLDER'] = None
else:
    # Local storage
    if IS_RENDER:
        app.config['UPLOAD_FOLDER'] = '/tmp/storage/files'
        app.config['THUMBNAIL_FOLDER'] = '/tmp/storage/thumbnails'
        print("WARNING: Using ephemeral storage on Render. Files will be lost on restart!", file=sys.stderr)
    else:
        app.config['UPLOAD_FOLDER'] = 'storage/files'
        app.config['THUMBNAIL_FOLDER'] = 'storage/thumbnails'
    
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['THUMBNAIL_FOLDER'], exist_ok=True)

# Database Configuration
database_url = os.environ.get('DATABASE_URL')
if not database_url:
    database_url = 'sqlite:///database/vault.db'
    os.makedirs('database', exist_ok=True)
    print("Using SQLite database", file=sys.stderr)

if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Connection pooling for PostgreSQL
if database_url and 'postgresql' in database_url:
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 3,
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_timeout': 10,
        'max_overflow': 5
    }
else:
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 10,
        'pool_pre_ping': True,
        'pool_recycle': 3600,
    }

db = SQLAlchemy(app)

# ==================== LOGGING ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)

# ==================== DATABASE MODELS ====================
class User(db.Model):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pin: Mapped[str] = mapped_column(String(20), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_login: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    device_logs = db.relationship('DeviceLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    downloads = db.relationship('Download', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    permissions = db.relationship('UserItemPermission', backref='user', lazy='dynamic', cascade='all, delete-orphan')

class Item(db.Model):
    __tablename__ = 'items'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    file_path: Mapped[str] = mapped_column(Text, nullable=True)
    thumbnail_path: Mapped[str] = mapped_column(Text, nullable=True)
    parent_id: Mapped[int] = mapped_column(Integer, ForeignKey('items.id', ondelete='CASCADE'), nullable=True, index=True)
    size: Mapped[int] = mapped_column(BigInteger, nullable=True)
    mime_type: Mapped[str] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    children = db.relationship('Item', backref=db.backref('parent', remote_side=[id]), lazy='dynamic')
    permissions = db.relationship('UserItemPermission', backref='item', lazy='dynamic', cascade='all, delete-orphan')
    downloads = db.relationship('Download', backref='item', lazy='dynamic', cascade='all, delete-orphan')

class UserItemPermission(db.Model):
    __tablename__ = 'user_item_permissions'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    item_id: Mapped[int] = mapped_column(Integer, ForeignKey('items.id', ondelete='CASCADE'), nullable=False, index=True)
    can_access: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('user_id', 'item_id', name='unique_user_item'),)

class DeviceLog(db.Model):
    __tablename__ = 'device_logs'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(50))
    user_agent: Mapped[str] = mapped_column(Text)
    device_type: Mapped[str] = mapped_column(String(100))
    browser: Mapped[str] = mapped_column(String(100))
    os: Mapped[str] = mapped_column(String(100))
    accessed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

class Download(db.Model):
    __tablename__ = 'downloads'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    item_id: Mapped[int] = mapped_column(Integer, ForeignKey('items.id', ondelete='CASCADE'), nullable=False, index=True)
    downloaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

# ==================== DATABASE INITIALIZATION ====================
def init_database():
    """Initialize database with retry logic"""
    max_retries = 3
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            with app.app_context():
                # Test connection first
                db.engine.connect()
                db.create_all()
                print("Database initialized successfully", file=sys.stderr)
                return True
        except Exception as e:
            print(f"Database init attempt {attempt + 1} failed: {e}", file=sys.stderr)
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
            else:
                print("Database initialization failed, but continuing...", file=sys.stderr)
                return False
    return False

# ==================== HELPER FUNCTIONS ====================
def parse_user_agent(ua_string):
    ua = user_agents.parse(ua_string)
    return {
        'device_type': ua.device.family,
        'browser': ua.browser.family,
        'os': ua.os.family
    }

def log_device_access(user_id, request):
    try:
        ua_info = parse_user_agent(request.user_agent.string)
        device_log = DeviceLog(
            user_id=user_id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            device_type=ua_info['device_type'],
            browser=ua_info['browser'],
            os=ua_info['os']
        )
        db.session.add(device_log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log device access: {e}")

def get_user_by_pin(pin):
    return User.query.filter_by(pin=pin).first()

def get_user_permissions(user_id):
    permissions = UserItemPermission.query.filter_by(user_id=user_id, can_access=False).all()
    return [p.item_id for p in permissions]

def get_file_icon(mime_type):
    if not mime_type:
        return 'fa-file'
    if mime_type.startswith('image/'):
        return 'fa-image'
    elif mime_type.startswith('video/'):
        return 'fa-video'
    elif mime_type.startswith('audio/'):
        return 'fa-music'
    elif mime_type == 'application/pdf':
        return 'fa-file-pdf'
    elif 'zip' in mime_type or 'rar' in mime_type:
        return 'fa-file-archive'
    elif 'word' in mime_type or 'document' in mime_type:
        return 'fa-file-word'
    elif 'excel' in mime_type or 'sheet' in mime_type:
        return 'fa-file-excel'
    elif 'powerpoint' in mime_type or 'presentation' in mime_type:
        return 'fa-file-powerpoint'
    else:
        return 'fa-file'

def create_thumbnail(file_path, thumbnail_path, size=(300, 300)):
    """Create thumbnail from local file or S3"""
    try:
        if USE_CLOUD_STORAGE:
            # Download from cloud storage to memory
            response = s3_client.get_object(Bucket=CLOUD_STORAGE_BUCKET, Key=file_path)
            img_data = response['Body'].read()
            img = Image.open(BytesIO(img_data))
        else:
            img = Image.open(file_path)
        
        # Handle transparency
        if img.mode in ('RGBA', 'P'):
            img = img.convert('RGB')
        
        # Create thumbnail
        img.thumbnail(size, Image.Resampling.LANCZOS)
        
        # Save thumbnail
        thumb_buffer = BytesIO()
        img.save(thumb_buffer, 'JPEG', quality=85, optimize=True)
        thumb_buffer.seek(0)
        
        if USE_CLOUD_STORAGE:
            # Upload thumbnail to cloud storage
            s3_client.upload_fileobj(
                thumb_buffer,
                CLOUD_STORAGE_BUCKET,
                thumbnail_path,
                ExtraArgs={'ContentType': 'image/jpeg'}
            )
        else:
            with open(thumbnail_path, 'wb') as f:
                f.write(thumb_buffer.getvalue())
        
        return True
    except Exception as e:
        logger.error(f"Thumbnail creation error: {e}")
        return False

def save_file_to_storage(file_data, filename, folder='files'):
    """Save file to either local storage or cloud storage"""
    if USE_CLOUD_STORAGE:
        key = f"{folder}/{secrets.token_hex(16)}_{secure_filename(filename)}"
        file_data.seek(0)
        s3_client.upload_fileobj(
            file_data,
            CLOUD_STORAGE_BUCKET,
            key,
            ExtraArgs={'ContentType': mimetypes.guess_type(filename)[0] or 'application/octet-stream'}
        )
        return key
    else:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{secrets.token_hex(16)}_{secure_filename(filename)}")
        file_data.seek(0)
        file_data.save(file_path)
        return file_path

def delete_file_from_storage(file_path):
    """Delete file from either local storage or cloud storage"""
    try:
        if USE_CLOUD_STORAGE:
            s3_client.delete_object(Bucket=CLOUD_STORAGE_BUCKET, Key=file_path)
        else:
            if os.path.exists(file_path):
                os.remove(file_path)
        return True
    except Exception as e:
        logger.error(f"Failed to delete file {file_path}: {e}")
        return False

# ==================== AUTHENTICATION ====================
ADMIN_PASSWORD_HASH = hashlib.sha256(os.environ.get('ADMIN_PASSWORD', 'admin123').encode()).hexdigest()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Please login as admin', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== HEALTH ROUTES ====================
@app.route('/health')
def health_check():
    """Health check endpoint for Render"""
    try:
        db.session.execute(text('SELECT 1'))
        return jsonify({'status': 'healthy', 'database': 'connected'}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/health/simple')
def simple_health():
    return jsonify({"status": "alive", "port": os.environ.get('PORT', 5000)}), 200

# ==================== USER ROUTES ====================
@app.route('/')
def index():
    return redirect(url_for('user_vault'))

@app.route('/vault', methods=['GET', 'POST'])
def user_vault():
    if request.method == 'POST':
        pin = request.form.get('pin')
        user = get_user_by_pin(pin)
        if user and user.is_active:
            session['user_id'] = user.id
            session['user_pin'] = user.pin
            session.permanent = True
            log_device_access(user.id, request)
            flash('Welcome to your secure vault!', 'success')
            return redirect(url_for('user_vault'))
        else:
            flash('Invalid PIN or account disabled', 'error')
            return redirect(url_for('user_vault'))
    
    if 'user_id' not in session:
        return render_template('user_vault.html', logged_in=False)
    
    user_id = session['user_id']
    restricted_items = get_user_permissions(user_id)
    parent_id = request.args.get('folder', None)
    
    if parent_id and parent_id != 'None':
        items = Item.query.filter_by(parent_id=parent_id).order_by(Item.type.desc(), Item.name).all()
        parent_folder = Item.query.get(parent_id)
        folder_name = parent_folder.name if parent_folder else 'Vault'
    else:
        items = Item.query.filter_by(parent_id=None).order_by(Item.type.desc(), Item.name).all()
        parent_id = None
        folder_name = 'Vault'
    
    items_with_access = []
    for item in items:
        items_with_access.append({
            'id': item.id,
            'name': item.name,
            'type': item.type,
            'thumbnail_path': item.thumbnail_path if not USE_CLOUD_STORAGE else None,
            'size': item.size,
            'can_access': item.id not in restricted_items,
            'icon': 'fa-folder' if item.type == 'folder' else get_file_icon(item.mime_type)
        })
    
    breadcrumb = []
    if parent_id:
        temp_id = parent_id
        while temp_id:
            crumb = Item.query.get(temp_id)
            if crumb:
                breadcrumb.insert(0, {'id': crumb.id, 'name': crumb.name})
                temp_id = crumb.parent_id
            else:
                break
    
    return render_template('user_vault.html', 
                         logged_in=True, 
                         items=items_with_access,
                         folder_id=parent_id, 
                         breadcrumb=breadcrumb)

@app.route('/download/<int:item_id>')
def download_item(item_id):
    if 'user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('user_vault'))
    
    user_id = session['user_id']
    if item_id in get_user_permissions(user_id):
        flash('Access denied', 'error')
        return redirect(url_for('user_vault'))
    
    item = Item.query.get(item_id)
    if not item:
        flash('Item not found', 'error')
        return redirect(url_for('user_vault'))
    
    # Log download
    download = Download(user_id=user_id, item_id=item_id)
    db.session.add(download)
    db.session.commit()
    
    if item.type == 'folder':
        # Create zip file for folder
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if USE_CLOUD_STORAGE:
                # List all files in folder from cloud storage
                prefix = item.file_path
                paginator = s3_client.get_paginator('list_objects_v2')
                for page in paginator.paginate(Bucket=CLOUD_STORAGE_BUCKET, Prefix=prefix):
                    if 'Contents' in page:
                        for obj in page['Contents']:
                            key = obj['Key']
                            if key != prefix + '/':
                                response = s3_client.get_object(Bucket=CLOUD_STORAGE_BUCKET, Key=key)
                                zipf.writestr(key.replace(prefix, ''), response['Body'].read())
            else:
                for root, dirs, files in os.walk(item.file_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, item.file_path)
                        zipf.write(file_path, arcname)
        
        zip_buffer.seek(0)
        
        @after_this_request
        def cleanup(response):
            zip_buffer.close()
            return response
        
        return send_file(
            zip_buffer,
            as_attachment=True,
            download_name=f"{item.name}.zip",
            mimetype='application/zip'
        )
    else:
        # Download single file
        if USE_CLOUD_STORAGE:
            # Generate presigned URL for direct download
            url = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': CLOUD_STORAGE_BUCKET, 'Key': item.file_path},
                ExpiresIn=3600
            )
            return redirect(url)
        else:
            return send_file(item.file_path, as_attachment=True, download_name=item.name)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('user_vault'))

# ==================== ADMIN ROUTES ====================
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        password = request.form.get('password')
        if hashlib.sha256(password.encode()).hexdigest() == ADMIN_PASSWORD_HASH:
            session['is_admin'] = True
            session.permanent = True
            flash('Welcome Admin!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid password', 'error')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_files = Item.query.filter_by(type='file').count()
    total_folders = Item.query.filter_by(type='folder').count()
    total_downloads = Download.query.count()
    
    users = db.session.query(
        User.id, User.pin, User.created_at, User.is_active,
        func.count(DeviceLog.id).label('device_count')
    ).outerjoin(DeviceLog).group_by(User.id).order_by(User.created_at.desc()).all()
    
    items = Item.query.order_by(Item.created_at.desc()).limit(100).all()
    folders = Item.query.filter_by(type='folder').order_by(Item.name).all()
    
    return render_template('admin_dashboard.html', 
                         total_users=total_users, 
                         total_files=total_files,
                         total_folders=total_folders, 
                         total_downloads=total_downloads,
                         users=users, 
                         items=items, 
                         folders=folders,
                         use_cloud_storage=USE_CLOUD_STORAGE)

@app.route('/admin/create_pin', methods=['POST'])
@admin_required
def create_pin():
    pin = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ0123456789') for _ in range(8))
    user = User(pin=pin, is_active=True)
    db.session.add(user)
    try:
        db.session.commit()
        flash(f'PIN created: {pin}', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to create PIN: {e}")
        flash('Failed to create PIN', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/revoke_pin/<int:user_id>')
@admin_required
def revoke_pin(user_id):
    user = User.query.get(user_id)
    if user:
        user.is_active = False
        db.session.commit()
        flash('PIN revoked', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/activate_pin/<int:user_id>')
@admin_required
def activate_pin(user_id):
    user = User.query.get(user_id)
    if user:
        user.is_active = True
        db.session.commit()
        flash('PIN activated', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_pin/<int:user_id>')
@admin_required
def delete_pin(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('PIN deleted', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user_devices/<int:user_id>')
@admin_required
def user_devices(user_id):
    user = User.query.get(user_id)
    devices = DeviceLog.query.filter_by(user_id=user_id).order_by(DeviceLog.accessed_at.desc()).limit(50).all()
    downloads = db.session.query(Download, Item.name).join(Item).filter(Download.user_id == user_id).order_by(Download.downloaded_at.desc()).limit(20).all()
    return render_template('user_devices.html', devices=devices, downloads=downloads, user=user)

@app.route('/admin/upload', methods=['POST'])
@admin_required
def upload_item():
    name = request.form.get('name')
    item_type = request.form.get('type')
    parent_id = request.form.get('parent_id') or None
    file = request.files.get('file')
    picture = request.files.get('picture')
    
    if not name:
        flash('Name required', 'error')
        return redirect(url_for('admin_dashboard'))
    
    if item_type == 'folder':
        # Create folder
        if USE_CLOUD_STORAGE:
            folder_key = f"folders/{secrets.token_hex(16)}/"
            s3_client.put_object(Bucket=CLOUD_STORAGE_BUCKET, Key=folder_key)
            file_path = folder_key
        else:
            folder_path = os.path.join(app.config['UPLOAD_FOLDER'], f"folder_{secrets.token_hex(16)}")
            os.makedirs(folder_path, exist_ok=True)
            file_path = folder_path
        
        # Handle folder thumbnail
        thumbnail_path = None
        if picture and picture.filename:
            if USE_CLOUD_STORAGE:
                thumb_key = f"thumbnails/thumb_{secrets.token_hex(16)}.jpg"
                picture.seek(0)
                s3_client.upload_fileobj(picture, CLOUD_STORAGE_BUCKET, thumb_key, 
                                        ExtraArgs={'ContentType': 'image/jpeg'})
                thumbnail_path = thumb_key
            else:
                thumb_filename = f"thumb_{secrets.token_hex(16)}.jpg"
                thumb_full_path = os.path.join(app.config['THUMBNAIL_FOLDER'], thumb_filename)
                picture.save(thumb_full_path)
                thumbnail_path = thumb_full_path
        
        item = Item(name=name, type='folder', file_path=file_path, 
                   thumbnail_path=thumbnail_path, parent_id=parent_id)
        db.session.add(item)
        db.session.commit()
        flash(f'Folder "{name}" created', 'success')
        
    elif item_type == 'file' and file and file.filename:
        # Upload file
        filename = secure_filename(file.filename)
        file_path = save_file_to_storage(file, filename, 'files')
        
        # Create thumbnail for images
        thumbnail_path = None
        if picture and picture.filename:
            thumb_filename = f"thumb_{secrets.token_hex(16)}.jpg"
            if USE_CLOUD_STORAGE:
                thumb_key = f"thumbnails/{thumb_filename}"
                picture.seek(0)
                s3_client.upload_fileobj(picture, CLOUD_STORAGE_BUCKET, thumb_key,
                                        ExtraArgs={'ContentType': 'image/jpeg'})
                thumbnail_path = thumb_key
            else:
                thumb_full_path = os.path.join(app.config['THUMBNAIL_FOLDER'], thumb_filename)
                picture.save(thumb_full_path)
                thumbnail_path = thumb_full_path
        elif file.content_type and file.content_type.startswith('image/'):
            thumb_filename = f"thumb_{secrets.token_hex(16)}.jpg"
            if USE_CLOUD_STORAGE:
                thumb_key = f"thumbnails/{thumb_filename}"
                file.seek(0)
                if create_thumbnail(file_path, thumb_key):
                    thumbnail_path = thumb_key
            else:
                thumb_full_path = os.path.join(app.config['THUMBNAIL_FOLDER'], thumb_filename)
                if create_thumbnail(file_path, thumb_full_path):
                    thumbnail_path = thumb_full_path
        
        # Get file size
        if USE_CLOUD_STORAGE:
            response = s3_client.head_object(Bucket=CLOUD_STORAGE_BUCKET, Key=file_path)
            file_size = response['ContentLength']
        else:
            file_size = os.path.getsize(file_path)
        
        mime_type = file.content_type or mimetypes.guess_type(filename)[0]
        
        item = Item(name=name, type='file', file_path=file_path, 
                   thumbnail_path=thumbnail_path, parent_id=parent_id, 
                   size=file_size, mime_type=mime_type)
        db.session.add(item)
        db.session.commit()
        flash(f'File "{name}" uploaded', 'success')
    else:
        flash('Please provide a file', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_item/<int:item_id>')
@admin_required
def delete_item(item_id):
    item = Item.query.get(item_id)
    if item:
        # Delete from storage
        if item.type == 'folder':
            if USE_CLOUD_STORAGE:
                # Delete all objects with folder prefix
                prefix = item.file_path
                paginator = s3_client.get_paginator('list_objects_v2')
                for page in paginator.paginate(Bucket=CLOUD_STORAGE_BUCKET, Prefix=prefix):
                    if 'Contents' in page:
                        objects = [{'Key': obj['Key']} for obj in page['Contents']]
                        s3_client.delete_objects(Bucket=CLOUD_STORAGE_BUCKET, Delete={'Objects': objects})
            else:
                if os.path.exists(item.file_path):
                    shutil.rmtree(item.file_path)
        else:
            delete_file_from_storage(item.file_path)
        
        # Delete thumbnail
        if item.thumbnail_path:
            delete_file_from_storage(item.thumbnail_path)
        
        db.session.delete(item)
        db.session.commit()
        flash('Item deleted', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/get_permissions/<int:user_id>')
@admin_required
def get_permissions(user_id):
    permissions = UserItemPermission.query.filter_by(user_id=user_id, can_access=False).all()
    return jsonify({'restricted': [p.item_id for p in permissions]})

@app.route('/admin/update_permissions', methods=['POST'])
@admin_required
def update_permissions():
    user_id = request.form.get('user_id')
    restricted_items = request.form.getlist('restricted_items')
    
    # Delete existing permissions
    UserItemPermission.query.filter_by(user_id=user_id).delete()
    
    # Add new restricted items
    for item_id in restricted_items:
        db.session.add(UserItemPermission(user_id=user_id, item_id=item_id, can_access=False))
    
    db.session.commit()
    flash('Permissions updated', 'success')
    return redirect(url_for('admin_dashboard'))

# ==================== ERROR HANDLERS ====================
@app.errorhandler(413)
def too_large(e):
    flash('File too large. Maximum size is 500MB.', 'error')
    return redirect(request.url)

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return render_template('500.html'), 500

# ==================== INITIALIZATION ====================
# Initialize database when the app starts
with app.app_context():
    init_database()

# ==================== MAIN ENTRY POINT ====================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f"Starting Flask server on port {port}", file=sys.stderr)
    app.run(host='0.0.0.0', port=port, debug=debug)
