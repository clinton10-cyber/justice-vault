import os
import secrets
import zipfile
import shutil
import hashlib
import logging
import mimetypes
import sys
import time
import socket
import re
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

load_dotenv()

print("=" * 50, file=sys.stderr)
print("🚀 JUSTICE VAULT APPLICATION STARTING", file=sys.stderr)
print(f"🐍 Python version: {sys.version}", file=sys.stderr)
print("=" * 50, file=sys.stderr)
sys.stderr.flush()

app = Flask(__name__)

# ==================== CONFIGURATION ====================
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

IS_RENDER = bool(os.environ.get('RENDER'))
IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production'

print(f"📡 Environment: {'RENDER' if IS_RENDER else 'LOCAL'}", file=sys.stderr)

app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

# Storage
if IS_RENDER:
    app.config['UPLOAD_FOLDER'] = '/tmp/storage/files'
    app.config['THUMBNAIL_FOLDER'] = '/tmp/storage/thumbnails'
else:
    app.config['UPLOAD_FOLDER'] = 'storage/files'
    app.config['THUMBNAIL_FOLDER'] = 'storage/thumbnails'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['THUMBNAIL_FOLDER'], exist_ok=True)

# Database
database_url = os.environ.get('DATABASE_URL')
if not database_url:
    database_url = 'sqlite:///database/vault.db?check_same_thread=False'
    os.makedirs('database', exist_ok=True)
    print("📀 Using SQLite database (local only)", file=sys.stderr)

if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

if database_url and 'postgresql' in database_url:
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 20,
        'max_overflow': 30,
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_timeout': 30,
    }
else:
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 10,
        'pool_pre_ping': True,
        'pool_recycle': 3600,
        'connect_args': {'check_same_thread': False}
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
    original_filename: Mapped[str] = mapped_column(String(500), nullable=True)
    type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    file_path: Mapped[str] = mapped_column(Text, nullable=True)
    thumbnail_path: Mapped[str] = mapped_column(Text, nullable=True)
    parent_id: Mapped[int] = mapped_column(Integer, ForeignKey('items.id', ondelete='CASCADE'), nullable=True, index=True)
    size: Mapped[int] = mapped_column(BigInteger, nullable=True)
    mime_type: Mapped[str] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    link_url: Mapped[str] = mapped_column(Text, nullable=True)
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
        db.session.rollback()

def get_user_by_pin(pin):
    return User.query.filter_by(pin=pin).first()

def get_user_permissions(user_id):
    permissions = UserItemPermission.query.filter_by(user_id=user_id, can_access=False).all()
    return [p.item_id for p in permissions]

def get_file_icon(mime_type):
    if not mime_type:
        return 'fa-file'
    if mime_type.startswith('image/'):
        return 'fa-file-image'
    elif mime_type.startswith('video/'):
        return 'fa-file-video'
    elif mime_type.startswith('audio/'):
        return 'fa-file-audio'
    elif mime_type == 'application/pdf':
        return 'fa-file-pdf'
    elif 'zip' in mime_type or 'rar' in mime_type or 'compressed' in mime_type:
        return 'fa-file-archive'
    elif 'word' in mime_type or 'document' in mime_type:
        return 'fa-file-word'
    elif 'excel' in mime_type or 'spreadsheet' in mime_type:
        return 'fa-file-excel'
    elif 'powerpoint' in mime_type or 'presentation' in mime_type:
        return 'fa-file-powerpoint'
    elif mime_type.startswith('text/'):
        return 'fa-file-alt'
    else:
        return 'fa-file'

def create_thumbnail(file_path, thumbnail_path, size=(300, 300)):
    try:
        img = Image.open(file_path)
        if img.mode in ('RGBA', 'P'):
            img = img.convert('RGB')
        img.thumbnail(size, Image.Resampling.LANCZOS)
        img.save(thumbnail_path, 'JPEG', quality=85, optimize=True)
        return True
    except Exception as e:
        logger.error(f"Thumbnail creation error: {e}")
        return False

def delete_file_from_storage(file_path):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        return True
    except Exception as e:
        logger.error(f"Failed to delete file {file_path}: {e}")
        return False

def format_file_size(size_bytes):
    if size_bytes is None:
        return "Unknown"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

def is_folder_link(url):
    folder_indicators = [
        '/folders/', '/drive/folders/', '#folders',
        'drive.google.com/drive/folders',
        'dropbox.com/sh/', 'onedrive.live.com/?id=',
        '/sh/', '/folder/'
    ]
    return any(indicator in url for indicator in folder_indicators)

def get_google_drive_direct_url(url):
    """Convert any Google Drive URL to a working direct download URL"""
    patterns = [
        r'/file/d/([a-zA-Z0-9_-]+)',
        r'id=([a-zA-Z0-9_-]+)',
        r'/uc\?id=([a-zA-Z0-9_-]+)',
        r'open\?id=([a-zA-Z0-9_-]+)',
        r'drive\.google\.com/file/d/([a-zA-Z0-9_-]+)',
    ]
    
    file_id = None
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            file_id = match.group(1)
            break
    
    if file_id:
        return f"https://drive.usercontent.google.com/download?id={file_id}&confirm=t&export=download"
    
    return url

# ==================== DATABASE INITIALIZATION ====================
def init_database():
    try:
        with app.app_context():
            if database_url and 'postgresql' in database_url:
                socket.setdefaulttimeout(10)
            db.engine.dispose()
            db.engine.connect()
            db.create_all()
            
            try:
                with db.engine.connect() as conn:
                    conn.execute(text('ALTER TABLE items ADD COLUMN link_url TEXT'))
                    conn.commit()
                print("✅ Added link_url column to items table", file=sys.stderr)
            except Exception as e:
                if "duplicate column" not in str(e).lower():
                    print(f"Note: {e}", file=sys.stderr)
            
            print("✅ Database initialized successfully", file=sys.stderr)
            return True
    except Exception as e:
        print(f"❌ Database init failed: {e}", file=sys.stderr)
        return False

# ==================== AUTHENTICATION ====================
ADMIN_PASSWORD_HASH = hashlib.sha256(os.environ.get('ADMIN_PASSWORD', 'admin123').encode()).hexdigest()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Please login to continue', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== HEALTH ROUTES ====================
@app.route('/health')
def health_check():
    try:
        db.session.execute(text('SELECT 1'))
        return jsonify({'status': 'healthy', 'database': 'connected', 'timestamp': datetime.utcnow().isoformat()}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e), 'timestamp': datetime.utcnow().isoformat()}), 500

@app.route('/health/simple')
def simple_health():
    return jsonify({"status": "alive", "port": os.environ.get('PORT', 5000)}), 200

# ==================== OWNER IMAGE ROUTE ====================
@app.route('/owner-image')
def owner_image():
    try:
        image_path = os.path.join(app.root_path, 'templates', 'owner.jpg')
        if os.path.exists(image_path):
            return send_file(image_path, mimetype='image/jpeg')
        else:
            alt_paths = ['owner.jpg', 'static/owner.jpg', 'templates/owner.jpg']
            for path in alt_paths:
                if os.path.exists(path):
                    return send_file(path, mimetype='image/jpeg')
            return '', 404
    except Exception as e:
        logger.error(f"Error serving owner image: {e}")
        return '', 404

# ==================== THUMBNAIL SERVING ====================
@app.route('/thumbnail/<path:filename>')
def serve_thumbnail(filename):
    try:
        safe_filename = os.path.basename(filename)
        safe_path = os.path.join(app.config['THUMBNAIL_FOLDER'], safe_filename)
        if os.path.exists(safe_path) and os.path.isfile(safe_path):
            return send_file(safe_path, mimetype='image/jpeg')
        return '', 404
    except Exception as e:
        logger.error(f"Thumbnail serving error: {e}")
        return '', 404

# ==================== ADMIN ROUTES ====================
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        if hashlib.sha256(password.encode()).hexdigest() == ADMIN_PASSWORD_HASH:
            session['is_admin'] = True
            session.permanent = True
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid password', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@app.route('/admin/dashboard/<int:folder_id>')
@admin_required
def admin_dashboard(folder_id=None):
    try:
        total_users = User.query.count()
        total_files = Item.query.filter_by(type='file').count()
        total_folders = Item.query.filter_by(type='folder').count()
        total_downloads = Download.query.count()
        
        users_data = db.session.query(
            User.id, User.pin, User.created_at, User.is_active,
            db.func.coalesce(db.func.count(DeviceLog.id), 0).label('device_count')
        ).outerjoin(DeviceLog, User.id == DeviceLog.user_id
        ).group_by(User.id, User.pin, User.created_at, User.is_active
        ).order_by(User.created_at.desc()).all()
        
        user_list = [{
            'id': u[0], 
            'pin': u[1], 
            'created_at': u[2], 
            'is_active': u[3], 
            'device_count': u[4]
        } for u in users_data]

        current_folder = None
        if folder_id:
            current_folder = Item.query.get(folder_id)
            if not current_folder or current_folder.type != 'folder':
                flash('Invalid folder', 'error')
                return redirect(url_for('admin_dashboard'))
        
        items = Item.query.filter_by(parent_id=folder_id).order_by(Item.type.desc(), Item.name).all()
        items_list = [{
            'id': item.id,
            'name': item.name,
            'type': item.type,
            'size': item.size,
            'size_formatted': format_file_size(item.size),
            'created_at': item.created_at,
            'parent_id': item.parent_id,
            'mime_type': item.mime_type or '',
            'icon': 'fa-folder' if item.type == 'folder' else get_file_icon(item.mime_type),
            'thumbnail_path': item.thumbnail_path,
            'link_url': item.link_url
        } for item in items]

        all_folders = Item.query.filter_by(type='folder').order_by(Item.name).all()
        folders_list = [{'id': f.id, 'name': f.name, 'parent_id': f.parent_id} for f in all_folders]

        breadcrumb = []
        if folder_id:
            temp_id = folder_id
            while temp_id:
                crumb = Item.query.get(temp_id)
                if crumb:
                    breadcrumb.insert(0, {'id': crumb.id, 'name': crumb.name})
                    temp_id = crumb.parent_id
                else:
                    break

        return render_template('admin_dashboard.html', 
                             total_users=total_users, 
                             total_files=total_files,
                             total_folders=total_folders, 
                             total_downloads=total_downloads,
                             users=user_list, 
                             items=items_list,
                             folders=folders_list,
                             current_folder=current_folder,
                             breadcrumb=breadcrumb,
                             folder_id=folder_id)

    except Exception as e:
        logger.error(f"Admin dashboard error: {e}", exc_info=True)
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return redirect(url_for('admin_login'))

@app.route('/admin/create_pin', methods=['POST'])
@admin_required
def create_pin():
    folder_id = request.form.get('folder_id', '')
    
    pin = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(8))
    
    user = User(pin=pin, is_active=True)
    db.session.add(user)
    
    try:
        db.session.commit()
        flash(f'✅ PIN created successfully: {pin}', 'success')
        logger.info(f"New PIN generated: {pin}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to create PIN: {e}")
        flash('❌ Failed to create PIN. Please try again.', 'error')
    
    if folder_id and folder_id != 'None' and folder_id != '':
        return redirect(url_for('admin_dashboard', folder_id=int(folder_id)))
    else:
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/revoke_pin/<int:user_id>')
@admin_required
def revoke_pin(user_id):
    folder_id = request.args.get('folder_id', '')
    user = User.query.get(user_id)
    if user:
        user.is_active = False
        db.session.commit()
        flash(f'🔒 PIN {user.pin} has been revoked', 'success')
    else:
        flash('User not found', 'error')
    
    if folder_id and folder_id != 'None' and folder_id != '':
        return redirect(url_for('admin_dashboard', folder_id=int(folder_id)))
    else:
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/activate_pin/<int:user_id>')
@admin_required
def activate_pin(user_id):
    folder_id = request.args.get('folder_id', '')
    user = User.query.get(user_id)
    if user:
        user.is_active = True
        db.session.commit()
        flash(f'🔓 PIN {user.pin} has been activated', 'success')
    else:
        flash('User not found', 'error')
    
    if folder_id and folder_id != 'None' and folder_id != '':
        return redirect(url_for('admin_dashboard', folder_id=int(folder_id)))
    else:
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_pin/<int:user_id>')
@admin_required
def delete_pin(user_id):
    folder_id = request.args.get('folder_id', '')
    user = User.query.get(user_id)
    if user:
        pin = user.pin
        db.session.delete(user)
        db.session.commit()
        flash(f'🗑️ User with PIN {pin} has been permanently deleted', 'success')
    else:
        flash('User not found', 'error')
    
    if folder_id and folder_id != 'None' and folder_id != '':
        return redirect(url_for('admin_dashboard', folder_id=int(folder_id)))
    else:
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/user_devices/<int:user_id>')
@admin_required
def user_devices(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin_dashboard'))
    
    devices = DeviceLog.query.filter_by(user_id=user_id).order_by(DeviceLog.accessed_at.desc()).limit(50).all()
    downloads = db.session.query(Download, Item.name).join(Item).filter(Download.user_id == user_id).order_by(Download.downloaded_at.desc()).limit(20).all()
    return render_template('user_devices.html', devices=devices, downloads=downloads, user=user)

@app.route('/admin/upload', methods=['POST'])
@admin_required
def upload_item():
    name = request.form.get('name')
    item_type = request.form.get('type')
    parent_id = request.form.get('parent_id')
    file = request.files.get('file')
    picture = request.files.get('picture')
    link_url = request.form.get('link_url')
    
    if not parent_id or parent_id == '' or parent_id == 'None':
        parent_id = None
    else:
        try:
            parent_id = int(parent_id)
            parent = Item.query.get(parent_id)
            if not parent or parent.type != 'folder':
                parent_id = None
        except (ValueError, TypeError):
            parent_id = None
    
    if not name:
        flash('Name is required', 'error')
        return redirect(url_for('admin_dashboard', folder_id=parent_id))
    
    if item_type == 'folder':
        thumbnail_path = None
        if picture and picture.filename:
            thumb_filename = f"thumb_{secrets.token_hex(16)}.jpg"
            thumb_full_path = os.path.join(app.config['THUMBNAIL_FOLDER'], thumb_filename)
            picture.save(thumb_full_path)
            thumbnail_path = thumb_full_path
        
        item = Item(name=name.strip(), type='folder', file_path=None, 
                   thumbnail_path=thumbnail_path, parent_id=parent_id)
        db.session.add(item)
        db.session.commit()
        flash(f'📁 Folder "{name}" created successfully!', 'success')
        
    elif item_type == 'file' and file and file.filename:
        original_filename = secure_filename(file.filename)
        file_ext = os.path.splitext(original_filename)[1]
        unique_filename = f"{secrets.token_hex(16)}{file_ext}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        thumbnail_path = None
        if picture and picture.filename:
            thumb_filename = f"thumb_{secrets.token_hex(16)}.jpg"
            thumb_full_path = os.path.join(app.config['THUMBNAIL_FOLDER'], thumb_filename)
            picture.save(thumb_full_path)
            thumbnail_path = thumb_full_path
        elif file.content_type and file.content_type.startswith('image/'):
            thumb_filename = f"thumb_{secrets.token_hex(16)}.jpg"
            thumb_full_path = os.path.join(app.config['THUMBNAIL_FOLDER'], thumb_filename)
            if create_thumbnail(file_path, thumb_full_path):
                thumbnail_path = thumb_full_path
        
        file_size = os.path.getsize(file_path)
        mime_type = file.content_type or mimetypes.guess_type(original_filename)[0]
        
        item = Item(name=name.strip(), original_filename=original_filename, type='file', 
                   file_path=file_path, thumbnail_path=thumbnail_path, 
                   parent_id=parent_id, size=file_size, mime_type=mime_type)
        db.session.add(item)
        db.session.commit()
        flash(f'📄 File "{name}" uploaded successfully!', 'success')
    
    elif item_type == 'link' and link_url and link_url.strip():
        if not link_url.startswith(('http://', 'https://')):
            flash('Please enter a valid URL starting with http:// or https://', 'error')
            return redirect(url_for('admin_dashboard', folder_id=parent_id))
        
        if is_folder_link(link_url):
            flash('⚠️ This appears to be a folder link. Please use direct file links only.', 'error')
            return redirect(url_for('admin_dashboard', folder_id=parent_id))
        
        thumbnail_path = None
        if picture and picture.filename:
            thumb_filename = f"thumb_{secrets.token_hex(16)}.jpg"
            thumb_full_path = os.path.join(app.config['THUMBNAIL_FOLDER'], thumb_filename)
            picture.save(thumb_full_path)
            thumbnail_path = thumb_full_path
        
        item = Item(
            name=name.strip(), 
            type='file',
            link_url=link_url,
            file_path=None,
            thumbnail_path=thumbnail_path, 
            parent_id=parent_id, 
            size=None, 
            mime_type=None
        )
        db.session.add(item)
        db.session.commit()
        flash(f'🔗 Link file "{name}" added successfully!', 'success')
    else:
        flash('Please provide a file or valid URL', 'error')
    
    return redirect(url_for('admin_dashboard', folder_id=parent_id))

@app.route('/admin/delete_item/<int:item_id>')
@admin_required
def delete_item(item_id):
    item = Item.query.get(item_id)
    parent_id = item.parent_id if item else None
    
    if item:
        name = item.name
        if item.type == 'folder':
            def delete_children(folder_item):
                for child in folder_item.children:
                    if child.type == 'folder':
                        delete_children(child)
                    elif child.type == 'file' and child.file_path:
                        delete_file_from_storage(child.file_path)
                    if child.thumbnail_path:
                        delete_file_from_storage(child.thumbnail_path)
                    db.session.delete(child)
            delete_children(item)
            
        elif item.type == 'file' and item.file_path:
            delete_file_from_storage(item.file_path)
        
        if item.thumbnail_path:
            delete_file_from_storage(item.thumbnail_path)
        
        db.session.delete(item)
        db.session.commit()
        flash(f'🗑️ "{name}" permanently deleted', 'success')
    else:
        flash('Item not found', 'error')
    
    return redirect(url_for('admin_dashboard', folder_id=parent_id))

@app.route('/admin/move_item/<int:item_id>', methods=['POST'])
@admin_required
def move_item(item_id):
    new_parent_id = request.form.get('new_parent_id')
    current_folder_id = request.form.get('current_folder_id')
    
    if not new_parent_id or new_parent_id == '' or new_parent_id == 'None':
        new_parent_id = None
    else:
        try:
            new_parent_id = int(new_parent_id)
        except (ValueError, TypeError):
            new_parent_id = None
    
    item = Item.query.get(item_id)
    if item:
        old_parent = item.parent_id
        item.parent_id = new_parent_id
        db.session.commit()
        flash(f'📦 "{item.name}" moved successfully!', 'success')
        logger.info(f"Item {item_id} moved from folder {old_parent} to {new_parent_id}")
    else:
        flash('Item not found', 'error')
    
    if current_folder_id and current_folder_id != 'None' and current_folder_id != '':
        return redirect(url_for('admin_dashboard', folder_id=int(current_folder_id)))
    else:
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/rename_item/<int:item_id>', methods=['POST'])
@admin_required
def rename_item(item_id):
    new_name = request.form.get('new_name')
    current_folder_id = request.form.get('current_folder_id')
    
    item = Item.query.get(item_id)
    if item and new_name:
        old_name = item.name
        item.name = new_name.strip()
        db.session.commit()
        flash(f'✏️ Item renamed from "{old_name}" to "{new_name}"', 'success')
        logger.info(f"Item {item_id} renamed from '{old_name}' to '{new_name}'")
    else:
        flash('Failed to rename item', 'error')
    
    if current_folder_id and current_folder_id != 'None' and current_folder_id != '':
        return redirect(url_for('admin_dashboard', folder_id=int(current_folder_id)))
    else:
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
    restricted_items_str = request.form.get('restricted_items', '')
    folder_id = request.form.get('folder_id', '')
    
    if not user_id:
        flash('Please select a user', 'error')
        if folder_id and folder_id != 'None' and folder_id != '':
            return redirect(url_for('admin_dashboard', folder_id=int(folder_id)))
        else:
            return redirect(url_for('admin_dashboard'))
    
    try:
        user_id = int(user_id)
        restricted_items = [int(x) for x in restricted_items_str.split(',') if x.strip()]
        
        UserItemPermission.query.filter_by(user_id=user_id).delete()
        
        for item_id in restricted_items:
            db.session.add(UserItemPermission(user_id=user_id, item_id=item_id, can_access=False))
        
        db.session.commit()
        
        user = User.query.get(user_id)
        flash(f'🔐 Permissions updated successfully for PIN: {user.pin}', 'success')
        logger.info(f"Permissions updated for user {user_id}, restricted items: {restricted_items}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to update permissions: {e}")
        flash('Failed to update permissions', 'error')
    
    if folder_id and folder_id != 'None' and folder_id != '':
        return redirect(url_for('admin_dashboard', folder_id=int(folder_id)))
    else:
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('admin_login'))

# ==================== USER ROUTES ====================
@app.route('/')
def index():
    return redirect(url_for('user_vault'))

@app.route('/vault', methods=['GET', 'POST'])
def user_vault():
    if request.method == 'POST':
        pin = request.form.get('pin', '').strip().upper()
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
        try:
            parent_id_int = int(parent_id)
            items = Item.query.filter_by(parent_id=parent_id_int).order_by(Item.type.desc(), Item.name).all()
        except (ValueError, TypeError):
            items = Item.query.filter_by(parent_id=None).order_by(Item.type.desc(), Item.name).all()
            parent_id = None
    else:
        items = Item.query.filter_by(parent_id=None).order_by(Item.type.desc(), Item.name).all()
        parent_id = None
    
    items_with_access = []
    for item in items:
        thumbnail_url = None
        if item.thumbnail_path:
            thumbnail_url = url_for('serve_thumbnail', filename=os.path.basename(item.thumbnail_path))
        
        items_with_access.append({
            'id': item.id, 
            'name': item.name, 
            'type': item.type,
            'thumbnail_url': thumbnail_url, 
            'size': item.size,
            'size_formatted': format_file_size(item.size),
            'can_access': item.id not in restricted_items,
            'icon': 'fa-folder' if item.type == 'folder' else get_file_icon(item.mime_type),
            'link_url': item.link_url  # Pass link_url to template
        })
    
    breadcrumb = []
    if parent_id:
        temp_id = int(parent_id)
        while temp_id:
            crumb = Item.query.get(temp_id)
            if crumb:
                breadcrumb.insert(0, {'id': crumb.id, 'name': crumb.name})
                temp_id = crumb.parent_id
            else:
                break
    
    return render_template('user_vault.html', logged_in=True, items=items_with_access,
                         folder_id=parent_id, breadcrumb=breadcrumb)

@app.route('/download/<int:item_id>')
def download_item(item_id):
    if 'user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('user_vault'))
    
    user_id = session['user_id']
    if item_id in get_user_permissions(user_id):
        flash('Access denied to this item', 'error')
        return redirect(url_for('user_vault'))
    
    item = Item.query.get(item_id)
    if not item:
        flash('Item not found', 'error')
        return redirect(url_for('user_vault'))
    
    # Log download
    download = Download(user_id=user_id, item_id=item_id)
    db.session.add(download)
    db.session.commit()
    
    # Handle link files - OPEN IN NEW TAB INSTEAD OF STREAMING
    if item.link_url and not item.file_path:
        # Convert Google Drive links to direct download format
        download_url = item.link_url
        if 'drive.google.com' in download_url:
            download_url = get_google_drive_direct_url(download_url)
        
        # Return HTML that opens the link in a new tab and closes it
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Opening Download...</title>
            <script>
                // Open the download link in a new tab
                var downloadWindow = window.open("{download_url}", "_blank");
                
                // Close this tab after a short delay
                setTimeout(function() {{
                    window.close();
                }}, 2000);
                
                // Show message to user
                document.body.innerHTML = `
                    <div style="text-align: center; font-family: Arial, sans-serif; padding: 50px;">
                        <h2>Opening Download...</h2>
                        <p>If the download doesn't start automatically, <a href="{download_url}" target="_blank">click here</a></p>
                        <p>This tab will close automatically.</p>
                    </div>
                `;
            </script>
        </head>
        <body style="text-align: center; font-family: Arial, sans-serif; padding: 50px;">
            <h2>Opening Download...</h2>
            <p>If the download doesn't start automatically, <a href="{download_url}" target="_blank">click here</a></p>
            <p>This tab will close automatically.</p>
        </body>
        </html>
        '''
    
    # Handle folder downloads (zip)
    if item.type == 'folder':
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
            def add_folder_to_zip(folder_item, path=""):
                for child in folder_item.children:
                    if child.type == 'folder':
                        add_folder_to_zip(child, os.path.join(path, child.name))
                    elif child.type == 'file' and child.file_path and os.path.exists(child.file_path):
                        arcname = os.path.join(path, child.original_filename or child.name)
                        zipf.write(child.file_path, arcname)
            add_folder_to_zip(item, item.name)
        zip_buffer.seek(0)
        
        @after_this_request
        def cleanup(response):
            zip_buffer.close()
            return response
        
        return send_file(zip_buffer, as_attachment=True, download_name=f"{item.name}.zip", mimetype='application/zip')
    
    # Handle regular file downloads
    else:
        if not item.file_path or not os.path.exists(item.file_path):
            flash('File not found on server', 'error')
            return redirect(url_for('user_vault'))
        
        download_filename = item.original_filename if item.original_filename else item.name
        if '.' not in download_filename and item.mime_type:
            ext = mimetypes.guess_extension(item.mime_type)
            if ext:
                download_filename = f"{download_filename}{ext}"
        
        return send_file(item.file_path, as_attachment=True, download_name=download_filename,
                        mimetype=item.mime_type or 'application/octet-stream')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

# ==================== ERROR HANDLERS ====================
@app.errorhandler(413)
def too_large(e):
    flash('File too large. Maximum size is 500MB.', 'error')
    return redirect(request.url)

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error_message="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}", exc_info=True)
    return render_template('error.html', error_message="Internal server error. Please try again."), 500

# ==================== INITIALIZATION ====================
with app.app_context():
    init_database()

print("=" * 50, file=sys.stderr)
print("✅ JUSTICE VAULT APP IS READY", file=sys.stderr)
print("📍 Admin login: /admin", file=sys.stderr)
print("📍 User vault: /vault", file=sys.stderr)
print("📍 Default admin password: admin123", file=sys.stderr)
print("=" * 50, file=sys.stderr)
sys.stderr.flush()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug, threaded=True)
