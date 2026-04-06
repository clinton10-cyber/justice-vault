import os
import secrets
import zipfile
import shutil
import hashlib
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, String, Boolean, DateTime, Text, BigInteger, ForeignKey
import user_agents
from PIL import Image
import mimetypes

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'storage/files'
app.config['THUMBNAIL_FOLDER'] = 'storage/thumbnails'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database/vault.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_pre_ping': True,
    'pool_recycle': 3600,
}

db = SQLAlchemy(app)

# Models
class User(db.Model):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pin: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    device_logs = db.relationship('DeviceLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    downloads = db.relationship('Download', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    permissions = db.relationship('UserItemPermission', backref='user', lazy='dynamic', cascade='all, delete-orphan')

class Item(db.Model):
    __tablename__ = 'items'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    type: Mapped[str] = mapped_column(String(20), nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=True)
    thumbnail_path: Mapped[str] = mapped_column(Text, nullable=True)
    parent_id: Mapped[int] = mapped_column(Integer, ForeignKey('items.id', ondelete='CASCADE'), nullable=True)
    size: Mapped[int] = mapped_column(BigInteger, nullable=True)
    mime_type: Mapped[str] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    children = db.relationship('Item', backref=db.backref('parent', remote_side=[id]), lazy='dynamic')
    permissions = db.relationship('UserItemPermission', backref='item', lazy='dynamic', cascade='all, delete-orphan')
    downloads = db.relationship('Download', backref='item', lazy='dynamic', cascade='all, delete-orphan')

class UserItemPermission(db.Model):
    __tablename__ = 'user_item_permissions'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    item_id: Mapped[int] = mapped_column(Integer, ForeignKey('items.id', ondelete='CASCADE'), nullable=False)
    can_access: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('user_id', 'item_id', name='unique_user_item'),)

class DeviceLog(db.Model):
    __tablename__ = 'device_logs'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(50))
    user_agent: Mapped[str] = mapped_column(Text)
    device_type: Mapped[str] = mapped_column(String(100))
    browser: Mapped[str] = mapped_column(String(100))
    os: Mapped[str] = mapped_column(String(100))
    accessed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Download(db.Model):
    __tablename__ = 'downloads'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    item_id: Mapped[int] = mapped_column(Integer, ForeignKey('items.id', ondelete='CASCADE'), nullable=False)
    downloaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

ADMIN_PASSWORD_HASH = hashlib.sha256(os.environ.get('ADMIN_PASSWORD', 'admin123').encode()).hexdigest()

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['THUMBNAIL_FOLDER'], exist_ok=True)

def parse_user_agent(ua_string):
    ua = user_agents.parse(ua_string)
    return {'device_type': ua.device.family, 'browser': ua.browser.family, 'os': ua.os.family}

def log_device_access(user_id, request):
    ua_info = parse_user_agent(request.user_agent.string)
    device_log = DeviceLog(
        user_id=user_id, ip_address=request.remote_addr, user_agent=request.user_agent.string,
        device_type=ua_info['device_type'], browser=ua_info['browser'], os=ua_info['os']
    )
    db.session.add(device_log)
    db.session.commit()

def create_thumbnail(file_path, thumbnail_path, size=(300, 300)):
    try:
        with Image.open(file_path) as img:
            img.thumbnail(size, Image.Resampling.LANCZOS)
            if img.mode in ('RGBA', 'P'):
                img = img.convert('RGB')
            img.save(thumbnail_path, 'JPEG', quality=85)
            return True
    except:
        return False

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
    elif 'word' in mime_type:
        return 'fa-file-word'
    elif 'excel' in mime_type:
        return 'fa-file-excel'
    elif 'powerpoint' in mime_type:
        return 'fa-file-powerpoint'
    else:
        return 'fa-file'

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Please login as admin', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

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
            'id': item.id, 'name': item.name, 'type': item.type,
            'thumbnail_path': item.thumbnail_path, 'size': item.size,
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
    
    return render_template('user_vault.html', logged_in=True, items=items_with_access,
                         folder_id=parent_id, breadcrumb=breadcrumb)

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
    
    download = Download(user_id=user_id, item_id=item_id)
    db.session.add(download)
    db.session.commit()
    
    if item.type == 'folder':
        zip_path = f"storage/temp_{user_id}_{item_id}_{secrets.token_hex(4)}.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(item.file_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, item.file_path)
                    zipf.write(file_path, arcname)
        response = send_file(zip_path, as_attachment=True, download_name=f"{item.name}.zip")
        @response.call_on_close
        def cleanup():
            if os.path.exists(zip_path):
                os.remove(zip_path)
        return response
    else:
        return send_file(item.file_path, as_attachment=True, download_name=item.name)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('user_vault'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        password = request.form.get('password')
        if hashlib.sha256(password.encode()).hexdigest() == ADMIN_PASSWORD_HASH:
            session['is_admin'] = True
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
    
    users = db.session.query(User.id, User.pin, User.created_at, User.is_active,
                           func.count(DeviceLog.id).label('device_count')
    ).outerjoin(DeviceLog).group_by(User.id).order_by(User.created_at.desc()).all()
    
    items = Item.query.order_by(Item.created_at.desc()).all()
    folders = Item.query.filter_by(type='folder').order_by(Item.name).all()
    
    return render_template('admin_dashboard.html', total_users=total_users, total_files=total_files,
                         total_folders=total_folders, total_downloads=total_downloads,
                         users=users, items=items, folders=folders)

@app.route('/admin/create_pin', methods=['POST'])
@admin_required
def create_pin():
    pin = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ0123456789') for _ in range(8))
    user = User(pin=pin, is_active=True)
    db.session.add(user)
    try:
        db.session.commit()
        flash(f'PIN created: {pin}', 'success')
    except:
        db.session.rollback()
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
        folder_path = os.path.join(app.config['UPLOAD_FOLDER'], f"folder_{secrets.token_hex(16)}")
        os.makedirs(folder_path, exist_ok=True)
        thumbnail_path = None
        if picture and picture.filename:
            thumb_filename = f"thumb_{secrets.token_hex(16)}.jpg"
            thumb_full_path = os.path.join(app.config['THUMBNAIL_FOLDER'], thumb_filename)
            picture.save(thumb_full_path)
            thumbnail_path = thumb_full_path
        item = Item(name=name, type='folder', file_path=folder_path, thumbnail_path=thumbnail_path, parent_id=parent_id)
        db.session.add(item)
        db.session.commit()
        flash(f'Folder "{name}" created', 'success')
        
    elif item_type == 'file' and file and file.filename:
        filename = secure_filename(file.filename)
        unique_filename = f"{secrets.token_hex(16)}_{filename}"
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
        mime_type = file.content_type or mimetypes.guess_type(filename)[0]
        item = Item(name=name, type='file', file_path=file_path, thumbnail_path=thumbnail_path,
                   parent_id=parent_id, size=file_size, mime_type=mime_type)
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
        if item.type == 'folder' and os.path.exists(item.file_path):
            shutil.rmtree(item.file_path)
        elif item.type == 'file' and os.path.exists(item.file_path):
            os.remove(item.file_path)
        if item.thumbnail_path and os.path.exists(item.thumbnail_path):
            os.remove(item.thumbnail_path)
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
    UserItemPermission.query.filter_by(user_id=user_id).delete()
    for item_id in restricted_items:
        db.session.add(UserItemPermission(user_id=user_id, item_id=item_id, can_access=False))
    db.session.commit()
    flash('Permissions updated', 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
