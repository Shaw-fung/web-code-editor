from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, EmailField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from passlib.hash import pbkdf2_sha256
import os
from datetime import datetime, timedelta

# 初始化Flask应用
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///editor.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化数据库
db = SQLAlchemy(app)

# 初始化CSRF保护
csrf = CSRFProtect(app)

# 初始化登录管理器
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 用户模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    files = db.relationship('File', backref='owner', lazy=True)

# 文件模型
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    language = db.Column(db.String(50), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    last_saved = db.Column(db.DateTime, default=datetime.utcnow)
    order = db.Column(db.Integer, default=0)  # 用于保存文件顺序
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

# 配置模型
class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=False)

# 操作日志模型
class OperationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    operator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    operator = db.relationship('User', foreign_keys=[operator_id])
    target_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    target_user = db.relationship('User', foreign_keys=[target_user_id])
    operation_type = db.Column(db.String(50), nullable=False)  # toggle_active, change_password, toggle_role
    operation_result = db.Column(db.String(50), nullable=False)  # success, failed
    operation_time = db.Column(db.DateTime, default=datetime.utcnow)
    remark = db.Column(db.Text, nullable=True)

# 找回密码表单
class ResetPasswordForm(FlaskForm):
    email = EmailField('邮箱', validators=[DataRequired(), Email()])
    submit = SubmitField('发送重置链接')

class NewPasswordForm(FlaskForm):
    password = PasswordField('新密码', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('确认新密码', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('重置密码')

# 注册表单
class RegistrationForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(min=2, max=20)])
    email = EmailField('邮箱', validators=[DataRequired(), Email()])
    password = PasswordField('密码', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('确认密码', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('注册')

# 登录表单
class LoginForm(FlaskForm):
    email = EmailField('邮箱', validators=[DataRequired(), Email()])
    password = PasswordField('密码', validators=[DataRequired()])
    submit = SubmitField('登录')

# 加载用户
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 管理员装饰器
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'success': False, 'message': '需要管理员权限'})
        return f(*args, **kwargs)
    return decorated_function

# 记录操作日志
def log_operation(operator_id, target_user_id, operation_type, operation_result, remark=None):
    log = OperationLog(
        operator_id=operator_id,
        target_user_id=target_user_id,
        operation_type=operation_type,
        operation_result=operation_result,
        remark=remark
    )
    db.session.add(log)
    db.session.commit()

# 获取配置项
def get_config(key, default=None):
    config = Config.query.filter_by(key=key).first()
    if config:
        if config.value.lower() == 'true':
            return True
        elif config.value.lower() == 'false':
            return False
        return config.value
    return default

# 设置配置项
def set_config(key, value):
    config = Config.query.filter_by(key=key).first()
    if config:
        config.value = str(value)
    else:
        config = Config(key=key, value=str(value))
        db.session.add(config)
    db.session.commit()

# 主页路由
@app.route('/')
def home():
    return render_template('index.html')

# 注册路由
@app.route('/api/config/registration', methods=['GET'])
@csrf.exempt
def get_registration_config():
    allow_registration = get_config('allow_registration', True)
    return jsonify({'allow_registration': allow_registration})

@app.route('/register', methods=['GET', 'POST'])
@csrf.exempt
def register():
    # 检查是否开放注册
    allow_registration = get_config('allow_registration', True)
    if not allow_registration:
        return jsonify({'success': False, 'message': '注册已关闭'})
    
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        
        # 验证用户名是否已存在
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': '用户名已存在'})
        
        # 验证邮箱是否已存在
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': '邮箱已存在'})
        
        # 验证密码
        if len(password) < 6:
            return jsonify({'success': False, 'message': '密码长度至少为6位'})
        
        if password != confirm_password:
            return jsonify({'success': False, 'message': '两次输入的密码不一致'})
        
        # 创建用户
        hashed_password = pbkdf2_sha256.hash(password)
        new_user = User(
            username=username,
            email=email,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'success': True, 'message': '注册成功'})
    
    return render_template('index.html')

# 登录路由
@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and user.is_active and pbkdf2_sha256.verify(password, user.password):
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)
            return jsonify({'success': True, 'message': '登录成功', 'user': {'id': user.id, 'username': user.username, 'is_admin': user.is_admin}})
        return jsonify({'success': False, 'message': '邮箱或密码错误'})
    return render_template('index.html')

# 找回密码请求路由
@app.route('/api/reset-password/request', methods=['POST'])
@csrf.exempt
def request_reset_password():
    data = request.get_json()
    email = data.get('email')
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'success': False, 'message': '邮箱不存在'})
    
    # 这里简化处理，实际应该发送包含重置链接的邮件
    # 为了演示，直接返回成功消息
    return jsonify({'success': True, 'message': '重置密码链接已发送到您的邮箱'})

# 重置密码路由
@app.route('/api/reset-password', methods=['POST'])
@csrf.exempt
def reset_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    
    if new_password != confirm_password:
        return jsonify({'success': False, 'message': '两次输入的密码不一致'})
    
    if len(new_password) < 6:
        return jsonify({'success': False, 'message': '密码长度至少为6位'})
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'success': False, 'message': '用户不存在'})
    
    # 更新密码
    user.password = pbkdf2_sha256.hash(new_password)
    db.session.commit()
    
    return jsonify({'success': True, 'message': '密码重置成功'})

# 登出路由
@app.route('/logout')
@login_required
@csrf.exempt
def logout():
    logout_user()
    return jsonify({'success': True, 'message': '登出成功'})

# 获取用户文件
@app.route('/api/files')
@login_required
@csrf.exempt
def get_files():
    files = File.query.filter_by(user_id=current_user.id).order_by(File.order).all()
    return jsonify([{
        'id': file.id,
        'filename': file.filename,
        'content': file.content,
        'language': file.language,
        'last_saved': (file.last_saved + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S'),
        'order': file.order
    } for file in files])

# 保存文件
@app.route('/api/files/save', methods=['POST'])
@csrf.exempt
def save_file():
    data = request.get_json()
    file_id = data.get('id')
    filename = data.get('filename')
    content = data.get('content')
    language = data.get('language')
    
    if current_user.is_authenticated:
        # 保存到数据库，优先使用ID作为唯一标识
        file = None
        
        # 尝试根据ID查找现有文件（仅当ID是有效整数时）
        if file_id:
            try:
                # 尝试将ID转换为整数
                file_id_int = int(file_id)
                file = File.query.filter_by(id=file_id_int, user_id=current_user.id).first()
            except (ValueError, TypeError):
                # 如果ID不是有效整数，视为临时ID，创建新文件
                file = None
        
        if file:
            # 更新现有文件
            file.filename = filename  # 更新文件名（如果有变化）
            file.content = content
            file.language = language
            file.last_saved = datetime.utcnow()
        else:
            # 创建新文件
            file = File(
                filename=filename,
                content=content,
                language=language,
                user_id=current_user.id
            )
            db.session.add(file)
        
        db.session.commit()
        return jsonify({'success': True, 'message': '文件已保存', 'id': file.id})
    else:
        # 游客模式，不保存到数据库
        return jsonify({'success': False, 'message': '游客模式无法保存文件'})

# 删除文件
@app.route('/api/files/delete', methods=['POST'])
@login_required
@csrf.exempt
def delete_file():
    data = request.get_json()
    file_id = data.get('file_id')
    
    try:
        file = File.query.filter_by(id=file_id, user_id=current_user.id).first()
        if file:
            db.session.delete(file)  # 直接删除记录，而不是标记为非活动
            db.session.commit()
            return jsonify({'success': True, 'message': '文件已删除'})
        return jsonify({'success': False, 'message': '文件不存在'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'删除文件失败: {str(e)}'})

# 更新文件名
@app.route('/api/files/update-name', methods=['POST'])
@login_required
@csrf.exempt
def update_file_name():
    data = request.get_json()
    file_id = data.get('file_id')
    new_filename = data.get('new_filename')
    
    file = File.query.filter_by(id=file_id, user_id=current_user.id).first()
    if file:
        file.filename = new_filename
        db.session.commit()
        return jsonify({'success': True, 'message': '文件名已更新'})
    return jsonify({'success': False, 'message': '文件不存在'})

# 保存文件顺序
@app.route('/api/files/save-order', methods=['POST'])
@login_required
@csrf.exempt
def save_file_order():
    data = request.get_json()
    file_orders = data.get('file_orders')
    
    if not file_orders:
        return jsonify({'success': False, 'message': '无效的文件顺序数据'})
    
    try:
        for order_data in file_orders:
            file_id = order_data.get('id')
            new_order = order_data.get('order')
            if file_id and new_order is not None:
                file = File.query.filter_by(id=file_id, user_id=current_user.id).first()
                if file:
                    file.order = new_order
        db.session.commit()
        return jsonify({'success': True, 'message': '文件顺序已保存'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'保存文件顺序失败: {str(e)}'})

# 个人中心路由
@app.route('/personal_center')
@login_required
def personal_center():
    return render_template('personal_center.html')

# 管理后台路由
@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

# ========== 管理员 API ==========

# 获取所有用户列表
@app.route('/api/admin/users', methods=['GET'])
@admin_required
@csrf.exempt
def get_users():
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'is_active': user.is_active,
        'created_at': (user.created_at + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S'),
        'last_login': (user.last_login + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S') if user.last_login else None,
        'file_count': len(user.files)
    } for user in users])

# 停用/启用用户
@app.route('/api/admin/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
@csrf.exempt
def toggle_user(user_id):
    user = User.query.get(user_id)
    if not user:
        log_operation(current_user.id, user_id, 'toggle_active', 'failed', '用户不存在')
        return jsonify({'success': False, 'message': '用户不存在'})
    
    # 不允许停用自己
    if user.id == current_user.id:
        log_operation(current_user.id, user_id, 'toggle_active', 'failed', '尝试停用自己')
        return jsonify({'success': False, 'message': '不能停用自己'})
    
    old_status = user.is_active
    user.is_active = not user.is_active
    new_status = user.is_active
    db.session.commit()
    
    log_operation(
        current_user.id, 
        user_id, 
        'toggle_active', 
        'success', 
        f'用户状态从{"活跃" if old_status else "停用"}切换为{"活跃" if new_status else "停用"}'
    )
    return jsonify({'success': True, 'message': '用户状态已更新'})

# 删除用户
@app.route('/api/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
@csrf.exempt
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': '用户不存在'})
    
    # 不允许删除自己
    if user.id == current_user.id:
        return jsonify({'success': False, 'message': '不能删除自己'})
    
    # 删除用户的所有文件
    for file in user.files:
        db.session.delete(file)
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True, 'message': '用户已删除'})

# 修改用户密码
@app.route('/api/admin/users/<int:user_id>/password', methods=['POST'])
@admin_required
@csrf.exempt
def change_user_password(user_id):
    user = User.query.get(user_id)
    if not user:
        log_operation(current_user.id, user_id, 'change_password', 'failed', '用户不存在')
        return jsonify({'success': False, 'message': '用户不存在'})
    
    data = request.get_json()
    new_password = data.get('new_password')
    
    if len(new_password) < 6:
        log_operation(current_user.id, user_id, 'change_password', 'failed', '密码长度不足')
        return jsonify({'success': False, 'message': '密码长度至少为6位'})
    
    # 更新密码
    user.password = pbkdf2_sha256.hash(new_password)
    db.session.commit()
    
    # 记录操作日志
    log_operation(current_user.id, user_id, 'change_password', 'success', '成功修改用户密码')
    return jsonify({'success': True, 'message': '用户密码已更新'})

# 切换用户角色（管理员/普通用户）
@app.route('/api/admin/users/<int:user_id>/role', methods=['POST'])
@admin_required
@csrf.exempt
def toggle_user_role(user_id):
    user = User.query.get(user_id)
    if not user:
        log_operation(current_user.id, user_id, 'toggle_role', 'failed', '用户不存在')
        return jsonify({'success': False, 'message': '用户不存在'})
    
    # 不允许取消自己的管理员权限
    if user.id == current_user.id:
        log_operation(current_user.id, user_id, 'toggle_role', 'failed', '尝试取消自己的管理员权限')
        return jsonify({'success': False, 'message': '不能取消自己的管理员权限'})
    
    old_role = user.is_admin
    user.is_admin = not user.is_admin
    new_role = user.is_admin
    db.session.commit()
    
    log_operation(
        current_user.id, 
        user_id, 
        'toggle_role', 
        'success', 
        f'用户角色从{"管理员" if old_role else "普通用户"}切换为{"管理员" if new_role else "普通用户"}'
    )
    return jsonify({'success': True, 'message': '用户角色已更新'})

# 获取注册开关状态
@app.route('/api/admin/registration-status', methods=['GET'])
@admin_required
@csrf.exempt
def get_registration_status():
    status = get_config('allow_registration', True)
    return jsonify({'success': True, 'status': status})

# 设置注册开关状态
@app.route('/api/admin/registration-status', methods=['POST'])
@admin_required
@csrf.exempt
def set_registration_status():
    data = request.get_json()
    status = data.get('status')
    
    set_config('allow_registration', status)
    return jsonify({'success': True, 'message': '注册状态已更新'})

# 获取当前用户信息
@app.route('/api/user', methods=['GET'])
@csrf.exempt
def get_current_user():
    if current_user.is_authenticated:
        return jsonify({
            'success': True,
            'user': {
                'id': current_user.id,
                'username': current_user.username,
                'email': current_user.email,
                'is_admin': current_user.is_admin
            }
        })
    return jsonify({'success': False, 'message': '未登录'})

# 更新用户个人资料
@app.route('/api/user/profile', methods=['PUT'])
@login_required
@csrf.exempt
def update_profile():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    # 验证用户名
    if not username or len(username) < 2 or len(username) > 20:
        return jsonify({'success': False, 'message': '用户名长度必须在2-20个字符之间'})
    
    # 验证邮箱
    if not email or not '@' in email:
        return jsonify({'success': False, 'message': '请输入有效的邮箱地址'})
    
    # 检查用户名是否已被其他用户使用
    existing_user = User.query.filter(User.username == username, User.id != current_user.id).first()
    if existing_user:
        return jsonify({'success': False, 'message': '用户名已被使用'})
    
    # 检查邮箱是否已被其他用户使用
    existing_email = User.query.filter(User.email == email, User.id != current_user.id).first()
    if existing_email:
        return jsonify({'success': False, 'message': '邮箱已被使用'})
    
    # 如果要修改密码
    if new_password:
        if not current_password:
            return jsonify({'success': False, 'message': '修改密码需要输入当前密码'})
        
        # 验证当前密码
        if not pbkdf2_sha256.verify(current_password, current_user.password):
            return jsonify({'success': False, 'message': '当前密码错误'})
        
        # 验证新密码
        if len(new_password) < 6:
            return jsonify({'success': False, 'message': '新密码长度至少为6位'})
        
        # 更新密码
        current_user.password = pbkdf2_sha256.hash(new_password)
    
    # 更新用户名和邮箱
    current_user.username = username
    current_user.email = email
    
    try:
        db.session.commit()
        return jsonify({
            'success': True,
            'user': {
                'id': current_user.id,
                'username': current_user.username,
                'email': current_user.email,
                'is_admin': current_user.is_admin
            },
            'message': '个人信息更新成功'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': '更新失败，请稍后重试'})

# 主程序入口
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # 创建默认管理员用户
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                password=pbkdf2_sha256.hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
        
        # 创建默认配置项
        if not get_config('allow_registration'):
            set_config('allow_registration', True)
    
    app.run(debug=True, host='0.0.0.0', port=5002)
