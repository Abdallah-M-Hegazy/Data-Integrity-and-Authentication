from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime
import pyotp
import qrcode
import io
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/di_task1'
db = SQLAlchemy(app)
SECRET_KEY = "abdallah"

# Database Models
class Users(db.Model):
    __tablename__ = 'users'
    uid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    twofa_secret = db.Column(db.String(256), nullable=False)
    
    
class Products(db.Model):
    __tablename__ = 'products'
    pid = db.Column(db.Integer, primary_key=True)  
    name = db.Column(db.String(80), nullable=False)  
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10,2), nullable=False)  
    stock = db.Column(db.Integer, nullable=False)  
    created_at = db.Column(db.TIMESTAMP, nullable=True)

# Create the database tables
with app.app_context():
    db.create_all()


# Authentication Middleware
def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        try:
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({'error': 'Invalid or expired token'}), 401
        return f(*args, **kwargs)
    return decorator

# User Registration
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    hashed_password = generate_password_hash(data['password'])
    twofa_secret = pyotp.random_base32()
    
    new_user = Users(username=data['username'], password=hashed_password, twofa_secret=twofa_secret)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User registered', '2FA_secret': twofa_secret}), 201

# Generate QR Code for Google Authenticator
@app.route('/generate_qr/<int:uid>', methods=['GET'])
def generate_qr(uid):
    user = Users.query.filter_by(uid=uid).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    otp_uri = pyotp.totp.TOTP(user.twofa_secret).provisioning_uri(uid, issuer_name="FlaskApp")
    img = qrcode.make(otp_uri)
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    return img_io.read(), {'Content-Type': 'image/png'}

# User Login with 2FA
@app.route('/login', methods=['POST'])
def login():
    auth = request.json
    if not auth or 'username' not in auth or 'password' not in auth or 'otp' not in auth:
        return jsonify({'error': 'Missing fields'}), 400

    user = Users.query.filter_by(username=auth['username']).first()
    if not user or not check_password_hash(user.password, auth['password']):
        return jsonify({'error': 'Invalid username or password'}), 401
    
    totp = pyotp.TOTP(user.twofa_secret)
    if not totp.verify(auth['otp']):
        return jsonify({'error': 'Invalid 2FA code'}), 401
    
    token = jwt.encode({'user': user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)}, SECRET_KEY, algorithm="HS256")
    return jsonify({'token': token})

# CRUD Operations for Products
@app.route('/products', methods=['POST'])
@token_required
def create_product():
    data = request.json
    new_product = Products(name=data['name'], description=data.get('description', ''), price=data['price'], stock=data['stock'])
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product added'}), 201

@app.route('/products', methods=['GET'])
@token_required
def get_products():
    products = Products.query.all()
    return jsonify([{'id': p.pid, 'name': p.name, 'description': p.description, 'price': float(p.price), 'stock': p.stock} for p in products])

@app.route('/products/<int:pid>', methods=['GET'])
@token_required
def get_product(pid):
    product = Products.query.get(pid)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    return jsonify([{'id': product.pid, 'name': product.name, 'description': product.description, 'price': float(product.price), 'stock': product.stock}])

@app.route('/products/<int:id>', methods=['PUT'])
@token_required
def update_product(id):
    product = Products.query.get(id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    data = request.json

    # Update only the fields that are provided in the request
    if 'name' in data:
        product.name = data['name']
    if 'description' in data:
        product.description = data['description']
    if 'price' in data:
        product.price = data['price']
    if 'stock' in data:
        product.stock = data['stock']

    db.session.commit()
    return jsonify({'message': 'Product updated'})

@app.route('/products/<int:id>', methods=['DELETE'])
@token_required
def delete_product(id):
    product = Products.query.get(id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted'})

if __name__ == '__main__':
    app.run(debug=True)