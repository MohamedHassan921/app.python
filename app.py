from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
import os
import logging
from marshmallow import Schema, fields, ValidationError

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration (replace with your MySQL credentials)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+mysqlconnector://root:@localhost/security_mgmt_db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# JWT configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "your_secret_key")  # Use environment variable for production
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=10)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# 🌟 Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Product(db.Model):
    pid = db.Column(db.Integer, primary_key=True)
    pname = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())

# 🌟 Input Validation Schemas (using Marshmallow)
class UserSchema(Schema):
    name = fields.Str(required=True)
    username = fields.Str(required=True)
    password = fields.Str(required=True)

class ProductSchema(Schema):
    pname = fields.Str(required=True)
    description = fields.Str()
    price = fields.Float(required=True)
    stock = fields.Int(required=True)

# Create database tables
with app.app_context():
    db.create_all()

# 🌟 Helper Functions
def validate_input(data, schema):
    try:
        return schema().load(data)
    except ValidationError as err:
        raise ValueError(err.messages)

# 🌟 Home Route
@app.route("/", methods=["GET"])
def home():
    return "<h1>Hello, Flask is working!</h1><p>API is running successfully.</p>"

# 🌟 User Signup
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = validate_input(request.json, UserSchema)
        hashed_password = bcrypt.generate_password_hash(data['password']).decode("utf-8")
        new_user = User(name=data['name'], username=data['username'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"New user registered: {data['username']}")
        return jsonify({"message": "User registered successfully"}), 201
    except ValueError as e:
        logger.error(f"Validation error during signup: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error during signup: {e}")
        return jsonify({"error": "An error occurred during registration"}), 500

# 🌟 User Login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = validate_input(request.json, UserSchema)
        user = User.query.filter_by(username=data['username']).first()
        if user and bcrypt.check_password_hash(user.password, data['password']):
            access_token = create_access_token(identity=user.id)
            logger.info(f"User logged in: {data['username']}")
            return jsonify({"token": access_token}), 200
        return jsonify({"message": "Invalid credentials"}), 401
    except ValueError as e:
        logger.error(f"Validation error during login: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({"error": "An error occurred during login"}), 500

# 🌟 Update User (Protected by JWT)
@app.route('/users/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    try:
        user = User.query.get_or_404(id)
        data = request.json
        if "name" in data:
            user.name = data["name"]
        if "username" in data:
            user.username = data["username"]
        db.session.commit()
        logger.info(f"User updated: {user.username}")
        return jsonify({"message": "User updated successfully"}), 200
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        return jsonify({"error": "An error occurred while updating the user"}), 500

# 🌟 Add Product (Protected by JWT)
@app.route('/products', methods=['POST'])
@jwt_required()
def add_product():
    try:
        data = validate_input(request.json, ProductSchema)
        new_product = Product(
            pname=data["pname"],
            description=data.get("description", ""),
            price=data["price"],
            stock=data["stock"]
        )
        db.session.add(new_product)
        db.session.commit()
        logger.info(f"New product added: {data['pname']}")
        return jsonify({"message": "Product added successfully"}), 201
    except ValueError as e:
        logger.error(f"Validation error adding product: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error adding product: {e}")
        return jsonify({"error": "An error occurred while adding the product"}), 500

# 🌟 Get All Products
@app.route('/products', methods=['GET'])
def get_products():
    try:
        products = Product.query.all()
        product_list = [{"pid": p.pid, "pname": p.pname, "description": p.description, "price": p.price, "stock": p.stock} for p in products]
        return jsonify({"products": product_list})
    except Exception as e:
        logger.error(f"Error fetching products: {e}")
        return jsonify({"error": "An error occurred while fetching products"}), 500

# 🌟 Get Single Product
@app.route('/products/<int:pid>', methods=['GET'])
def get_product(pid):
    try:
        product = Product.query.get_or_404(pid)
        return jsonify({"pid": product.pid, "pname": product.pname, "description": product.description, "price": product.price, "stock": product.stock})
    except Exception as e:
        logger.error(f"Error fetching product: {e}")
        return jsonify({"error": "Product not found"}), 404

# 🌟 Update Product (Protected by JWT)
@app.route('/products/<int:pid>', methods=['PUT'])
@jwt_required()
def update_product(pid):
    try:
        product = Product.query.get_or_404(pid)
        data = request.json
        product.pname = data.get("pname", product.pname)
        product.description = data.get("description", product.description)
        product.price = data.get("price", product.price)
        product.stock = data.get("stock", product.stock)
        db.session.commit()
        logger.info(f"Product updated: {product.pname}")
        return jsonify({"message": "Product updated successfully"}), 200
    except Exception as e:
        logger.error(f"Error updating product: {e}")
        return jsonify({"error": "An error occurred while updating the product"}), 500

# 🌟 Delete Product (Protected by JWT)
@app.route('/products/<int:pid>', methods=['DELETE'])
@jwt_required()
def delete_product(pid):
    try:
        product = Product.query.get_or_404(pid)
        db.session.delete(product)
        db.session.commit()
        logger.info(f"Product deleted: {product.pname}")
        return jsonify({"message": "Product deleted successfully"}), 200
    except Exception as e:
        logger.error(f"Error deleting product: {e}")
        return jsonify({"error": "An error occurred while deleting the product"}), 500

# ✅ Run the Application
if __name__ == '__main__':
    app.run(debug=True)