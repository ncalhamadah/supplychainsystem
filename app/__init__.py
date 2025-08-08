import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField, FloatField, TextAreaField, SelectField, DateField
from wtforms.validators import DataRequired, Email, Length, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__, static_folder='static', template_folder='templates')
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev')
    db_url = os.getenv('DATABASE_URL', 'sqlite:///instance/dev.db')
    # Render provides a postgres URL starting with postgres:// but SQLAlchemy expects postgresql://
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Ensure instance folder for SQLite
    os.makedirs(os.path.join(app.root_path, '..', 'instance'), exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    with app.app_context():
        db.create_all()

    register_routes(app)
    return app

# -------------------- Models --------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120))
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    channel = db.Column(db.String(100))   # e.g., "Retailer", "Distributor", "Online"
    contact_name = db.Column(db.String(120))
    contact_email = db.Column(db.String(120))
    contact_phone = db.Column(db.String(50))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    flavor = db.Column(db.String(100))
    size_ml = db.Column(db.Integer)
    nicotine_mg = db.Column(db.Integer)

class InventoryLot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_cost = db.Column(db.Float, nullable=False)
    received_date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    product = db.relationship('Product', backref='lots')

class BuyIn(db.Model):  # Sell-in to customers
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Float, nullable=False)  # price to customer
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    customer = db.relationship('Customer', backref='buyins')
    product = db.relationship('Product')

class SellOut(db.Model):  # Reported sell-out from customers
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    customer = db.relationship('Customer', backref='sellouts')
    product = db.relationship('Product')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- Forms --------------------
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember me')

class UserForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    name = StringField('Name')
    password = PasswordField('Password', validators=[Length(min=6)])
    is_admin = BooleanField('Admin')

class CustomerForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    channel = StringField('Channel')
    contact_name = StringField('Contact Name')
    contact_email = StringField('Contact Email')
    contact_phone = StringField('Contact Phone')
    notes = TextAreaField('Notes')

class ProductForm(FlaskForm):
    sku = StringField('SKU', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    flavor = StringField('Flavor')
    size_ml = IntegerField('Size (ml)', validators=[NumberRange(min=0)], default=30)
    nicotine_mg = IntegerField('Nicotine (mg)', validators=[NumberRange(min=0)], default=20)

class InventoryLotForm(FlaskForm):
    product_id = SelectField('Product', coerce=int, validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])
    unit_cost = FloatField('Unit Cost', validators=[DataRequired(), NumberRange(min=0)])
    received_date = DateField('Received Date', format='%Y-%m-%d')

class BuyInForm(FlaskForm):
    customer_id = SelectField('Customer', coerce=int, validators=[DataRequired()])
    product_id = SelectField('Product', coerce=int, validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])
    unit_price = FloatField('Unit Price', validators=[DataRequired(), NumberRange(min=0)])
    date = DateField('Date', format='%Y-%m-%d')

class SellOutForm(FlaskForm):
    customer_id = SelectField('Customer', coerce=int, validators=[DataRequired()])
    product_id = SelectField('Product', coerce=int, validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])
    date = DateField('Date', format='%Y-%m-%d')

# -------------------- Utilities --------------------
def require_admin():
    if not current_user.is_authenticated or not current_user.is_admin:
        flash("Admin access required.", "warning")
        return False
    return True

def cogs_per_unit(product_id):
    # Simple avg cost from inventory lots
    lots = InventoryLot.query.filter_by(product_id=product_id).all()
    if not lots:
        return 0.0
    total_qty = sum(l.quantity for l in lots)
    total_cost = sum(l.quantity * l.unit_cost for l in lots)
    return (total_cost / total_qty) if total_qty else 0.0

def compute_margin(unit_price, product_id):
    cogs = cogs_per_unit(product_id)
    return unit_price - cogs

# -------------------- Routes --------------------
def register_routes(app):
    @app.route('/')
    @login_required
    def index():
        # Simple KPIs
        total_buyin_units = db.session.query(db.func.coalesce(db.func.sum(BuyIn.quantity), 0)).scalar()
        total_sellout_units = db.session.query(db.func.coalesce(db.func.sum(SellOut.quantity), 0)).scalar()
        num_customers = Customer.query.count()
        num_products = Product.query.count()
        # Revenue estimate: sum(price * qty)
        total_revenue = db.session.query(db.func.coalesce(db.func.sum(BuyIn.unit_price * BuyIn.quantity), 0.0)).scalar()
        # Gross margin estimate: sum((price - avg_cost)*qty) -- approximation
        gm = 0.0
        for bi in BuyIn.query.all():
            gm += compute_margin(bi.unit_price, bi.product_id) * bi.quantity

        # Top customers by buy-in units
        top_customers = db.session.query(Customer.name, db.func.sum(BuyIn.quantity).label('qty')) \            .join(BuyIn, Customer.id == BuyIn.customer_id) \            .group_by(Customer.id) \            .order_by(db.desc('qty')).limit(5).all()

        # Top products by buy-in units
        top_products = db.session.query(Product.name, db.func.sum(BuyIn.quantity).label('qty')) \            .join(BuyIn, Product.id == BuyIn.product_id) \            .group_by(Product.id) \            .order_by(db.desc('qty')).limit(5).all()

        return render_template('dashboard.html',
                               total_buyin_units=total_buyin_units,
                               total_sellout_units=total_sellout_units,
                               num_customers=num_customers,
                               num_products=num_products,
                               total_revenue=total_revenue,
                               gross_margin=gm,
                               top_customers=top_customers,
                               top_products=top_products)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data.lower()).first()
            if user and user.check_password(form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('index'))
            flash('Invalid credentials', 'danger')
        return render_template('login.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))

    # ---------- Users (Admin) ----------
    @app.route('/admin/users')
    @login_required
    def users():
        if not require_admin():
            return redirect(url_for('index'))
        return render_template('users.html', users=User.query.all())

    @app.route('/admin/users/new', methods=['GET','POST'])
    @login_required
    def new_user():
        if not require_admin():
            return redirect(url_for('index'))
        form = UserForm()
        if form.validate_on_submit():
            u = User(email=form.email.data.lower(), name=form.name.data, is_admin=form.is_admin.data)
            if form.password.data:
                u.set_password(form.password.data)
            else:
                u.set_password('ChangeMe123!')
            db.session.add(u)
            db.session.commit()
            flash('User created', 'success')
            return redirect(url_for('users'))
        return render_template('user_form.html', form=form, title='New User')

    @app.route('/admin/users/<int:user_id>/edit', methods=['GET','POST'])
    @login_required
    def edit_user(user_id):
        if not require_admin():
            return redirect(url_for('index'))
        u = User.query.get_or_404(user_id)
        form = UserForm(obj=u)
        if form.validate_on_submit():
            u.email = form.email.data.lower()
            u.name = form.name.data
            u.is_admin = form.is_admin.data
            if form.password.data:
                u.set_password(form.password.data)
            db.session.commit()
            flash('User updated', 'success')
            return redirect(url_for('users'))
        return render_template('user_form.html', form=form, title='Edit User')

    @app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
    @login_required
    def delete_user(user_id):
        if not require_admin():
            return redirect(url_for('index'))
        u = User.query.get_or_404(user_id)
        if u.id == current_user.id:
            flash('You cannot delete yourself.', 'warning')
        else:
            db.session.delete(u)
            db.session.commit()
            flash('User deleted', 'success')
        return redirect(url_for('users'))

    # ---------- CRM ----------
    @app.route('/crm/customers')
    @login_required
    def customers():
        return render_template('customers.html', customers=Customer.query.order_by(Customer.created_at.desc()).all())

    @app.route('/crm/customers/new', methods=['GET','POST'])
    @login_required
    def new_customer():
        form = CustomerForm()
        if form.validate_on_submit():
            c = Customer(**form.data)
            db.session.add(c)
            db.session.commit()
            flash('Customer created', 'success')
            return redirect(url_for('customers'))
        return render_template('customer_form.html', form=form, title='New Customer')

    @app.route('/crm/customers/<int:cid>/edit', methods=['GET','POST'])
    @login_required
    def edit_customer(cid):
        c = Customer.query.get_or_404(cid)
        form = CustomerForm(obj=c)
        if form.validate_on_submit():
            form.populate_obj(c)
            db.session.commit()
            flash('Customer updated', 'success')
            return redirect(url_for('customers'))
        return render_template('customer_form.html', form=form, title='Edit Customer')

    @app.route('/crm/customers/<int:cid>/delete', methods=['POST'])
    @login_required
    def delete_customer(cid):
        c = Customer.query.get_or_404(cid)
        db.session.delete(c)
        db.session.commit()
        flash('Customer deleted', 'success')
        return redirect(url_for('customers'))

    # ---------- Products ----------
    @app.route('/products')
    @login_required
    def products():
        return render_template('products.html', products=Product.query.all())

    @app.route('/products/new', methods=['GET','POST'])
    @login_required
    def new_product():
        form = ProductForm()
        if form.validate_on_submit():
            p = Product(**form.data)
            db.session.add(p)
            db.session.commit()
            flash('Product created', 'success')
            return redirect(url_for('products'))
        return render_template('product_form.html', form=form, title='New Product')

    @app.route('/products/<int:pid>/edit', methods=['GET','POST'])
    @login_required
    def edit_product(pid):
        p = Product.query.get_or_404(pid)
        form = ProductForm(obj=p)
        if form.validate_on_submit():
            form.populate_obj(p)
            db.session.commit()
            flash('Product updated', 'success')
            return redirect(url_for('products'))
        return render_template('product_form.html', form=form, title='Edit Product')

    @app.route('/products/<int:pid>/delete', methods=['POST'])
    @login_required
    def delete_product(pid):
        p = Product.query.get_or_404(pid)
        db.session.delete(p)
        db.session.commit()
        flash('Product deleted', 'success')
        return redirect(url_for('products'))

    # ---------- Inventory ----------
    @app.route('/inventory')
    @login_required
    def inventory():
        lots = InventoryLot.query.order_by(InventoryLot.received_date.desc()).all()
        return render_template('inventory.html', lots=lots)

    @app.route('/inventory/new', methods=['GET','POST'])
    @login_required
    def new_lot():
        form = InventoryLotForm()
        form.product_id.choices = [(p.id, f"{p.sku} - {p.name}") for p in Product.query.all()]
        if form.validate_on_submit():
            lot = InventoryLot(
                product_id=form.product_id.data,
                quantity=form.quantity.data,
                unit_cost=form.unit_cost.data,
                received_date=form.received_date.data or datetime.utcnow().date()
            )
            db.session.add(lot)
            db.session.commit()
            flash('Inventory lot added', 'success')
            return redirect(url_for('inventory'))
        return render_template('inventory_form.html', form=form, title='New Inventory Lot')

    # ---------- Buy-In ----------
    @app.route('/buyins')
    @login_required
    def buyins():
        items = BuyIn.query.order_by(BuyIn.date.desc()).all()
        return render_template('buyins.html', items=items)

    @app.route('/buyins/new', methods=['GET','POST'])
    @login_required
    def new_buyin():
        form = BuyInForm()
        form.customer_id.choices = [(c.id, c.name) for c in Customer.query.all()]
        form.product_id.choices = [(p.id, f"{p.sku} - {p.name}") for p in Product.query.all()]
        if form.validate_on_submit():
            bi = BuyIn(
                customer_id=form.customer_id.data,
                product_id=form.product_id.data,
                quantity=form.quantity.data,
                unit_price=form.unit_price.data,
                date=form.date.data or datetime.utcnow().date()
            )
            db.session.add(bi)
            db.session.commit()
            flash('Buy-in recorded', 'success')
            return redirect(url_for('buyins'))
        return render_template('buyin_form.html', form=form, title='New Buy-In')

    # ---------- Sell-Out ----------
    @app.route('/sellouts')
    @login_required
    def sellouts():
        items = SellOut.query.order_by(SellOut.date.desc()).all()
        return render_template('sellouts.html', items=items)

    @app.route('/sellouts/new', methods=['GET','POST'])
    @login_required
    def new_sellout():
        form = SellOutForm()
        form.customer_id.choices = [(c.id, c.name) for c in Customer.query.all()]
        form.product_id.choices = [(p.id, f"{p.sku} - {p.name}") for p in Product.query.all()]
        if form.validate_on_submit():
            so = SellOut(
                customer_id=form.customer_id.data,
                product_id=form.product_id.data,
                quantity=form.quantity.data,
                date=form.date.data or datetime.utcnow().date()
            )
            db.session.add(so)
            db.session.commit()
            flash('Sell-out recorded', 'success')
            return redirect(url_for('sellouts'))
        return render_template('sellout_form.html', form=form, title='New Sell-Out')

# -------------------- Seed & Admin helpers --------------------
def seed_data():
    # Basic seed for testing
    if not Product.query.first():
        p1 = Product(sku="VASH-CHERRY-30-20", name="VASH Cherry", flavor="Cherry", size_ml=30, nicotine_mg=20)
        p2 = Product(sku="VASH-MINT-30-20", name="VASH Mint", flavor="Mint", size_ml=30, nicotine_mg=20)
        db.session.add_all([p1, p2])
    if not Customer.query.first():
        c1 = Customer(name="Lulu Hypermarket", channel="Retailer", contact_name="Buyer 1")
        c2 = Customer(name="Aljazeera Supermarket", channel="Retailer", contact_name="Buyer 2")
        db.session.add_all([c1, c2])
    db.session.commit()

def create_admin():
    email = os.getenv('ADMIN_EMAIL', 'admin@vash.local').lower()
    pwd = os.getenv('ADMIN_PASSWORD', 'ChangeMe123!')
    u = User.query.filter_by(email=email).first()
    if not u:
        u = User(email=email, name="Admin", is_admin=True)
    u.set_password(pwd)
    u.is_admin = True
    db.session.add(u)
    db.session.commit()
