from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import datetime
import click
import hashlib

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.urandom(24)
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable = False)
    role = db.Column(db.String(10), nullable = False)

class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    condition = db.Column(db.String(20), nullable=False)
    date_added = db.Column(db.DateTime, nullable=False)

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('inventory.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime)

class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    supplier = db.Column(db.String(200))
    quantity = db.Column(db.Integer)

class Request(db.Model):
     id = db.Column(db.Integer, primary_key=True)
     user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
     item_id = db.Column(db.Integer, db.ForeignKey('inventory.id'))
     quantity = db.Column(db.Integer, nullable = False)
     status = db.Column(db.String(20), default = "pending", nullable = False)
     request_time = db.Column(db.DateTime, nullable = False)

def hash_password(password):
    salt = os.urandom(16)
    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return f"{salt.hex()}${hashed_password}"

def check_password(hashed_password, password):
      salt, hash_pw = hashed_password.split("$")
      salted_password = bytes.fromhex(salt) + password.encode('utf-8')
      hashed_password_input = hashlib.sha256(salted_password).hexdigest()
      return hash_pw == hashed_password_input

@click.command("create_db")
def create_db():
    db.create_all()
    click.echo("Database Created")

app.cli.add_command(create_db)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        hashed_password = hash_password(password)
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', error = "")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password(user.password, password):
            session['username'] = username
            session['role'] = user.role
            session['user_id'] = user.id
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            return render_template('login.html', error="Invalid username or password")
    return render_template('login.html', error="", register_link = url_for('register'))




@app.route('/admin', methods=['GET'])
def admin_dashboard():
     if 'username' in session and session['role'] == 'admin':
       return render_template('admin_dashboard.html')
     else:
        return "Unauthorized", 401

@app.route('/admin/inventory', methods=['GET','POST'])
def admin_inventory():
   if 'username' in session and session['role'] == 'admin':
        if request.method == 'POST':
            name = request.form['name']
            quantity = int(request.form['quantity'])
            condition = request.form['condition']
            new_item = Inventory(name = name, quantity = quantity, condition = condition, date_added = datetime.now())
            db.session.add(new_item)
            db.session.commit()
            return redirect(url_for('admin_inventory'))
        inventory_items = Inventory.query.all()
        return render_template('admin_inventory.html', inventory_items=inventory_items)
   else:
        return "Unauthorized", 401

@app.route('/admin/inventory/<int:item_id>/edit', methods=['GET','POST'])
def admin_edit_inventory(item_id):
    if 'username' in session and session['role'] == 'admin':
        item = Inventory.query.get(item_id)
        if request.method == 'POST':
             item.name = request.form['name']
             item.quantity = int(request.form['quantity'])
             item.condition = request.form['condition']
             db.session.commit()
             return redirect(url_for('admin_inventory'))
        return render_template('admin_edit_inventory.html', item = item)
    else:
        return "Unauthorized", 401
@app.route('/admin/inventory/<int:item_id>/delete')
def admin_delete_inventory(item_id):
    if 'username' in session and session['role'] == 'admin':
      item = Inventory.query.get(item_id)
      db.session.delete(item)
      db.session.commit()
      return redirect(url_for('admin_inventory'))
    else:
        return "Unauthorized", 401

@app.route('/admin/assignments', methods=['GET','POST'])
def admin_assignments():
    if 'username' in session and session['role'] == 'admin':
        if request.method == 'POST':
            item_id = int(request.form['item_id'])
            user_id = int(request.form['user_id'])
            new_assignment = Assignment(item_id = item_id, user_id = user_id, start_date = datetime.now() )
            db.session.add(new_assignment)
            db.session.commit()
            return redirect(url_for('admin_assignments'))
        assignments=Assignment.query.all()
        users = User.query.all()
        items = Inventory.query.all()
        return render_template('admin_assignments.html', assignments=assignments, users=users, items = items)
    else:
         return "Unauthorized", 401

@app.route('/admin/purchases', methods=['GET','POST'])
def admin_purchases():
    if 'username' in session and session['role'] == 'admin':
        if request.method == 'POST':
            name = request.form['name']
            price = float(request.form['price'])
            supplier = request.form['supplier']
            quantity = int(request.form['quantity'])
            new_purchase = Purchase(name = name, price = price, supplier = supplier, quantity = quantity)
            db.session.add(new_purchase)
            db.session.commit()
            return redirect(url_for('admin_purchases'))
        purchases = Purchase.query.all()
        return render_template('admin_purchases.html', purchases = purchases)
    else:
         return "Unauthorized", 401

@app.route('/admin/reports', methods=['GET'])
def admin_reports():
    if 'username' in session and session['role'] == 'admin':
        inventory = Inventory.query.all()
        assignments = Assignment.query.all()
        return render_template('admin_reports.html', inventory=inventory, assignments=assignments )
    else:
        return "Unauthorized", 401

@app.route('/user', methods=['GET'])
def user_dashboard():
    if 'username' in session and session['role'] == 'user':
       return render_template('user_dashboard.html')
    else:
       return "Unauthorized", 401


@app.route('/user/inventory', methods=['GET', 'POST'])
def user_inventory():
      if 'username' in session and session['role'] == 'user':
          inventory_items = Inventory.query.all()
          return render_template('user_inventory.html', inventory_items = inventory_items)
      else:
          return "Unauthorized", 401

@app.route('/user/request', methods=['GET', 'POST'])
def user_request():
       if 'username' in session and session['role'] == 'user':
           if request.method == 'POST':
              item_id = int(request.form['item_id'])
              quantity = int(request.form['quantity'])
              user_id = session.get('user_id')
              new_request = Request(item_id = item_id, user_id = user_id, quantity = quantity, request_time = datetime.now())
              db.session.add(new_request)
              db.session.commit()
              return redirect(url_for('user_request'))
           inventory = Inventory.query.all()
           return render_template('user_request.html', inventory = inventory)
       else:
         return "Unauthorized", 401

@app.route('/user/requests', methods=['GET'])
def user_requests():
      if 'username' in session and session['role'] == 'user':
           user_id = session.get('user_id')
           requests = Request.query.filter_by(user_id = user_id).all()
           return render_template('user_requests.html', requests = requests)
      else:
        return "Unauthorized", 401


@app.route('/logout')
def logout():
  session.pop('username', None)
  session.pop('role', None)
  session.pop('user_id', None)
  return redirect(url_for('login'))

@app.route('/')
def index():
  return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)