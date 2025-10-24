from flask import Flask, render_template, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date 
from flask import session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin
from functools import wraps
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user


app = Flask(__name__)
app.secret_key = "my_secrect_key12345"
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:12345@localhost:5432/Todo'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # login view function

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    
    

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)    



class Todo(db.Model):
    __tablename__ = 'todos'
    id = db.Column(db.Integer, primary_key = True)
    content = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.Date, nullable=False, default=date.today)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    user = db.relationship('User', backref=db.backref('todos', lazy=True))
    

    def __repr__(self):
        return f"Todo {self.id}"
    
 # User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))   
    

# Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect('/register')
        if User.query.filter_by(email=email).first():
            flash('Email already exists!')
            return redirect('/register')

        new_user = User(username=username, email=email)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect('/login')

    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)  
            flash('Logged in successfully!')
            return redirect('/')
        else:
            flash('Invalid username or password!')
            return redirect('/login')

    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    logout_user()
    flash('Logged out successfully!')
    return redirect('/login')


    #home route  
@app.route('/', methods=["POST","GET"])   
@login_required
def index():

    user_id = current_user.id

    if request.method == 'POST':
        current_task = request.form['content']
        date_task = request.form.get('date_created')

        if not current_task:
            flash('Task content cannot be empty.')
            return redirect('/')

        date_input = datetime.strptime(date_task, "%Y-%m-%d") if date_task else datetime.today()

        new_task = Todo(content=current_task, date_created=date_input, user_id=user_id)

        try:
            db.session.add(new_task)
            db.session.commit()
            flash('Task added successfully!')
            return redirect('/')
        except Exception as e:
            flash(f"Error adding task: {e}")
            return redirect('/')
    else:
        tasks = Todo.query.filter_by(user_id=user_id).order_by(Todo.date_created).all()
        return render_template('index.html', tasks=tasks, username=current_user.username)

#delete route
@app.route("/delete/<int:id>")
@login_required
def delete(id):
    task = Todo.query.get_or_404(id)
    if task.user_id != current_user.id:
        flash("You are not allowed to delete this task.")
        return redirect('/')
    try:
        db.session.delete(task)
        db.session.commit()
        flash('Task deleted successfully!')
        return redirect('/')
    except Exception as e:
        flash(f"Error deleting task: {e}")
        return redirect('/')
    
    
@app.route("/edit/<int:id>", methods=["POST","GET"])
@login_required
def edit(id):
    task = Todo.query.get_or_404(id)
    if task.user_id != current_user.id:
        flash("You are not allowed to edit this task.")
        return redirect('/')

    if request.method == 'POST':
        task.content = request.form['content']
        task.date_created = datetime.strptime(request.form['date_created'], "%Y-%m-%d")
        try:
            db.session.commit()
            flash('Task updated successfully!')
            return redirect('/')
        except Exception as e:
            flash(f"Error updating task: {e}")
            return redirect('/')
    else:
        return render_template('edit.html', task=task)
        

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin123@gmail.com', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
        print(db.engine.url)
    app.run(debug=True)                        