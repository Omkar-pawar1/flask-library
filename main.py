from flask import Flask,render_template,request,send_file,session,redirect,url_for,flash,render_template_string
from werkzeug.utils import secure_filename
from flask import jsonify

from flask_admin import Admin,AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView

from flask_login import UserMixin,login_user,login_required,LoginManager,logout_user,current_user
from flask_bcrypt import Bcrypt

from flask_migrate import Migrate

from datetime import datetime

import io
from io import BytesIO
import base64


#for wtf form functionalites
from flask_wtf import FlaskForm
from wtforms import StringField,EmailField,FileField,SubmitField,TextAreaField,PasswordField
from wtforms.validators import DataRequired,Email,Length,ValidationError
import email_validator

#for database using sqlalchemy

from flask_sqlalchemy import SQLAlchemy
# from SQLAlchemy import ForeignKey 
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import relationship

import PyPDF2
import fitz 
from PIL import Image


# Your code using Pillow



# initializing app to flask or u can say flask instance creation
app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY']="msadfj"

#mapping app and database 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///my_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # optional,

# initializing database
db = SQLAlchemy(app)



#initializing Migrate 
migrate=Migrate(app,db)

#initializing Bcrypt for using it for hashing password
bcrypt=Bcrypt(app)

#for login manager 
login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if current_user.is_authenticated and current_user.id == 2:
            # Allow only user with ID 2 to access the admin dashboard
            return super(MyAdminIndexView, self).index()
        else:
            # Redirect unauthorized users to a different page
            return redirect(url_for('home'))  
        
#initializing flask admin
admin = Admin(app, index_view=MyAdminIndexView())        
        
#database class for sections   
class Section(db.Model):
    id=db.Column(db.Integer,primary_key=True,autoincrement=True)
    name=db.Column(db.String(200),nullable=False,unique=True)
    description=db.Column(db.String(500),nullable=False)
    date_created=db.Column(db.DateTime,default=datetime.utcnow())
    #a section can have one or many books accociated with it
    book_s=db.relationship('books',backref='book_section', cascade='all, delete-orphan')
    def __repr__(self):
        return '<Section %r>' % self.name
admin.add_view(ModelView(Section, db.session))

#creating model or table schema /database class
class books(db.Model):
    id=db.Column(db.Integer,primary_key=True,autoincrement=True)
    name=db.Column(db.String(200),primary_key=False,nullable=False,unique=True)
    author=db.Column(db.String(200),nullable=False)
    description=db.Column(db.String(500),nullable=False)
    content=db.Column(db.LargeBinary,nullable=False)
    filename = db.Column(db.String(255),nullable=False) 
    #creatiog foreign key to section id 
    section_id=db.Column(db.Integer,db.ForeignKey('section.id'))
    book_borro=db.relationship('borrow_book',backref='book_borrow', cascade='all, delete-orphan')
admin.add_view(ModelView(books, db.session))

#database class for users      
class User(db.Model,UserMixin):
    id=db.Column(db.Integer,primary_key=True,autoincrement=True)
    username=db.Column(db.String(200),nullable=False,unique=True)
    role=db.Column(db.String(50),default='user')
    password=db.Column(db.String(500),nullable=False)
    user_borrowing=db.relationship('borrow_book',backref='user_borrow', cascade='all, delete-orphan')
admin.add_view(ModelView(User, db.session))


#class for borrowing books   
class borrow_book(db.Model):
    id=db.Column(db.Integer,primary_key=True,autoincrement=True)
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'))
    book_name=db.Column(db.String,db.ForeignKey('books.name'))
    borrow_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)  

    
#form for signup/register user
class UserRegister(FlaskForm):
    username=StringField('Enter username',validators=[DataRequired()])
    password=PasswordField('Enter password',validators=[DataRequired(),Length(min=8,max=15)])
    submit=SubmitField('sign up')
    def validate_username(self,username):
        existing_user_username=User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("This username allready exists.Please choose another")

#form for login
class Userlogin(FlaskForm):
    username=StringField('Enter username',validators=[DataRequired()])
    password=PasswordField('Enter password',validators=[DataRequired(),Length(min=8,max=15)])
    submit=SubmitField('login')
       



#creating bookform class
class up_books(FlaskForm):
    book_name=StringField('Enter book name',validators=[DataRequired()])
    author=StringField('Enter author name',validators=[DataRequired()])
    description=StringField('write discription about book',validators=[DataRequired()])
    content=FileField('select the file to upload',validators=[DataRequired()])
    submit=SubmitField('submit')
        
    def validate_bookname(self,book_name):
        existing_bookname=books.query.filter_by(name=book_name.data).first()
        if existing_bookname:
            raise ValidationError("Book by this name is allready present.Please choose different book")

        
        
#form class for section
class sectionform(FlaskForm):
    section_name=StringField('Enter the name of section',validators=[DataRequired()])
    section_description=StringField('write short discription about section',validators=[DataRequired()])
    section_submit=SubmitField('submit')
    def validate_sectionname(self,section_name):
        existing_section_name=Section.query.filter_by(section_name=section_name.data).first()
        if existing_section_name:
            raise ValidationError("This section is allready present.Please make different Section")
    
#displaying book form on web page
@app.route("/book_form_display/<sid>",methods=['GET','POST'])
def book_form_display(sid):
    form=up_books()
    sectionid=sid   
    return render_template('book_form_display.html',form=form,section_id=sectionid) #web page for displaying form
    
        
      
#after user clicks on submit button on  book_form_display.html that data is send to this function which uploads data to database
@app.route("/uploadbook/<section_id>", methods=['GET','POST'])        
def uploadbook(section_id):
    
    form=up_books()
    if form.validate_on_submit():
        uploaded_file = request.files['content']
        if uploaded_file:
            # Open the file in binary mode and read its content
            content_data = uploaded_file.read()
            original_filename = secure_filename(uploaded_file.filename)


            book = books(
                name=form.book_name.data,
                author=form.author.data,
                description=form.description.data,
                content=content_data,
                filename = original_filename,# Get the original filename
                section_id=section_id
            )
            session['uploaded_filename'] = original_filename

               
            

            db.session.add(book)
            db.session.commit()

            all_books = books.query.all()
            
            return render_template('books.html', all_books=all_books)#displaying all books
        
    all_books = books.query.all()
    return render_template('books.html', all_books=all_books)

#function for making book available for download
@app.route('/download/<upload_id>')
def download(upload_id):
    all_books = books.query.filter_by(id=upload_id).first()
    
    filename = secure_filename(all_books.filename)

    return send_file(BytesIO(all_books.content), 
    download_name=filename,
    mimetype='application/pdf',
    as_attachment=True)  


#function for deleting book form database    
@app.route('/delete_book/<delete_id>',methods=['GET']) 
def delete_book(delete_id):
    
    #retriving book by it's id
    dlt_book=books.query.filter_by(id=delete_id).first()
    db.session.delete(dlt_book)
    db.session.commit()
    return redirect(url_for('uploadbook'))

#function for displaying book 
@login_required
@app.route('/display_book/<name>',methods=['GET','POST'])
def display_book(name):
    display_book=books.query.filter_by(name=name).first()
    binary_content = display_book.content
    image_data_list = []
    pdf_binary_data=binary_content
    pdf_document = fitz.open(stream=io.BytesIO(pdf_binary_data), filetype="pdf")
    for page_number in range(pdf_document.page_count):
                # Get the page
                page = pdf_document[page_number]
                pixmap = page.get_pixmap()
                image = Image.frombytes("RGB", [pixmap.width, pixmap.height], pixmap.samples)
                # Save the image to a BytesIO object
                image_bytes_io = io.BytesIO()
                image.save(image_bytes_io, format='PNG')

                # Get the binary image data
                image_bytes = image_bytes_io.getvalue()
                # Encode the binary image data in base64
                encoded_image_data = base64.b64encode(image_bytes).decode('utf-8')

                # Append the binary image data to the list
                image_data_list.append(encoded_image_data)

                # Convert the page to an image (PNG format)
                # image_bytes = pixmap.getPNGdata()

                # Append the binary image data to the list
                # image_data_list.append(image_bytes)
    pdf_document.close()
    # pdf_reader = PyPDF2.PdfReader(io.BytesIO(binary_content))
    # text_content = ""
    # for page in pdf_reader.pages: just writing here this should be passed as attribute in template text_content=text_content
    #     text_content += page.extract_text()
    #above code will just give me text from the binary format
    
    return render_template('display_book.html',image_data_list=image_data_list)


#fuction for displaying all available sections
@app.route('/display_section')
def display_section():
    
    secc=Section.query.all()
    return render_template('all_sections.html',secc=secc)   #display all available sections 

#function for deleting section
@app.route('/delete_section/<int:id>',methods=['GET','POST'])
def delete_section(id):
    sec=Section.query.get(id)
    db.session.delete(sec)
    db.session.commit()
    return redirect(url_for('display_section'))

#funtion for displaying form for section
@app.route('/section_form_display',methods=['GET','POST'])
def section_form_display():
    form=sectionform()
    return render_template('section_form.html',form=form)

#when submitted section form this function is called to store it in database
@app.route('/section_upload_func',methods=['GET','POST'])
def section_upload_func():
    form=sectionform()
    if request.method=='POST':
        if form.validate_on_submit():
            sec=Section(
                name=form.section_name.data,
                description=form.section_description.data
                
            )
            db.session.add(sec)
            db.session.commit()
            
            return redirect(url_for('section_form_display'))
    else:
        return "error found"
    
#function for displaying books under the given section
@app.route('/books_under_section/<secid>')
def books_under_section(secid):
    b=books.query.filter_by(section_id=secid)   
    return render_template('books_under_section.html',b=b)

#register route
@app.route('/register',methods=['GET','POST'])
def register():
    form=UserRegister()
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data)
        add_user=User(username=form.username.data,
                      password=hashed_password)
        db.session.add(add_user)
        db.session.commit()
        return redirect(url_for('login'))
        
    return render_template('register.html',form=form)
#if user is librarian then 
@app.route('/librarian',methods=['GET'])
@login_required
def librarian():
    if current_user.is_authenticated and current_user.role == "librarian":
        total_users = User.query.count()
        total_sections = Section.query.count()
        sections_with_books = Section.query.filter(Section.book_s.any()).all()
        sections_with_books_json = [{'name': section.name, 'books': [book.name for book in section.book_s]} for section in sections_with_books]


        
        return render_template('librarian.html', total_users=total_users,total_sections=total_sections,sections_with_books_json=sections_with_books_json)
        
    else:
        return redirect(url_for('home'))
#login route
@app.route('/login',methods=['GET','POST'])
def login():
    form=Userlogin()
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                flash('You are logged in!')
                if current_user.role =="librarian":
                    return redirect(url_for('librarian'))
   
                for borrowed_book in current_user.user_borrowing:
                    if (datetime.utcnow() - borrowed_book.borrow_date).days > 15:
                        # Book is overdue, remove it from the user's borrow list
                        db.session.delete(borrowed_book)
                        db.session.commit()
                        flash(f"Book '{borrowed_book.book_name}' was overdue and removed from your borrow list.")
                
                return redirect(url_for('dashboard',id=current_user.id)) 
            else:
                return ('password incorrect')
        else:
            return ('Username entered do not exists')
    else:
        return render_template('login.html',form=form)

#logout route
@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    flash('you are logged out')
    return redirect(url_for('home'))
    
@app.route('/',methods=['GET'])    
def home():
    template_string = display_section() #call for display_section function which displays all sections
    sections = render_template_string(template_string)#for getting out put of above function that is html file
    return render_template('home.html',sections=sections) 

@login_required
@app.route('/dashboard/<int:id>',methods=['GET'])    
def dashboard(id):
    if current_user.id != id:
        # Redirect unauthorized users to the homepage or an error page
        return redirect(url_for('home'))
    template_string = display_section() #call for display_section function which displays all sections
    sections = render_template_string(template_string)#for getting out put of above function that is html file
    user_=User.query.filter_by(id=id).first()
    return render_template('dashboard.html',user_=user_,sections=sections)

@app.route('/request_book/<name>',methods=['GET','POST'])
@login_required
def request_book(name):
    check=borrow_book.query.filter_by(user_id=current_user.id ,book_name=name).first()
    borrowed_books_count = borrow_book.query.filter_by(user_id=current_user.id).count()
    
    print("check:", check) 
    
    if borrowed_books_count >= 5:
        return ("You have already borrowed 5 books")
    elif check:
        return ("You have all borrowed this book")
    
    borrowed_detail=borrow_book(user_id=current_user.id,book_name=name)
    db.session.add(borrowed_detail)
    db.session.commit()
    flash("You have borrow the book successfully")
    return redirect(url_for('display_book',name=name))

#function for returning  book from database    
@app.route('/return_book',methods=['GET','POST']) 
def return_book():
    rtun_book=borrow_book.query.filter_by(user_id=current_user.id).all()
    
    return render_template('return_book.html',rtun_book=rtun_book)   
    
# function for deleting record from borrow book table    
@app.route('/delete_returned_book/<name>',methods=['GET','POST']) 
def delete_returned_book(name):
    
    #retriving book by it's id
    dlt_book=borrow_book.query.filter_by(book_name=name).first()
    db.session.delete(dlt_book)
    db.session.commit()
    flash("Book is successfully returned")

    return redirect(url_for('dashboard',id=current_user.id))   

@app.route('/search_sections')
def search_sections():
    query = request.args.get('query')
    sections = Section.query.filter(Section.name.ilike(f'%{query}%')).all()
    return render_template('search_sections.html', sections=sections,query=query)

@app.route('/policies',methods=['GET']) 
def policies():
    return render_template('policies.html')

def assignL():
    with app.app_context():
        # Retrieve the user with ID 1
        user = User.query.get(1)
        
        if user:
            # Update the role to "librarian"
            user.role = 'librarian'
            
            # Commit the changes to the database
            db.session.commit()
            
            return "Role assigned successfully"
        else:
            return "User with ID 1 not found"

assignL()


if __name__ == '__main__':
    app.run(debug=True)
