from flask import Flask, render_template, request, flash, redirect, url_for
from urllib.parse import quote_plus
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, logout_user, login_required, LoginManager, UserMixin

app = Flask(__name__)
app.secret_key = "cle_securite_du_code_de_merveilles"

password = quote_plus('merveilles')
chaine = "postgresql://postgres:{}@localhost:5432/ecole".format(password)
app.config['SQLALCHEMY_DATABASE_URI']= chaine

app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False

db=SQLAlchemy(app)

class User( UserMixin, db.Model):
    __tablename__="users"
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(60), nullable = False)
    prenom = db.Column(db.String(60), nullable = False)
    email = db.Column(db.String(60), nullable = False)
    password = db.Column(db.String(1000), nullable = False)
    passwordconf = db.Column(db.String(1000), nullable = False)

with app.app_context():
    db.create_all()



@app.route('/')
def index():
    return render_template("accueil.html")

@app.route('/Connection', methods = ["GET" , "POST"])
def Connect():
    if request.method == 'GET':
        return render_template("Connection.html")
    else:
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Vous avez saisi un mauvais email ou un mauvais mot de passe. Reessayer svp!')
            return redirect(url_for('Connect'))
        
        login_user(user)
        return redirect(url_for('cool'))


@app.route('/inscrire' , methods = ["GET" , "POST"])
def Inscrire():
    if request.method == 'GET':
        return render_template("inscription.html")
    else :
        nom = request.form.get('nom')
        prenom = request.form.get('prenom')
        email = request.form.get('email')
        password = request.form.get('passe')
        passwordconf = request.form.get('passeconf')

        if len(nom) < 2:
                 flash("Le nom doit être supérieur à 1 caractère !" , category="error")
                 return redirect(url_for("Inscrire"))
        elif len(email) < 4:
                 flash("Email doit être supérieur à 3 caractère !" , category="error")
                 return redirect(url_for("Inscrire"))
        elif password !=passwordconf:
                 flash("Les mots de Mot de passe saisi ne sont pas les mêmes. Mettez le même mot de passe pour la confirmation!", category="error")
                 return redirect(url_for("Inscrire"))
        elif len(password) < 7:
                 flash("Le mot de passe doit depasser 6 caractère !", category="error")
                 return redirect(url_for("Inscrire"))
                        
        user = User.query.filter_by(email=email).first()

        if user : 
            flash ('Email existe déjà')
            return redirect(url_for('Inscrire'))

        info=User(nom=nom, prenom=prenom, email=email, password=generate_password_hash(password, method='sha256'), passwordconf=generate_password_hash(passwordconf, method='sha256'))

        db.session.add(info)
        db.session.commit()
        flash('Votre compte est creé avec success',category="success")
        
        return redirect(url_for('Connect'))

@app.route('/cool')
def cool():
    return render_template("deconnecte.html")

@app.route('/oubli')
def oubli():
    return render_template("oublier.html")


login_manager = LoginManager()
login_manager.login_view = 'connect'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__ == '__main__' :
    app.run(debug= True)

