from flask import Flask, render_template, request, jsonify, make_response, redirect
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity,
    jwt_required, get_jwt
)
from datetime import timedelta

app = Flask(__name__)

# Config JWT
app.config["JWT_SECRET_KEY"] = "abcd"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_COOKIE_SECURE"] = False  # True en HTTPS
app.config["JWT_COOKIE_SAMESITE"] = "Lax"
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

jwt = JWTManager(app)

# Home
@app.route('/')
def home():
    return render_template('accueil.html')

# Formulaire HTML (GET)
@app.route('/formulaire')
def formulaire():
    return render_template('formulaire.html')

# Login (POST depuis formulaire)
@app.route('/login', methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if username != "test" or password != "test":
        return jsonify({"msg": "Identifiants invalides"}), 401

    # Attribuer un rôle pour test
    role = "admin" if username == "test" else "user"

    access_token = create_access_token(identity=username, additional_claims={"role": role})
    response = make_response(redirect("/protected"))
    response.set_cookie("access_token_cookie", access_token)
    return response

# Protected route
@app.route('/protected')
@jwt_required()
def protected():
    user = get_jwt_identity()
    return jsonify(message=f"Bienvenue {user}, vous êtes authentifié.")

# Admin route protégée par rôle
@app.route('/admin')
@jwt_required()
def admin():
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"msg": "Accès refusé : vous n'êtes pas admin"}), 403
    return jsonify(message="Bienvenue dans la zone admin !")

if __name__ == "__main__":
    app.run(debug=True)
