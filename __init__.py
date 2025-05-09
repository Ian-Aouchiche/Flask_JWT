from flask import Flask, render_template, request, jsonify, make_response, redirect
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity,
    jwt_required, get_jwt
)
from datetime import timedelta

app = Flask(__name__)

# Configuration du module JWT
app.config["JWT_SECRET_KEY"] = "abcd"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # simplifie pour l'atelier
jwt = JWTManager(app)

@app.route('/')
def hello_world():
    return render_template('accueil.html')

# Formulaire simple
@app.route('/formulaire')
def formulaire():
    return '''
    <form method="POST" action="/login">
        Nom d'utilisateur : <input type="text" name="username"><br>
        Mot de passe : <input type="password" name="password"><br>
        <input type="submit" value="Se connecter">
    </form>
    '''

# Route de login
@app.route("/login", methods=["POST"])
def login():
    if request.is_json:
        username = request.json.get("username", None)
        password = request.json.get("password", None)
    else:
        username = request.form.get("username", None)
        password = request.form.get("password", None)

    if username != "test" and username != "admin" or password != "test":
        return jsonify({"msg": "Mauvais utilisateur ou mot de passe"}), 401

    # 🔽 Rôle selon utilisateur
    role = "admin" if username == "admin" else "user"
    access_token = create_access_token(identity=username, additional_claims={"role": role})
    
    if not request.is_json:
        resp = make_response(redirect("/protected"))
        resp.set_cookie("access_token_cookie", access_token)
        return resp

    return jsonify(access_token=access_token)


@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# Route admin protégée par rôle
@app.route("/admin", methods=["GET"])
@jwt_required()
def admin():
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify(msg="Accès refusé, vous n'êtes pas admin"), 403
    return jsonify(msg="Bienvenue sur la page admin !")

if __name__ == "__main__":
    app.run(debug=True)
