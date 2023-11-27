from flask import Flask, request, jsonify, render_template
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = 'cclabsecret'

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = bcrypt.generate_password_hash("admin").decode('utf-8')

def b64_padding(value):
    return value + '=' * (4 - (len(value) % 4))

# RSA 키 쌍 생성
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_PEM = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
PUBLIC_PEM = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

public_key_obj = serialization.load_pem_public_key(PUBLIC_PEM, backend=default_backend())
public_numbers = public_key_obj.public_numbers()
jwk_n = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).rstrip(b'=').decode('utf-8')

JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "e": b64_padding(base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8')),
            "kid": "test-key",
            "alg": "RS256",
            "n": jwk_n
        }
    ]
}

class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    submit = SubmitField('Login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if form.username.data == ADMIN_USERNAME and bcrypt.check_password_hash(ADMIN_PASSWORD_HASH, form.password.data):
            # JWT 발행
            encoded_jwt = jwt.encode({"user": "admin", "roles": "admin"}, PRIVATE_PEM, algorithm="RS256", headers={"kid": "test-key"})
            return jsonify({'token': encoded_jwt})
        return "Invalid credentials", 401   
    return render_template('login.html', form=form)

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks_endpoint():
    return jsonify(JWKS)

if __name__ == '__main__':
    app.run(debug=True)