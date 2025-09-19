from werkzeug.security import generate_password_hash

password = "Rammurthy@0806"
hashed_password = generate_password_hash(password, method='scrypt')  # or 'pbkdf2:sha256'
print(hashed_password)
