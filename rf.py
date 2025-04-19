import jwt
import datetime

def gerar_token(usuario_id):
    payload = {
        'sub': usuario_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        'iat': datetime.datetime.utcnow()
    }
    token = jwt.encode(payload, "974655", algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

print(gerar_token("admin"))
