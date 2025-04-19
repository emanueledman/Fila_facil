# wsgi.py
import os
from app import create_app

# Criar a aplicação Flask
app, _ = create_app()

if __name__ == "__main__":
    # Apenas para testes locais, o Gunicorn será usado em produção
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))