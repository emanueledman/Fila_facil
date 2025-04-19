# wsgi.py
import os
from ini import create_app

# Criar a aplicação Flask
app, _ = create_app()

if __name__ == "__main__":
    # Apenas para testes locais, o Gunicorn será usado em produção
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)