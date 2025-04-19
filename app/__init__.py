from flask import Flask

def create_app():
    app = Flask(__name__)

    # Configurações da aplicação
    app.config['DEBUG'] = True
    app.config['JSON_SORT_KEYS'] = False

    # Importa e registra os blueprints (rotas)
    from .routes import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    return app