import logging
import eventlet
eventlet.monkey_patch()

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from redis import Redis
import os
from dotenv import load_dotenv

# Carregar variáveis de ambiente
load_dotenv()

# Inicializar extensões
db = SQLAlchemy()
socketio = SocketIO()
limiter = Limiter(key_func=get_remote_address)
redis_client = Redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))

def create_app():
    app = Flask(__name__)

    # Configurações da aplicação
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key')
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default-jwt-secret-key')
    database_url = os.getenv('DATABASE_URL', 'sqlite:///facilita.db')
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://')
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['DEBUG'] = os.getenv('FLASK_ENV') != 'production'

    # Atribuir redis_client ao app
    app.redis_client = redis_client

    # Configurar logging
    handler = logging.handlers.RotatingFileHandler(
        'queue_service.log', maxBytes=1024*1024, backupCount=10
    )
    handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO if os.getenv('FLASK_ENV') == 'production' else logging.DEBUG)
    app.logger.info(f"Iniciando com banco de dados: {app.config['SQLALCHEMY_DATABASE_URI']}")

    # Inicializar extensões
    db.init_app(app)
    socketio.init_app(
        app,
        cors_allowed_origins=[
            "http://127.0.0.1:5500",
            "https://frontfa.netlify.app",
            "https://courageous-dolphin-66662b.netlify.app"
        ],
        async_mode='eventlet',
        path='/tickets',
        logger=True,
        engineio_logger=True
    )
    limiter.init_app(app)
    CORS(app, resources={
        r"/api/*": {
            "origins": [
                "http://127.0.0.1:5500",
                "https://frontfa.netlify.app",
                "https://courageous-dolphin-66662b.netlify.app"
            ],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True
        }
    })

    # Configurar Flask-Limiter com Redis
    limiter.storage_uri = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

    with app.app_context():
        from .models import Institution, Queue, User, Ticket, Department

        # Reiniciar o banco de dados
        #db.drop_all()
        db.create_all()
        app.logger.info("Banco limpo e tabelas recriadas")

        # Inserir dados iniciais
        try:
            from .data_init import populate_initial_data
            populate_initial_data(app)
            app.logger.info("Dados iniciais inseridos")
        except Exception as e:
            app.logger.error(f"Erro ao inserir dados iniciais: {e}")
            raise

        # Inicializar modelos de ML
        try:
            from .ml_models import wait_time_predictor, service_recommendation_predictor
            queues = Queue.query.all()
            for queue in queues:
                app.logger.info(f"Treinando WaitTimePredictor para queue_id={queue.id}")
                wait_time_predictor.train(queue.id)
            app.logger.info("Treinando ServiceRecommendationPredictor")
            service_recommendation_predictor.train()
            app.logger.info("Modelos de ML inicializados")
        except Exception as e:
            app.logger.error(f"Erro ao inicializar modelos de ML: {e}")

    # Registrar rotas
    from .routes import init_routes
    from .queue_routes import init_queue_routes
    from .user_routes import init_user_routes
    from .admin_routes import init_admin_routes

    init_routes(app)
    init_queue_routes(app)
    init_user_routes(app)
    init_admin_routes(app)

    return app