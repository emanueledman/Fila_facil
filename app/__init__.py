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

load_dotenv()

db = SQLAlchemy()
socketio = SocketIO()
limiter = Limiter(key_func=get_remote_address)
redis_client = None

def create_app():
    from .config import get_config
    
    app = Flask(__name__)
    app_config = get_config()
    app.config.from_object(app_config)
    
    # Configurar logging
    handler = logging.handlers.RotatingFileHandler(
        'queue_service.log', maxBytes=1024*1024, backupCount=10
    )
    handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    handler.setLevel(logging.INFO)
    if not any(isinstance(h, logging.handlers.RotatingFileHandler) for h in app.logger.handlers):
        app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO if os.getenv('FLASK_ENV') == 'production' else logging.DEBUG)
    app.logger.info(f"Iniciando com banco de dados: {app.config['SQLALCHEMY_DATABASE_URI']}")
    
    # Inicializar Redis client
    global redis_client
    redis_client = Redis.from_url(app.config['REDIS_URL'])
    app.redis_client = redis_client
    
    # Inicializar extensões
    db.init_app(app)
    socketio.init_app(
        app,
        cors_allowed_origins=app.config['SOCKETIO_CORS_ALLOWED_ORIGINS'],
        async_mode=app.config['SOCKETIO_ASYNC_MODE'],
        path=app.config['SOCKETIO_PATH'],
        logger=True,
        engineio_logger=True
    )
    
    # Configurar limiter
    limiter.init_app(app)
    limiter.storage_uri = app.config['REDIS_URL']
    
    # Configurar CORS
    CORS(app, resources={r"/api/*": {
        "origins": app.config['CORS_ORIGINS'],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }})
    
    with app.app_context():
        from .models import Institution, Queue, User, Ticket, Department
        
        # SEMPRE reiniciar o banco de dados
        db.drop_all()
        db.create_all()
        app.logger.info("Banco limpo e tabelas recriadas automaticamente")
        
        # Inserir dados iniciais de forma idempotente
        from .data_init import populate_initial_data
        try:
            populate_initial_data(app)
            app.logger.info("Dados iniciais inseridos automaticamente")
        except Exception as e:
            app.logger.error(f"Erro ao inserir dados iniciais: {str(e)}")
            raise
        
        # Inicializar modelos de ML
        app.logger.debug("Tentando importar preditores de ML")
        try:
            from .ml_models import wait_time_predictor, service_recommendation_predictor
            app.logger.info("Preditores de ML importados com sucesso")
        except ImportError as e:
            app.logger.error(f"Erro ao importar preditores de ML: {e}")
            raise
        
        app.logger.debug("Iniciando treinamento dos modelos de ML")
        try:
            queues = Queue.query.all()
            for queue in queues:
                app.logger.debug(f"Treinando WaitTimePredictor para queue_id={queue.id}")
                wait_time_predictor.train(queue.id)
            app.logger.debug("Treinando ServiceRecommendationPredictor")
            service_recommendation_predictor.train()
            app.logger.info("Modelos de ML inicializados na startup")
        except Exception as e:
            app.logger.error(f"Erro ao inicializar modelos de ML: {str(e)}")
            # Não lançar exceção aqui para permitir que a aplicação continue
    
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