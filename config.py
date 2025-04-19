# app/config.py
import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # Configuração base
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.getenv('SECRET_KEY', '1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0')
    
    # Configuração do banco de dados
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    database_url = os.getenv('DATABASE_URL', 'sqlite:///facilita.db')
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://')
    SQLALCHEMY_DATABASE_URI = database_url
    
    # Configuração JWT
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', '1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    
    # Configuração do Redis
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    
    # Configuração CORS
    CORS_HEADERS = 'Content-Type'
    CORS_ORIGINS = [
        "http://127.0.0.1:5500",
        "https://frontfa.netlify.app",
        "https://courageous-dolphin-66662b.netlify.app"
    ]
    
    # Configuração SocketIO
    SOCKETIO_PATH = '/tickets'
    SOCKETIO_CORS_ALLOWED_ORIGINS = CORS_ORIGINS
    SOCKETIO_ASYNC_MODE = 'eventlet'


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    # Configurações específicas para produção
    SQLALCHEMY_ECHO = False  # Desativa logs SQL em produção


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


# Configuração baseada no ambiente
config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig
}


def get_config():
    env = os.getenv('FLASK_ENV', 'development')
    if env == 'dev':
        env = 'development'
    elif env == 'prod':
        env = 'production'
    elif env == 'test':
        env = 'testing'
    
    return config_by_name.get(env, DevelopmentConfig)