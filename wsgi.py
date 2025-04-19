import eventlet
eventlet.monkey_patch()
import logging
import os
from app import create_app, socketio

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Criar a aplicação
app = create_app()

# Esta linha é importante para o Gunicorn
application = socketio.wsgi_app

if __name__ == "__main__":
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', '5000'))
    debug = os.getenv('FLASK_ENV') != 'production'
    logger.info(f"Iniciando servidor WSGI em {host}:{port} (debug={debug})")
    socketio.run(app, host=host, port=port, debug=debug)