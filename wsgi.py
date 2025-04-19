import eventlet
eventlet.monkey_patch()

import logging
import os
from app import create_app

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Criar a aplicação
app = create_app()

if __name__ == "__main__":
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', '5000'))  # Fallback apenas para testes locais
    debug = os.getenv('FLASK_ENV') != 'production'
    logger.info(f"Iniciando servidor WSGI em {host}:{port} (debug={debug})")
    from app import socketio
    socketio.run(app, host=host, port=port, debug=debug)