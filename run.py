import eventlet
eventlet.monkey_patch()

import logging
import os
from app import create_app, socketio, db
from app.models import Queue
from app.ml_models import wait_time_predictor, service_recommendation_predictor

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Criar a aplicação
app = create_app()

def train_ml_model_periodically():
    """Treina os modelos de ML periodicamente para todas as filas."""
    while True:
        with app.app_context():
            try:
                logger.info("Iniciando treinamento periódico dos modelos de ML")
                queues = Queue.query.all()
                for queue in queues:
                    logger.info(f"Treinando WaitTimePredictor para queue_id={queue.id}")
                    wait_time_predictor.train(queue.id)
                logger.info("Treinando ServiceRecommendationPredictor")
                service_recommendation_predictor.train()
                logger.info("Treinamento periódico concluído")
            except Exception as e:
                logger.error(f"Erro ao treinar modelos de ML: {e}")
        eventlet.sleep(3600)  # Treinar a cada hora

if __name__ == "__main__":
    # Iniciar treinamento periódico apenas em desenvolvimento
    if os.getenv('FLASK_ENV') != 'production':
        eventlet.spawn(train_ml_model_periodically)

    # Configurar host e porta
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', '5000'))
    debug = os.getenv('FLASK_ENV') != 'production'

    logger.info(f"Iniciando servidor Flask-SocketIO em {host}:{port} (debug={debug})")
    socketio.run(app, host=host, port=port, debug=debug)