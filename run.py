# run.py
from app import create_app

# Criar a aplicação Flask e o SocketIO
app, socketio = create_app()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)