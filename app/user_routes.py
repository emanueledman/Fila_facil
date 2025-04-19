from flask import jsonify, request, make_response
from . import db
from .models import User, UserRole, Queue, Department
import logging
import jwt
import os
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_user_routes(app):
    @app.route('/api/admin/login', methods=['POST', 'OPTIONS'])
    def admin_login():
        if request.method == 'OPTIONS':
            response = make_response()
            response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
            response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
            response.headers['Access-Control-Max-Age'] = '86400'
            return response

        logger.info("Recebida requisição POST para /api/admin/login")
        try:
            data = request.get_json()
            if not data:
                logger.warning("Requisição POST sem corpo JSON")
                return jsonify({"error": "Corpo da requisição inválido"}), 400

            email = data.get('email')
            password = data.get('password')
            if not email or not password:
                logger.warning("Tentativa de login sem email ou senha")
                return jsonify({"error": "Email e senha são obrigatórios"}), 400

            logger.info(f"Buscando usuário com email={email}")
            user = User.query.filter_by(email=email).first()
            if not user:
                logger.warning(f"Usuário não encontrado para email={email}")
                return jsonify({"error": "Credenciais inválidas"}), 401

            if not user.check_password(password):
                logger.warning(f"Senha inválida para email={email}")
                return jsonify({"error": "Credenciais inválidas"}), 401

            # Verificar se o usuário é dept_admin ou inst_admin
            if user.user_role not in [UserRole.DEPARTMENT_ADMIN, UserRole.INSTITUTION_ADMIN]:
                logger.warning(f"Usuário {email} tem papel inválido: {user.user_role.value}")
                return jsonify({"error": "Acesso restrito a administradores de departamento ou instituição"}), 403

            secret_key = os.getenv('JWT_SECRET_KEY', '1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0')
            token = jwt.encode({
                'user_id': user.id,
                'user_role': user.user_role.value,
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, secret_key, algorithm='HS256')

            if isinstance(token, bytes):
                token = token.decode('utf-8')

            # Preparar resposta com base no papel
            response_data = {
                "token": token,
                "user_id": user.id,
                "user_role": user.user_role.value,
                "institution_id": user.institution_id,
                "department_id": user.department_id,
                "email": user.email
            }

            if user.user_role == UserRole.DEPARTMENT_ADMIN:
                if not user.department_id:
                    logger.warning(f"Gestor {user.id} não vinculado a departamento")
                    return jsonify({"error": "Gestor não vinculado a um departamento"}), 403

                # Buscar filas do departamento
                queues = Queue.query.filter_by(department_id=user.department_id).all()
                response_data["queues"] = [{
                    'id': q.id,
                    'service': q.service,
                    'prefix': q.prefix,
                    'department': q.department.name if q.department else 'N/A',
                    'active_tickets': q.active_tickets,
                    'daily_limit': q.daily_limit,
                    'current_ticket': q.current_ticket,
                    'status': 'Aberto' if q.active_tickets < q.daily_limit else 'Lotado',
                    'open_time': q.open_time.strftime('%H:%M') if q.open_time else None,
                    'end_time': q.end_time.strftime('%H:%M') if q.end_time else None
                } for q in queues]

            elif user.user_role == UserRole.INSTITUTION_ADMIN:
                if not user.institution_id:
                    logger.warning(f"Admin {user.id} não vinculado a instituição")
                    return jsonify({"error": "Admin não vinculado a uma instituição"}), 403

                # Buscar departamentos e gestores
                departments = Department.query.filter_by(institution_id=user.institution_id).all()
                response_data["departments"] = [{
                    'id': d.id,
                    'name': d.name,
                    'sector': d.sector
                } for d in departments]

                # Buscar gestores (dept_admin) da instituição
                managers = User.query.filter_by(
                    institution_id=user.institution_id,
                    user_role=UserRole.DEPARTMENT_ADMIN
                ).all()
                response_data["managers"] = [{
                    'id': m.id,
                    'email': m.email,
                    'name': m.name,
                    'department_id': m.department_id,
                    'department_name': m.department.name if m.department else 'N/A'
                } for m in managers]

            response = jsonify(response_data)
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Credentials', 'true')

            logger.info(f"Login bem-sucedido para usuário: {email} ({user.user_role.value})")
            return response, 200

        except Exception as e:
            logger.error(f"Erro ao processar login para email={request.json.get('email', 'unknown')}: {str(e)}")
            return jsonify({"error": "Erro interno no servidor"}), 500