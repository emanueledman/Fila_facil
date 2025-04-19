import logging
import uuid
import numpy as np
from sqlalchemy import and_, func
from datetime import datetime, time, timedelta
from app.models import Queue, QueueSchedule, Ticket, AuditLog, Department, Institution, User, Weekday, Branch, ServiceCategory, ServiceTag, UserPreference
from app.ml_models import wait_time_predictor, service_recommendation_predictor
from app import db, redis_client, socketio
from .utils.pdf_generator import generate_ticket_pdf
from firebase_admin import messaging
from sqlalchemy.exc import SQLAlchemyError
import json
from dateutil import parser
from geopy.distance import geodesic
from flask_socketio import emit

logger = logging.getLogger(__name__)

class QueueService:
    DEFAULT_EXPIRATION_MINUTES = 30
    CALL_TIMEOUT_MINUTES = 5
    PROXIMITY_THRESHOLD_KM = 1.0
    PRESENCE_PROXIMITY_THRESHOLD_KM = 0.5  # Distância máxima para validar presença

    @staticmethod
    def generate_qr_code():
        qr_code = f"QR-{uuid.uuid4().hex[:8]}"
        logger.debug(f"QR Code gerado: {qr_code}")
        return qr_code

    @staticmethod
    def generate_receipt(ticket):
        queue = ticket.queue
        if not queue or not queue.department or not queue.department.branch or not queue.department.branch.institution:
            logger.error(f"Dados incompletos para o ticket {ticket.id}: queue, department, branch ou institution ausentes")
            raise ValueError("Fila, departamento ou instituição associada ao ticket não encontrada")
        
        receipt = (
            "=== Comprovante Facilita 2.0 ===\n"
            f"Serviço: {queue.service}\n"
            f"Instituição: {queue.department.branch.institution.name}\n"
            f"Filial: {queue.department.branch.name}\n"
            f"Bairro: {queue.department.branch.neighborhood or 'Não especificado'}\n"
            f"Senha: {queue.prefix}{ticket.ticket_number}\n"
            f"Tipo: {'Física' if ticket.is_physical else 'Virtual'}\n"
            f"QR Code: {ticket.qr_code}\n"
            f"Prioridade: {ticket.priority}\n"
            f"Data de Emissão: {ticket.issued_at.strftime('%d/%m/%Y %H:%M')}\n"
            f"Expira em: {ticket.expires_at.strftime('%d/%m/%Y %H:%M') if ticket.expires_at else 'N/A'}\n"
            "=== Guarde este comprovante ==="
        )
        logger.debug(f"Comprovante gerado para ticket {ticket.id}")
        return receipt

    @staticmethod
    def generate_pdf_ticket(ticket, position=None, wait_time=None):
        if not ticket.queue or not ticket.queue.department or not ticket.queue.department.branch or not ticket.queue.department.branch.institution:
            logger.error(f"Dados incompletos para o ticket {ticket.id}: queue, department, branch ou institution ausentes")
            raise ValueError("Fila, departamento ou instituição associada ao ticket não encontrada")
            
        if position is None:
            position = max(0, ticket.ticket_number - ticket.queue.current_ticket)
        if wait_time is None:
            wait_time = QueueService.calculate_wait_time(
                ticket.queue.id, ticket.ticket_number, ticket.priority
            )

        pdf_buffer = generate_ticket_pdf(
            ticket=ticket,
            institution_name=f"{ticket.queue.department.branch.institution.name} - {ticket.queue.department.branch.name}",
            service=ticket.queue.service,
            position=position,
            wait_time=wait_time
        )
        return pdf_buffer

    @staticmethod
    def calculate_wait_time(queue_id, ticket_number, priority=0):
        queue = Queue.query.get(queue_id)
        if not queue:
            logger.error(f"Fila não encontrada para queue_id={queue_id}")
            return 0
        
        if not QueueService.is_queue_open(queue):
            logger.warning(f"Fila {queue_id} está fechada para cálculo de wait_time")
            return "N/A"

        if queue.current_ticket == 0:
            queue.current_ticket = 1
            db.session.commit()
            logger.debug(f"Atendimento ainda não começou para queue_id={queue_id}, inicializando current_ticket=1")

        position = max(0, ticket_number - queue.current_ticket)
        if position == 0:
            logger.debug(f"Ticket {ticket_number} está na posição 0, wait_time=0")
            return 0

        now = datetime.utcnow()
        hour_of_day = now.hour
        predicted_time = wait_time_predictor.predict(queue_id, position, queue.active_tickets, priority, hour_of_day)
        
        if predicted_time is not None:
            wait_time = predicted_time
        else:
            completed_tickets = Ticket.query.filter_by(queue_id=queue_id, status='Atendido').all()
            service_times = [t.service_time for t in completed_tickets if t.service_time is not None and t.service_time > 0]
            
            if service_times:
                avg_time = np.mean(service_times)
                estimated_time = avg_time
                logger.debug(f"Tempo médio de atendimento calculado: {avg_time} min")
            else:
                estimated_time = queue.avg_wait_time or 5
                logger.debug(f"Nenhum ticket atendido, usando tempo padrão: {estimated_time} min")

            wait_time = position * estimated_time
            if priority > 0:
                wait_time *= (1 - priority * 0.1)
            if queue.active_tickets > 10:
                wait_time += (queue.active_tickets - 10) * 0.5

            queue.avg_wait_time = estimated_time
            db.session.commit()

        wait_time = round(wait_time, 1)
        logger.debug(f"Wait time calculado para ticket {ticket_number} na fila {queue_id}: {wait_time} min (position={position}, priority={priority})")
        return wait_time

    @staticmethod
    def calculate_distance(user_lat, user_lon, branch):
        if not all([user_lat, user_lon, branch.latitude, branch.longitude]):
            logger.warning(f"Coordenadas incompletas para cálculo de distância: user_lat={user_lat}, user_lon={user_lon}, branch_lat={branch.latitude}, branch_lon={branch.longitude}")
            return None
        
        user_location = (user_lat, user_lon)
        branch_location = (branch.latitude, branch.longitude)
        try:
            distance = geodesic(user_location, branch_location).kilometers
            return round(distance, 2)
        except Exception as e:
            logger.error(f"Erro ao calcular distância: {e}")
            return None

    @staticmethod
    def send_notification(fcm_token, message, ticket_id=None, via_websocket=False, user_id=None):
        logger.info(f"Notificação para user_id {user_id}: {message}")
        
        if not fcm_token and user_id:
            user = User.query.get(user_id)
            if user and user.fcm_token:
                fcm_token = user.fcm_token
                logger.debug(f"FCM token recuperado do banco para user_id {user_id}: {fcm_token}")
            else:
                logger.warning(f"FCM token não encontrado para user_id {user_id}")

        if fcm_token:
            try:
                fcm_message = messaging.Message(
                    notification=messaging.Notification(
                        title="Facilita 2.0",
                        body=message
                    ),
                    data={"ticket_id": ticket_id or ""},
                    token=fcm_token
                )
                response = messaging.send(fcm_message)
                logger.info(f"Notificação FCM enviada para {fcm_token}: {response}")
            except Exception as e:
                logger.error(f"Erro ao enviar notificação FCM: {e}")
        else:
            logger.warning(f"Token FCM não fornecido e não encontrado para user_id {user_id}")

        if via_websocket and socketio and user_id:
            try:
                emit('notification', {'user_id': user_id, 'message': message}, namespace='/', room=str(user_id))
                logger.debug(f"Notificação WebSocket enviada para user_id={user_id}")
            except Exception as e:
                logger.error(f"Erro ao enviar notificação via WebSocket: {e}")

    @staticmethod
    def add_to_queue(service, user_id, priority=0, is_physical=False, fcm_token=None, branch_id=None):
        query = Queue.query.filter_by(service=service)
        if branch_id:
            query = query.join(Department).join(Branch).filter(Branch.id == branch_id)
        queue = query.first()
        
        if not queue:
            logger.error(f"Fila não encontrada para o serviço: {service} e branch_id: {branch_id}")
            raise ValueError("Fila não encontrada")
        
        if not QueueService.is_queue_open(queue):
            logger.warning(f"Fila {queue.id} está fechada para emissão de senha")
            raise ValueError(f"A fila {queue.service} está fechada no momento.")
        
        if queue.active_tickets >= queue.daily_limit:
            logger.warning(f"Fila {service} está cheia: {queue.active_tickets}/{queue.daily_limit}")
            raise ValueError("Limite diário atingido")
        
        if Ticket.query.filter_by(user_id=user_id, queue_id=queue.id, status='Pendente').first():
            logger.warning(f"Usuário {user_id} já possui uma senha ativa na fila {queue.id}")
            raise ValueError("Você já possui uma senha ativa")
        
        ticket_number = queue.active_tickets + 1
        qr_code = QueueService.generate_qr_code()
        ticket = Ticket(
            id=str(uuid.uuid4()),
            queue_id=queue.id,
            user_id=user_id,
            ticket_number=ticket_number,
            qr_code=qr_code,
            priority=priority,
            is_physical=is_physical,
            expires_at=None,
            issued_at=datetime.utcnow()
        )
        
        queue.active_tickets += 1
        db.session.add(ticket)
        db.session.commit()
        db.session.refresh(ticket)
        
        if not ticket.queue:
            logger.error(f"Relação ticket.queue não carregada para ticket {ticket.id}")
            raise ValueError("Erro ao carregar a fila associada ao ticket")
        
        ticket.receipt_data = QueueService.generate_receipt(ticket) if is_physical else None
        wait_time = QueueService.calculate_wait_time(queue.id, ticket_number, priority)
        position = max(0, ticket.ticket_number - queue.current_ticket)
        pdf_buffer = None
        
        if is_physical:
            pdf_buffer = QueueService.generate_pdf_ticket(ticket, position, wait_time)
        
        message = f"Senha {queue.prefix}{ticket_number} emitida. QR: {qr_code}. Espera: {wait_time if wait_time != 'N/A' else 'Aguardando início'}"
        QueueService.send_notification(fcm_token, message, ticket.id, via_websocket=True, user_id=user_id)
        
        if socketio:
            emit('queue_update', {
                'queue_id': queue.id,
                'active_tickets': queue.active_tickets,
                'current_ticket': queue.current_ticket,
                'message': f"Nova senha emitida: {queue.prefix}{ticket_number}"
            }, namespace='/', room=str(queue.id))
        
        logger.info(f"Ticket {ticket.id} adicionado à fila {service}")
        return ticket, pdf_buffer
    
    @staticmethod
    def generate_physical_ticket_for_totem(queue_id, client_ip):
        queue = Queue.query.get(queue_id)
        if not queue:
            logger.error(f"Fila não encontrada para queue_id={queue_id}")
            raise ValueError("Fila não encontrada")

        if not QueueService.is_queue_open(queue):
            logger.warning(f"Fila {queue_id} está fechada")
            raise ValueError("Fila está fechada no momento")

        if queue.active_tickets >= queue.daily_limit:
            logger.warning(f"Fila {queue_id} atingiu o limite diário: {queue.active_tickets}/{queue.daily_limit}")
            raise ValueError("Limite diário de tickets atingido")

        cache_key = f'ticket_limit:{client_ip}:{queue.department.branch.institution_id}'
        try:
            emission_count = redis_client.get(cache_key)
            emission_count = int(emission_count) if emission_count else 0
            if emission_count >= 5:
                logger.warning(f"Limite de emissões atingido para IP {client_ip}")
                raise ValueError("Limite de emissões por hora atingido. Tente novamente mais tarde.")
            redis_client.setex(cache_key, 3600, emission_count + 1)
        except Exception as e:
            logger.warning(f"Erro ao acessar Redis para limite de emissão ({client_ip}): {e}. Prosseguindo sem limite.")

        ticket_number = queue.active_tickets + 1
        qr_code = QueueService.generate_qr_code()
        ticket = Ticket(
            id=str(uuid.uuid4()),
            queue_id=queue.id,
            user_id='PRESENCIAL',
            ticket_number=ticket_number,
            qr_code=qr_code,
            priority=0,
            is_physical=True,
            status='Pendente',
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=4),
            receipt_data=None
        )
        queue.active_tickets += 1
        db.session.add(ticket)

        wait_time = QueueService.calculate_wait_time(queue.id, ticket_number, 0)
        position = max(0, ticket.ticket_number - queue.current_ticket)
        pdf_buffer = QueueService.generate_pdf_ticket(ticket, position, wait_time)
        pdf_base64 = pdf_buffer.getvalue().hex()

        ticket.receipt_data = QueueService.generate_receipt(ticket)
        audit_log = AuditLog(
            id=str(uuid.uuid4()),
            user_id=None,
            action='GENERATE_USER_PHYSICAL_TICKET',
            resource_type='Ticket',
            resource_id=ticket.id,
            details=f"Ticket {qr_code} gerado via mesa digital para fila {queue.service} (IP: {client_ip})",
            timestamp=datetime.utcnow()
        )
        db.session.add(audit_log)
        db.session.commit()

        if socketio:
            emit('queue_update', {
                'queue_id': queue.id,
                'active_tickets': queue.active_tickets,
                'current_ticket': queue.current_ticket,
                'message': f"Nova senha emitida: {queue.prefix}{ticket_number}"
            }, namespace='/', room=str(queue.id))

        logger.info(f"Ticket físico {ticket.id} gerado via totem para fila {queue_id}")
        return {
            'ticket': {
                'id': ticket.id,
                'queue_id': ticket.queue_id,
                'ticket_number': ticket.ticket_number,
                'qr_code': ticket.qr_code,
                'status': ticket.status,
                'issued_at': ticket.issued_at.isoformat(),
                'expires_at': ticket.expires_at.isoformat()
            },
            'pdf': pdf_base64
        }

    @staticmethod
    def call_next(service, branch_id=None):
        query = Queue.query.filter_by(service=service)
        if branch_id:
            query = query.join(Department).join(Branch).filter(Branch.id == branch_id)
        queue = query.first()
        
        if not queue:
            logger.warning(f"Fila {service} não encontrada")
            raise ValueError("Fila não encontrada")
        
        if not QueueService.is_queue_open(queue):
            logger.warning(f"Fila {queue.id} está fechada para chamar próximo")
            raise ValueError("Fila está fechada no momento")

        if queue.active_tickets == 0:
            logger.warning(f"Fila {service} está vazia")
            raise ValueError("Fila vazia")
        
        next_ticket = Ticket.query.filter_by(queue_id=queue.id, status='Pendente')\
            .order_by(Ticket.priority.desc(), Ticket.ticket_number).first()
        if not next_ticket:
            logger.warning(f"Não há tickets pendentes na fila {queue.id}")
            raise ValueError("Nenhum ticket pendente")
        
        now = datetime.utcnow()
        next_ticket.expires_at = now + timedelta(minutes=QueueService.CALL_TIMEOUT_MINUTES)
        
        queue.current_ticket = next_ticket.ticket_number
        queue.active_tickets -= 1
        queue.last_counter = (queue.last_counter % queue.num_counters) + 1
        next_ticket.status = 'Chamado'
        next_ticket.counter = queue.last_counter
        next_ticket.attended_at = now
        db.session.commit()
        
        message = f"Dirija-se ao guichê {next_ticket.counter:02d}! Senha {queue.prefix}{next_ticket.ticket_number} chamada."
        QueueService.send_notification(None, message, next_ticket.id, via_websocket=True, user_id=next_ticket.user_id)
        
        if socketio:
            emit('queue_update', {
                'queue_id': queue.id,
                'active_tickets': queue.active_tickets,
                'current_ticket': queue.current_ticket,
                'message': f"Senha {queue.prefix}{next_ticket.ticket_number} chamada"
            }, namespace='/', room=str(queue.id))
        
        logger.info(f"Ticket {next_ticket.id} chamado na fila {service}")
        return next_ticket

    @staticmethod
    def check_proximity_notifications(user_id, user_lat, user_lon, desired_service=None, institution_id=None, branch_id=None):
        """
        Verifica e envia notificações de proximidade com base na localização atual do usuário.

        Args:
            user_id (str): ID do usuário.
            user_lat (float): Latitude atual do usuário (obrigatório).
            user_lon (float): Longitude atual do usuário (obrigatório).
            desired_service (str, optional): Serviço desejado (ex.: "abertura de conta").
            institution_id (str, optional): ID da instituição (ex.: Banco BIC).
            branch_id (str, optional): ID da filial (ex.: Talatona).
        """
        user = User.query.get(user_id)
        if not user or not user.fcm_token:
            logger.warning(f"Usuário {user_id} não encontrado ou sem FCM token para notificações de proximidade")
            raise ValueError("Usuário não encontrado ou sem token de notificação")

        if user_lat is None or user_lon is None:
            logger.warning(f"Localização atual não fornecida para user_id={user_id}")
            raise ValueError("Localização atual do usuário é obrigatória para notificações de proximidade")

        # Atualizar localização do usuário
        try:
            user.last_known_lat = user_lat
            user.last_known_lon = user_lon
            user.last_location_update = datetime.utcnow()
            db.session.commit()
            logger.debug(f"Localização atualizada para user_id={user_id}: lat={user_lat}, lon={user_lon}")
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Erro ao atualizar localização do usuário {user_id}: {e}")
            raise ValueError("Erro ao atualizar localização do usuário")

        # Obter preferências do usuário
        user_prefs = UserPreference.query.filter_by(user_id=user_id).all()
        preferred_institutions = {pref.institution_id for pref in user_prefs if pref.institution_id}
        preferred_categories = {pref.service_category_id for pref in user_prefs if pref.service_category_id}

        # Construir query para filas
        query = Queue.query.join(Department).join(Branch).join(Institution)
        if institution_id:
            query = query.filter(Institution.id == institution_id)
        if branch_id:
            query = query.filter(Branch.id == branch_id)
        if desired_service:
            # Validar e sanitizar desired_service
            if not isinstance(desired_service, str) or not desired_service.strip():
                logger.warning(f"desired_service inválido ou vazio: {desired_service}")
                raise ValueError("O serviço desejado deve ser uma string não vazia")
            
            # Remover caracteres especiais e preparar termos para busca
            import re
            search_terms = re.sub(r'[^\w\s]', '', desired_service.lower()).split()
            if not search_terms:
                logger.warning(f"Nenhum termo válido em desired_service: {desired_service}")
                raise ValueError("Nenhum termo de busca válido fornecido")
            
            search_query = ' & '.join(search_terms)
            logger.debug(f"Termo de busca full-text: {search_query}")
            
            try:
                query = query.filter(
                    func.to_tsvector('portuguese', Queue.service + ' ' + Department.sector)
                    .op('@@')(func.to_tsquery('portuguese', search_query))
                )
            except Exception as e:
                logger.error(f"Erro na construção da query full-text para desired_service={desired_service}: {e}")
                raise ValueError("Erro ao processar a busca pelo serviço desejado")

        queues = query.all()

        now = datetime.utcnow()
        notified_branches = set()

        for queue in queues:
            branch = queue.department.branch
            if not branch or not branch.institution:
                logger.warning(f"Fila {queue.id} sem filial ou instituição associada")
                continue
            if not QueueService.is_queue_open(queue):
                logger.debug(f"Fila {queue.id} fechada, ignorando notificação")
                continue
            if queue.active_tickets >= queue.daily_limit:
                logger.debug(f"Fila {queue.id} atingiu limite diário, ignorando notificação")
                continue

            # Verificar preferências do usuário
            if preferred_institutions and branch.institution_id not in preferred_institutions:
                logger.debug(f"Filial {branch.id} não está nas preferências do usuário {user_id}")
                continue
            if preferred_categories and queue.category_id and queue.category_id not in preferred_categories:
                logger.debug(f"Categoria {queue.category_id} não está nas preferências do usuário {user_id}")
                continue

            # Calcular distância
            distance = QueueService.calculate_distance(user_lat, user_lon, branch)
            if distance is None or distance > QueueService.PROXIMITY_THRESHOLD_KM:
                logger.debug(f"Filial {branch.id} muito longe: {distance} km")
                continue

            # Verificar cache de notificações
            cache_key = f'notification:{user_id}:{branch.id}:{queue.id}:{int(user_lat*1000)}:{int(user_lon*1000)}'
            if redis_client.get(cache_key):
                logger.debug(f"Notificação já enviada para user_id={user_id}, queue_id={queue.id}, localização={user_lat},{user_lon}")
                continue

            # Calcular tempo de espera
            wait_time = QueueService.calculate_wait_time(queue.id, queue.active_tickets + 1, priority=0)
            message = (
                f"Fila disponível próxima! {queue.service} em {branch.institution.name} ({branch.name}) "
                f"a {distance:.2f} km de você. Tempo de espera: {wait_time if wait_time != 'N/A' else 'Aguardando início'} min."
            )

            # Enviar notificação
            QueueService.send_notification(
                user.fcm_token,
                message,
                via_websocket=True,
                user_id=user_id
            )

            # Marcar notificação como enviada no cache
            redis_client.setex(cache_key, 3600, 'sent')
            notified_branches.add(branch.id)
            logger.info(f"Notificação de proximidade enviada para user_id={user_id}: {message}")
    
    @staticmethod
    def check_proactive_notifications():
        now = datetime.utcnow()
        tickets = Ticket.query.filter_by(status='Pendente').all()
        for ticket in tickets:
            queue = ticket.queue
            if not QueueService.is_queue_open(queue):
                ticket.status = 'Cancelado'
                ticket.queue.active_tickets -= 1
                db.session.commit()
                QueueService.send_notification(
                    None,
                    f"Sua senha {ticket.queue.prefix}{ticket.ticket_number} foi cancelada porque o horário de atendimento terminou.",
                    user_id=ticket.user_id
                )
                logger.info(f"Ticket {ticket.id} cancelado devido ao fim do horário de atendimento")
                continue
            
            wait_time = QueueService.calculate_wait_time(ticket.queue_id, ticket.ticket_number, ticket.priority)
            if wait_time == "N/A":
                continue

            if wait_time <= 5 and ticket.user_id != 'PRESENCIAL':
                distance = QueueService.calculate_distance(-8.8147, 13.2302, ticket.queue.department.branch)
                distance_msg = f" Você está a {distance} km." if distance else ""
                message = f"Sua vez está próxima! {ticket.queue.service}, Senha {ticket.queue.prefix}{ticket.ticket_number}. Prepare-se em {wait_time} min.{distance_msg}"
                QueueService.send_notification(None, message, ticket.id, via_websocket=True, user_id=ticket.user_id)

            if ticket.user_id != 'PRESENCIAL':
                user = User.query.get(ticket.user_id)
                if user and user.last_known_lat and user.last_known_lon and user.last_location_update:
                    # Verificar se a localização é recente (menos de 10 minutos)
                    if (datetime.utcnow() - user.last_location_update).total_seconds() < 600:
                        distance = QueueService.calculate_distance(user.last_known_lat, user.last_known_lon, ticket.queue.department.branch)
                        if distance and distance > 5:
                            travel_time = distance * 2
                            if wait_time <= travel_time:
                                message = f"Você está a {distance} km! Senha {ticket.queue.prefix}{ticket.ticket_number} será chamada em {wait_time} min. Comece a se deslocar!"
                                QueueService.send_notification(None, message, ticket.id, via_websocket=True, user_id=ticket.user_id)
                    else:
                        logger.debug(f"Localização do usuário {user_id} desatualizada: {user.last_location_update}")

        called_tickets = Ticket.query.filter_by(status='Chamado').all()
        for ticket in called_tickets:
            if ticket.expires_at and ticket.expires_at < now:
                ticket.status = 'Cancelado'
                ticket.queue.active_tickets -= 1
                db.session.commit()
                QueueService.send_notification(
                    None,
                    f"Sua senha {ticket.queue.prefix}{ticket.ticket_number} foi cancelada porque você não validou a presença a tempo.",
                    user_id=ticket.user_id
                )
                logger.info(f"Ticket {ticket.id} cancelado por falta de validação de presença")

    @staticmethod
    def trade_tickets(ticket_from_id, ticket_to_id, user_from_id):
        ticket_from = Ticket.query.get_or_404(ticket_from_id)
        ticket_to = Ticket.query.get_or_404(ticket_to_id)
        if ticket_from.user_id != user_from_id or not ticket_to.trade_available or \
           ticket_from.queue_id != ticket_to.queue_id or ticket_from.status != 'Pendente' or \
           ticket_to.status != 'Pendente':
            logger.warning(f"Tentativa inválida de troca entre {ticket_from_id} e {ticket_to_id}")
            raise ValueError("Troca inválida")
        
        user_from, user_to = ticket_from.user_id, ticket_to.user_id
        num_from, num_to = ticket_from.ticket_number, ticket_to.ticket_number
        ticket_from.user_id, ticket_from.ticket_number = user_to, num_to
        ticket_to.user_id, ticket_to.ticket_number = user_from, num_from
        ticket_from.trade_available, ticket_to.trade_available = False, False
        db.session.commit()
        logger.info(f"Troca realizada entre {ticket_from_id} e {ticket_to_id}")

        QueueService.send_notification(
            None,
            f"Sua senha foi trocada! Nova senha: {ticket_from.queue.prefix}{ticket_from.ticket_number}",
            ticket_from.id,
            via_websocket=True,
            user_id=ticket_from.user_id
        )
        QueueService.send_notification(
            None,
            f"Sua senha foi trocada! Nova senha: {ticket_to.queue.prefix}{ticket_to.ticket_number}",
            ticket_to.id,
            via_websocket=True,
            user_id=ticket_to.user_id
        )

        return {"ticket_from": ticket_from, "ticket_to": ticket_to}

    @staticmethod
    def validate_presence(qr_code, user_lat=None, user_lon=None):
        ticket = Ticket.query.filter_by(qr_code=qr_code).first()
        if not ticket or ticket.status != 'Chamado':
            logger.warning(f"Tentativa inválida de validar presença com QR {qr_code}")
            raise ValueError("Senha inválida ou não chamada")
        if not QueueService.is_queue_open(ticket.queue):
            logger.warning(f"Fila {ticket.queue.id} está fechada para validação de presença")
            raise ValueError("Fila está fechada no momento")
        
        # Verificar proximidade (opcional)
        if user_lat and user_lon:
            branch = ticket.queue.department.branch
            distance = QueueService.calculate_distance(user_lat, user_lon, branch)
            if distance and distance > QueueService.PRESENCE_PROXIMITY_THRESHOLD_KM:
                logger.warning(f"Usuário muito longe para validar presença: {distance} km")
                raise ValueError(f"Você está muito longe da filial ({distance:.2f} km). Aproxime-se para validar.")
        
        ticket.status = 'Atendido'
        ticket.attended_at = datetime.utcnow()
        
        queue = ticket.queue
        last_ticket = Ticket.query.filter_by(queue_id=queue.id, status='Atendido')\
            .filter(Ticket.attended_at < ticket.attended_at).order_by(Ticket.attended_at.desc()).first()
        if last_ticket and last_ticket.attended_at:
            ticket.service_time = (ticket.attended_at - last_ticket.attended_at).total_seconds() / 60.0
            queue.last_service_time = ticket.service_time
        
        db.session.commit()
        logger.info(f"Presença validada para ticket {ticket.id}")
        return ticket

    @staticmethod
    def offer_trade(ticket_id, user_id):
        logger.info(f"Iniciando oferta de troca para ticket {ticket_id} por user_id {user_id}")
        ticket = Ticket.query.get_or_404(ticket_id)
        if ticket.user_id != user_id:
            logger.warning(f"Tentativa inválida de oferecer ticket {ticket_id} por {user_id}")
            raise ValueError("Você só pode oferecer sua própria senha.")
        if ticket.status != 'Pendente':
            logger.warning(f"Ticket {ticket_id} no estado {ticket.status} não pode ser oferecido")
            raise ValueError(f"Esta senha está no estado '{ticket.status}' e não pode ser oferecida.")
        if ticket.trade_available:
            logger.warning(f"Ticket {ticket_id} já está oferecido para troca")
            raise ValueError("Esta senha já está oferecida para troca.")
        
        try:
            ticket.trade_available = True 
            db.session.commit()
            logger.info(f"Ticket {ticket_id} oferecido para troca com sucesso")
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Erro ao persistir oferta de troca do ticket {ticket_id}: {e}")
            raise ValueError("Erro interno ao oferecer a senha para troca.")

        QueueService.send_notification(
            None,
            f"Sua senha {ticket.queue.prefix}{ticket.ticket_number} foi oferecida para troca!",
            ticket.id,
            via_websocket=True,
            user_id=user_id
        )

        eligible_tickets = Ticket.query.filter(
            Ticket.queue_id == ticket.queue_id,
            Ticket.user_id != user_id,
            Ticket.status == 'Pendente',
            Ticket.trade_available == False
        ).order_by(Ticket.issued_at.asc()).limit(5).all()

        if socketio:
            for eligible_ticket in eligible_tickets:
                try:
                    emit('trade_available', {
                        'ticket_id': ticket.id,
                        'queue_id': ticket.queue_id,
                        'service': ticket.queue.service,
                        'number': f"{ticket.queue.prefix}{ticket.ticket_number}",
                        'position': max(0, ticket.ticket_number - ticket.queue.current_ticket)
                    }, namespace='/', room=str(eligible_ticket.user_id))
                    logger.debug(f"Evento trade_available emitido para user_id {eligible_ticket.user_id}")
                except Exception as e:
                    logger.error(f"Erro ao emitir trade_available para user_id {eligible_ticket.user_id}: {e}")

        return ticket

    @staticmethod
    def cancel_ticket(ticket_id, user_id):
        ticket = Ticket.query.get_or_404(ticket_id)
        if ticket.user_id != user_id:
            logger.warning(f"Tentativa inválida de cancelar ticket {ticket_id} por user_id={user_id}")
            raise ValueError("Você só pode cancelar sua própria senha")
        if ticket.status != 'Pendente':
            logger.warning(f"Ticket {ticket_id} no estado {ticket.status} não pode ser cancelado")
            raise ValueError("Esta senha não pode ser cancelada no momento")
        
        ticket.status = 'Cancelado'
        ticket.queue.active_tickets -= 1
        db.session.commit()
        
        QueueService.send_notification(
            None,
            f"Sua senha {ticket.queue.prefix}{ticket.ticket_number} foi cancelada.",
            ticket.id,
            via_websocket=True,
            user_id=user_id
        )
        
        if socketio:
            emit('queue_update', {
                'queue_id': ticket.queue_id,
                'active_tickets': ticket.queue.active_tickets,
                'current_ticket': ticket.current_ticket,
                'message': f"Senha {ticket.queue.prefix}{ticket.ticket_number} cancelada"
            }, namespace='/', room=str(ticket.queue_id))
        
        logger.info(f"Ticket {ticket.id} cancelado por user_id={user_id}")
        return ticket

    @staticmethod
    def is_queue_open(queue, now=None):
        if not now:
            now = datetime.utcnow()
        
        weekday_str = now.strftime('%A')
        try:
            weekday_enum = Weekday[weekday_str.upper()]
            schedule = QueueSchedule.query.filter_by(
                queue_id=queue.id, 
                weekday=weekday_enum
            ).first()
            
            if not schedule or schedule.is_closed:
                return False
            
            current_time = now.time()
            return schedule.open_time <= current_time <= schedule.end_time
        except KeyError:
            logger.error(f"Dia da semana inválido: {weekday_str}")
            return False

    @staticmethod
    def search_services(
        query,
        user_id=None,
        user_lat=None,
        user_lon=None,
        institution_name=None,
        neighborhood=None,
        branch_id=None,
        max_results=5,
        max_distance_km=10.0,
        page=1,
        per_page=20
    ):
        """
        Busca serviços disponíveis com base em critérios como query, localização, instituição e bairro.

        Args:
            query (str): Termo de busca (ex.: "abertura de conta").
            user_id (str, optional): ID do usuário para preferências personalizadas.
            user_lat (float, optional): Latitude do usuário.
            user_lon (float, optional): Longitude do usuário.
            institution_name (str, optional): Nome da instituição (ex.: "Banco BIC").
            neighborhood (str, optional): Bairro (ex.: "Talatona").
            branch_id (str, optional): ID da filial.
            max_results (int): Número máximo de resultados a retornar.
            max_distance_km (float): Distância máxima em km para filtrar resultados.
            page (int): Página atual para paginação.
            per_page (int): Resultados por página.
        
        Returns:
            dict: Resultados da busca, incluindo serviços, total, página e sugestões.
        """
        now = datetime.utcnow()
        results = []
        
        query_base = Queue.query.join(Department).join(Branch).join(Institution)
        
        if query:
            # Validar e sanitizar query
            if not isinstance(query, str) or not query.strip():
                logger.warning(f"Query inválida ou vazia: {query}")
                raise ValueError("O termo de busca deve ser uma string não vazia")
            
            # Remover caracteres especiais e preparar termos para busca
            import re
            search_terms = re.sub(r'[^\w\s]', '', query.lower()).split()
            if not search_terms:
                logger.warning(f"Nenhum termo válido em query: {query}")
                raise ValueError("Nenhum termo de busca válido fornecido")
            
            search_term = ' & '.join(search_terms)
            logger.debug(f"Termo de busca full-text: {search_term}")
            
            try:
                query_base = query_base.filter(
                    func.to_tsvector('portuguese', Queue.service + ' ' + Department.sector + ' ' + Institution.name)
                    .op('@@')(func.to_tsquery('portuguese', search_term))
                )
                query_base = query_base.outerjoin(ServiceTag).filter(
                    Queue.id.in_(
                        db.session.query(ServiceTag.queue_id).filter(
                            ServiceTag.tag.ilike(f'%{query.lower()}%')
                        )
                    ) | (
                        func.to_tsvector('portuguese', Queue.service)
                        .op('@@')(func.to_tsquery('portuguese', search_term))
                    )
                )
            except Exception as e:
                logger.error(f"Erro na construção da query full-text para query={query}: {e}")
                raise ValueError("Erro ao processar a busca pelo termo fornecido")
        
        if institution_name:
            query_base = query_base.filter(Institution.name.ilike(f'%{institution_name}%'))
        
        if neighborhood:
            query_base = query_base.filter(Branch.neighborhood.ilike(f'%{neighborhood}%'))
        
        if branch_id:
            query_base = query_base.filter(Branch.id == branch_id)
        
        query_base = query_base.join(QueueSchedule).filter(
            and_(
                QueueSchedule.weekday == now.strftime('%A'),
                QueueSchedule.is_closed == False,
                QueueSchedule.open_time <= now.time(),
                QueueSchedule.end_time >= now.time()
            )
        )
        
        query_base = query_base.filter(Queue.active_tickets < Queue.daily_limit)
        
        user_prefs = None
        if user_id:
            user_prefs = UserPreference.query.filter_by(user_id=user_id).all()
        
        total = query_base.count()
        queues = query_base.order_by(
            func.ts_rank(
                func.to_tsvector('portuguese', Queue.service + ' ' + Department.sector),
                func.to_tsquery('portuguese', search_term if query and search_terms else '*')
            ).desc()
        ).offset((page - 1) * per_page).limit(per_page).all()
        
        for queue in queues:
            branch = queue.department.branch
            institution = branch.institution
            
            distance = None
            if user_lat and user_lon and branch.latitude and branch.longitude:
                distance = QueueService.calculate_distance(user_lat, user_lon, branch)
                if distance and distance > max_distance_km:
                    continue
            
            wait_time = QueueService.calculate_wait_time(queue.id, queue.active_tickets + 1, 0)
            
            # Calcular speed_label
            speed_label = "Desconhecida"
            tickets = Ticket.query.filter_by(queue_id=queue.id, status='attended').all()
            service_times = [t.service_time for t in tickets if t.service_time is not None and t.service_time > 0]
            if service_times:
                avg_service_time = np.mean(service_times)
                if avg_service_time <= 5:
                    speed_label = "Rápida"
                elif avg_service_time <= 15:
                    speed_label = "Moderada"
                else:
                    speed_label = "Lenta"
            
            score = 0.0
            quality_score = service_recommendation_predictor.predict(queue)
            if query and search_terms:
                rank = db.session.query(
                    func.ts_rank(
                        func.to_tsvector('portuguese', Queue.service + ' ' + Department.sector),
                        func.to_tsquery('portuguese', search_term)
                    )
                ).filter(Queue.id == queue.id).scalar()
                score += rank * 0.4
            if distance:
                score += (1 / (distance + 1)) * 0.3
            score += quality_score * 0.2
            if user_prefs:
                if any(pref.institution_id == institution.id for pref in user_prefs):
                    score += 0.2
                if any(pref.service_category_id == queue.category_id for pref in user_prefs):
                    score += 0.2
            
            results.append({
                'institution': {
                    'id': institution.id,
                    'name': institution.name
                },
                'branch': {
                    'id': branch.id,
                    'name': branch.name,
                    'location': branch.location,
                    'neighborhood': branch.neighborhood,
                    'latitude': branch.latitude,
                    'longitude': branch.longitude
                },
                'queue': {
                    'id': queue.id,
                    'service': queue.service,
                    'category_id': queue.category_id,
                    'wait_time': wait_time if wait_time != 'N/A' else 'Aguardando início',
                    'distance': distance if distance is not None else 'Desconhecida',
                    'active_tickets': queue.active_tickets,
                    'daily_limit': queue.daily_limit,
                    'open_time': queue.open_time.strftime('%H:%M') if queue.open_time else None,
                    'end_time': queue.end_time.strftime('%H:%M') if queue.end_time else None,
                    'quality_score': quality_score,
                    'speed_label': speed_label
                },
                'score': score
            })
        
        results.sort(key=lambda x: x['score'], reverse=True)
        
        suggestions = []
        if results and results[0]['queue']['category_id']:
            related_queues = Queue.query.filter(
                Queue.category_id == results[0]['queue']['category_id'],
                Queue.id != results[0]['queue']['id']
            ).join(Department).join(Branch).join(Institution).limit(3).all()
            for q in related_queues:
                suggestions.append({
                    'queue_id': q.id,
                    'institution': q.department.branch.institution.name,
                    'branch': q.department.branch.name,
                    'service': q.service,
                    'wait_time': QueueService.calculate_wait_time(q.id, q.active_tickets + 1, 0)
                })
        
        result = {
            'services': results[:max_results],
            'total': total,
            'page': page,
            'per_page': per_page,
            'suggestions': suggestions
        }
        
        try:
            cache_key = f'services:{query}:{institution_name}:{neighborhood}:{branch_id}'
            redis_client.setex(cache_key, 30, json.dumps(result))
        except Exception as e:
            logger.warning(f"Erro ao salvar cache no Redis para {cache_key}: {e}")
        
        return result
    def get_dashboard_data(institution_id):
        branches = Branch.query.filter_by(institution_id=institution_id).all()
        result = {'branches': []}
        
        for branch in branches:
            queues = Queue.query.join(Department).filter(Department.branch_id == branch.id).all()
            branch_data = {
                'branch_id': branch.id,
                'branch_name': branch.name,
                'neighborhood': branch.neighborhood,
                'queues': []
            }
            
            for queue in queues:
                current_ticket = Ticket.query.filter_by(queue_id=queue.id, status='Chamado').order_by(Ticket.attended_at.desc()).first()
                current_call = None
                if current_ticket:
                    current_call = {
                        'ticket_number': f"{queue.prefix}{current_ticket.ticket_number}",
                        'counter': current_ticket.counter or queue.last_counter or 1,
                        'timestamp': current_ticket.attended_at.isoformat() if current_ticket.attended_at else None
                    }
                
                recent_tickets = Ticket.query.filter_by(queue_id=queue.id, status='Atendido')\
                    .order_by(Ticket.attended_at.desc()).limit(5).all()
                recent_calls_data = [
                    {
                        'ticket_number': f"{queue.prefix}{ticket.ticket_number}",
                        'counter': ticket.counter or queue.last_counter or 1,
                        'timestamp': ticket.attended_at.isoformat()
                    } for ticket in recent_tickets
                ]
                
                branch_data['queues'].append({
                    'queue_id': queue.id,
                    'name': queue.service,
                    'service': queue.service or 'Atendimento Geral',
                    'current_call': current_call,
                    'recent_calls': recent_calls_data,
                    'category_id': queue.category_id
                })
            
            result['branches'].append(branch_data)
        
        try:
            cache_key = f'dashboard:{institution_id}'
            redis_client.setex(cache_key, 10, json.dumps(result))
        except Exception as e:
            logger.warning(f"Erro ao salvar cache no Redis para {cache_key}: {e}")
        
        return result

def emit_dashboard_update(institution_id, queue_id, event_type, data):
    channel = f'dashboard:{institution_id}'
    message = {
        'event': event_type,
        'queue_id': queue_id,
        'data': data,
        'timestamp': datetime.utcnow().isoformat()
    }
    try:
        redis_client.publish(channel, json.dumps(message))
    except Exception as e:
        logger.warning(f"Erro ao publicar atualização de dashboard para {channel}: {e}")

def subscribe_to_dashboard(institution_id):
    pubsub = redis_client.pubsub()
    try:
        pubsub.subscribe(f'dashboard:{institution_id}')
    except Exception as e:
        logger.error(f"Erro ao subscrever dashboard {institution_id}: {e}")
    return pubsub