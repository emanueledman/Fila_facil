from datetime import time, datetime, timedelta
import uuid
from .models import Institution, Queue, User, Ticket, Department, UserRole, QueueSchedule, Weekday, Branch, ServiceCategory, ServiceTag, UserPreference
from . import db
import os
from sqlalchemy.exc import SQLAlchemyError


def populate_initial_data(app):
    with app.app_context():
        try:
            with db.session.no_autoflush:
                if Institution.query.count() > 0:
                    app.logger.info("Dados já existem, pulando inicialização.")
                    return

                # 1. Categorias de Serviço (expandidas)
                service_categories = [
                    # Categorias principais
                    {'name': 'Saúde', 'description': 'Serviços médicos e hospitalares'},
                    {'name': 'Bancário', 'description': 'Serviços financeiros'},
                    {'name': 'Notarial', 'description': 'Serviços cartorários'},
                    {'name': 'Utilidades', 'description': 'Serviços públicos essenciais'},
                    {'name': 'Educação', 'description': 'Instituições de ensino'},
                    {'name': 'Transporte', 'description': 'Serviços de transporte e logística'},
                    {'name': 'Universidade', 'description': 'Serviços universitários'},
                    
                    # Subcategorias de Saúde
                    {'name': 'Consulta Médica', 'description': 'Consultas gerais e especializadas', 'parent_name': 'Saúde'},
                    {'name': 'Emergência', 'description': 'Atendimento de urgência', 'parent_name': 'Saúde'},
                    {'name': 'Exames', 'description': 'Realização de exames', 'parent_name': 'Saúde'},
                    {'name': 'Farmácia', 'description': 'Dispensação de medicamentos', 'parent_name': 'Saúde'},
                    
                    # Subcategorias Bancárias
                    {'name': 'Atendimento ao Cliente', 'description': 'Atendimento geral bancário', 'parent_name': 'Bancário'},
                    {'name': 'Crédito', 'description': 'Serviços de empréstimos', 'parent_name': 'Bancário'},
                    {'name': 'Investimentos', 'description': 'Gestão de investimentos', 'parent_name': 'Bancário'},
                    
                    # Subcategorias Notariais
                    {'name': 'Registro Civil', 'description': 'Certidões e registros', 'parent_name': 'Notarial'},
                    {'name': 'Autenticações', 'description': 'Autenticação de documentos', 'parent_name': 'Notarial'},
                    
                    # Subcategorias de Educação
                    {'name': 'Matrículas', 'description': 'Processos de matrícula', 'parent_name': 'Educação'},
                    {'name': 'Secretaria', 'description': 'Serviços administrativos', 'parent_name': 'Educação'},
                    
                    # Subcategorias de Transporte
                    {'name': 'Bilhetes', 'description': 'Venda de bilhetes', 'parent_name': 'Transporte'},
                    {'name': 'Cargas', 'description': 'Gestão de cargas', 'parent_name': 'Transporte'},
                    {'name': 'Logística', 'description': 'Gestão logística', 'parent_name': 'Transporte'},
                    
                    # Subcategorias Universitárias
                    {'name': 'Inscrições', 'description': 'Inscrições acadêmicas', 'parent_name': 'Universidade'},
                    {'name': 'Pagamentos', 'description': 'Pagamento de propinas', 'parent_name': 'Universidade'},
                    {'name': 'Biblioteca', 'description': 'Serviços de biblioteca', 'parent_name': 'Universidade'}
                ]
                
                # Inserir categorias e mapear IDs
                category_map = {}
                for cat in service_categories:
                    parent_id = None
                    if 'parent_name' in cat:
                        parent_id = category_map[cat['parent_name']]
                    
                    category = ServiceCategory(
                        id=str(uuid.uuid4()),
                        name=cat['name'],
                        description=cat['description'],
                        parent_id=parent_id
                    )
                    db.session.add(category)
                    category_map[cat['name']] = category.id

                # 2. Bairros e coordenadas (exemplo para Luanda)
                neighborhoods = [
                    {'name': 'Ingombota', 'lat': -8.8167, 'long': 13.2332},
                    {'name': 'Maianga', 'lat': -8.8147, 'long': 13.2302},
                    {'name': 'Rangel', 'lat': -8.8300, 'long': 13.2500},
                    {'name': 'Samba', 'lat': -8.8200, 'long': 13.2400},
                    {'name': 'Viana', 'lat': -8.9035, 'long': 13.3741},
                    {'name': 'Talatona', 'lat': -8.9167, 'long': 13.1833},
                    {'name': 'Kilamba', 'lat': -8.9986, 'long': 13.2669},
                    {'name': 'Cazenga', 'lat': -8.8500, 'long': 13.2833},
                    {'name': 'Cacuaco', 'lat': -8.7833, 'long': 13.3667},
                    {'name': 'Patriota', 'lat': -8.8500, 'long': 13.2333}
                ]

                # 3. Instituições (50 no total)
                institutions = []
                
                # 15 Hospitais (reduzido para dar espaço a outras categorias)
                hospital_names = [
                    "Hospital Josina Machel", "Hospital Maria Pia", 
                    "Hospital Americo Boavida", "Clínica Girassol",
                    "Hospital Pediatrico", "Hospital Militar",
                    "Clínica Sagrada Esperança", "Hospital Geral de Luanda",
                    "Hospital Sanatório", "Clínica Multiperfil",
                    "Hospital Prenda", "Hospital Cajueiros",
                    "Clínica Endiama", "Hospital Esperança",
                    "Centro Médico Luanda"
                ]
                for i, name in enumerate(hospital_names):
                    institutions.append({
                        'name': name,
                        'description': f'Hospital público em {neighborhoods[i%10]["name"]}',
                        'type': 'Saúde',
                        'branches': []
                    })
                
                # 10 Bancos
                bank_names = [
                    "Banco BIC", "Banco BAI", "Banco BCI", 
                    "Banco Sol", "Banco Económico", "Banco Fomento",
                    "Banco Millennium", "Banco Atlântico", 
                    "Banco de Poupança e Crédito", "Banco Keve"
                ]
                for i, name in enumerate(bank_names):
                    institutions.append({
                        'name': f'{name} {neighborhoods[i%10]["name"]}',
                        'description': f'Agência bancária do {name}',
                        'type': 'Bancário',
                        'branches': []
                    })
                
                # 5 Cartórios
                for i in range(1, 6):
                    institutions.append({
                        'name': f'Cartório Notarial {neighborhoods[i%10]["name"]}',
                        'description': 'Serviços notariais e de registro',
                        'type': 'Notarial',
                        'branches': []
                    })
                
                # 5 Serviços de Alta Demanda
                high_demand_services = [
                    'Casa de Repouso Vovó Feliz',
                    'Centro de Emissão de Passaportes',
                    'Central de Licenciamento de Veículos',
                    'Delegacia de Imigração',
                    'Centro de Atendimento Fiscal'
                ]
                for i, service in enumerate(high_demand_services):
                    institutions.append({
                        'name': service,
                        'description': f'Serviço público de alta demanda em {neighborhoods[i%10]["name"]}',
                        'type': 'Utilidades',
                        'branches': []
                    })
                
                # 5 Universidades
                universities = [
                    "Universidade Agostinho Neto",
                    "Universidade Católica de Angola",
                    "Universidade Lusíada",
                    "Universidade Metodista",
                    "Universidade Privada de Angola"
                ]
                for i, uni in enumerate(universities):
                    institutions.append({
                        'name': uni,
                        'description': f'Instituição de ensino superior em {neighborhoods[i%10]["name"]}',
                        'type': 'Universidade',
                        'branches': []
                    })
                
                # 10 Serviços de Transporte/Logística
                transport_services = [
                    "Terminal Rodoviário de Luanda",
                    "Empresa de Caminhões Transafrica",
                    "Companhia de Táxis City",
                    "Transportes Colectivos TCUL",
                    "Logística Angola Express",
                    "Carga Pesada TransAngola",
                    "Terminal de Cargas Aéreas",
                    "Gestão Portuária de Luanda",
                    "Transportes Marítimos Atlântico",
                    "Distribuição Logística Nacional"
                ]
                for i, service in enumerate(transport_services):
                    institutions.append({
                        'name': service,
                        'description': f'Serviço de transporte em {neighborhoods[i%10]["name"]}',
                        'type': 'Transporte',
                        'branches': []
                    })
                
                # Adicionar filiais (1-3 por instituição)
                for inst in institutions:
                    inst['id'] = str(uuid.uuid4())
                    num_branches = 1  # Padrão 1 filial, pode ser aumentado
                    
                    for i in range(num_branches):
                        neighborhood = neighborhoods[i%10]
                        branch = {
                            'id': str(uuid.uuid4()),
                            'name': f'Unidade {neighborhood["name"]}',
                            'location': f'{neighborhood["name"]}, Luanda',
                            'neighborhood': neighborhood['name'],
                            'latitude': neighborhood['lat'],
                            'longitude': neighborhood['long'],
                            'departments': []
                        }
                        
                        # Adicionar departamentos (2-5 por filial)
                        num_departments = 3  # Padrão 3 departamentos
                        for j in range(num_departments):
                            if inst['type'] == 'Saúde':
                                dept_options = [
                                    ('Consulta Geral', 'Saúde', 'Consulta Médica'),
                                    ('Emergência', 'Saúde', 'Emergência'),
                                    ('Pediatria', 'Saúde', 'Consulta Médica'),
                                    ('Exames', 'Saúde', 'Exames'),
                                    ('Farmácia', 'Saúde', 'Farmácia')
                                ]
                            elif inst['type'] == 'Bancário':
                                dept_options = [
                                    ('Atendimento ao Cliente', 'Bancário', 'Atendimento ao Cliente'),
                                    ('Crédito', 'Bancário', 'Crédito'),
                                    ('Investimentos', 'Bancário', 'Investimentos')
                                ]
                            elif inst['type'] == 'Notarial':
                                dept_options = [
                                    ('Registro Civil', 'Notarial', 'Registro Civil'),
                                    ('Autenticações', 'Notarial', 'Autenticações')
                                ]
                            elif inst['type'] == 'Universidade':
                                dept_options = [
                                    ('Secretaria Acadêmica', 'Universidade', 'Inscrições'),
                                    ('Financeiro', 'Universidade', 'Pagamentos'),
                                    ('Biblioteca', 'Universidade', 'Biblioteca')
                                ]
                            elif inst['type'] == 'Transporte':
                                dept_options = [
                                    ('Bilhetes', 'Transporte', 'Bilhetes'),
                                    ('Cargas', 'Transporte', 'Cargas'),
                                    ('Logística', 'Transporte', 'Logística')
                                ]
                            else:  # Utilidades
                                dept_options = [
                                    ('Atendimento Geral', 'Utilidades', None),
                                    ('Licenciamento', 'Utilidades', None),
                                    ('Documentação', 'Utilidades', None)
                                ]
                            
                            dept_name, sector, category = dept_options[j%len(dept_options)]
                            
                            department = {
                                'id': str(uuid.uuid4()),
                                'name': dept_name,
                                'sector': sector,
                                'queues': []
                            }
                            
                            # Adicionar filas (1-3 por departamento)
                            num_queues = 2  # Padrão 2 filas por departamento
                            for k in range(num_queues):
                                if sector == 'Saúde':
                                    queue_options = [
                                        ('Consulta', 'A', ['consulta', 'médico']),
                                        ('Triagem', 'T', ['triagem', 'urgência']),
                                        ('Retorno', 'R', ['retorno', 'consulta']),
                                        ('Exames', 'E', ['exames', 'laboratório'])
                                    ]
                                elif sector == 'Bancário':
                                    queue_options = [
                                        ('Atendimento', 'A', ['banco', 'atendimento']),
                                        ('Caixa', 'C', ['caixa', 'depósitos']),
                                        ('Crédito', 'D', ['crédito', 'empréstimos'])
                                    ]
                                elif sector == 'Notarial':
                                    queue_options = [
                                        ('Autenticação', 'A', ['documentos', 'autenticação']),
                                        ('Registro', 'R', ['registro', 'civil'])
                                    ]
                                elif sector == 'Universidade':
                                    queue_options = [
                                        ('Inscrições', 'I', ['inscrição', 'universidade']),
                                        ('Pagamentos', 'P', ['pagamento', 'propinas']),
                                        ('Emissão Documentos', 'E', ['documentos', 'certidões'])
                                    ]
                                elif sector == 'Transporte':
                                    queue_options = [
                                        ('Bilhetes', 'B', ['bilhetes', 'viagem']),
                                        ('Cargas', 'C', ['cargas', 'frete']),
                                        ('Logística', 'L', ['logística', 'planeamento'])
                                    ]
                                else:  # Utilidades
                                    queue_options = [
                                        ('Atendimento', 'A', ['atendimento', 'serviço']),
                                        ('Licenças', 'L', ['licença', 'documento']),
                                        ('Pagamentos', 'P', ['pagamentos', 'taxas'])
                                    ]
                                
                                service, prefix, tags = queue_options[k%len(queue_options)]
                                
                                # Definir horários padrão
                                if sector in ['Saúde', 'Emergência']:
                                    open_time = time(7, 0)
                                    end_time = time(17, 0)
                                elif sector == 'Universidade':
                                    open_time = time(8, 0)
                                    end_time = time(15, 0)
                                else:
                                    open_time = time(8, 0)
                                    end_time = time(16, 0)
                                
                                queue = {
                                    'id': str(uuid.uuid4()),
                                    'service': f'{service} {k+1}',
                                    'category_id': category_map[category] if category else None,
                                    'prefix': prefix,
                                    'open_time': open_time,
                                    'end_time': end_time,
                                    'daily_limit': 50,
                                    'num_counters': 2,
                                    'tags': tags,
                                    'schedules': []
                                }
                                
                                # Agendamentos para cada dia da semana
                                for day in Weekday:
                                    is_closed = (day == Weekday.SUNDAY)
                                    
                                    if is_closed:
                                        schedule = {
                                            'weekday': day,
                                            'is_closed': True
                                        }
                                    else:
                                        # Ajustar horários para sábado
                                        if day == Weekday.SATURDAY:
                                            q_open = time(8, 0)
                                            q_end = time(12, 0)
                                        else:
                                            q_open = open_time
                                            q_end = end_time
                                        
                                        schedule = {
                                            'weekday': day,
                                            'open_time': q_open,
                                            'end_time': q_end,
                                            'is_closed': False
                                        }
                                    
                                    queue['schedules'].append(schedule)
                                
                                department['queues'].append(queue)
                            
                            branch['departments'].append(department)
                        
                        inst['branches'].append(branch)
                
                # Inserir todas as instituições, filiais, departamentos e filas no banco de dados
                for inst in institutions:
                    institution = Institution(
                        id=inst['id'],
                        name=inst['name'],
                        description=inst['description']
                    )
                    db.session.add(institution)
                    
                    for branch in inst['branches']:
                        branch_obj = Branch(
                            id=branch['id'],
                            institution_id=inst['id'],
                            name=branch['name'],
                            location=branch['location'],
                            neighborhood=branch['neighborhood'],
                            latitude=branch['latitude'],
                            longitude=branch['longitude']
                        )
                        db.session.add(branch_obj)
                        
                        for dept in branch['departments']:
                            department = Department(
                                id=dept['id'],
                                branch_id=branch['id'],
                                name=dept['name'],
                                sector=dept['sector']
                            )
                            db.session.add(department)
                            
                            for q in dept['queues']:
                                queue = Queue(
                                    id=q['id'],
                                    department_id=dept['id'],
                                    service=q['service'],
                                    category_id=q['category_id'],
                                    prefix=q['prefix'],
                                    open_time=q['open_time'],
                                    end_time=q['end_time'],
                                    daily_limit=q['daily_limit'],
                                    num_counters=q['num_counters'],
                                    active_tickets=0,
                                    current_ticket=0
                                )
                                db.session.add(queue)
                                
                                # Adicionar agendamentos
                                for schedule in q['schedules']:
                                    queue_schedule = QueueSchedule(
                                        id=str(uuid.uuid4()),
                                        queue_id=q['id'],
                                        weekday=schedule['weekday'],
                                        open_time=schedule.get('open_time'),
                                        end_time=schedule.get('end_time'),
                                        is_closed=schedule.get('is_closed', False)
                                    )
                                    db.session.add(queue_schedule)
                                
                                # Adicionar tags
                                for tag in q['tags']:
                                    service_tag = ServiceTag(
                                        id=str(uuid.uuid4()),
                                        queue_id=q['id'],
                                        tag=tag
                                    )
                                    db.session.add(service_tag)
                
                db.session.commit()
                app.logger.info("Dados iniciais de instituições inseridos com sucesso!")

                # 4. Usuários (400 no total)
                users = []
                
                # 1 Super Admin
                users.append({
                    'email': 'superadmin@facilita.com',
                    'name': 'Super Admin',
                    'password': os.getenv('SUPERADMIN_PASSWORD', 'superadmin123'),
                    'role': UserRole.SYSTEM_ADMIN,
                    'institution_id': None,
                    'department_name': None
                })
                
                # 1 Admin por instituição (50)
                for inst in institutions:
                    users.append({
                        'email': f'admin.{inst["name"].replace(" ", "").lower()}@facilita.com',
                        'name': f'Admin {inst["name"]}',
                        'password': os.getenv('ADMIN_PASSWORD', 'admin123'),
                        'role': UserRole.INSTITUTION_ADMIN,
                        'institution_id': inst['id'],
                        'department_name': None
                    })
                
                # 2 Gestores por departamento (~300)
                for inst in institutions:
                    for branch in inst['branches']:
                        for dept in branch['departments']:
                            for i in range(1, 3):  # 2 gestores por departamento
                                users.append({
                                    'email': f'gestor.{dept["name"].replace(" ", "").lower()}.{i}@{inst["name"].replace(" ", "").lower()}.com',
                                    'name': f'Gestor {dept["name"]} {i}',
                                    'password': os.getenv('ADMIN_PASSWORD', 'admin123'),
                                    'role': UserRole.DEPARTMENT_ADMIN,
                                    'institution_id': inst['id'],
                                    'department_name': dept['name']
                                })
                
                # 50 Usuários padrão
                for i in range(1, 51):
                    inst = institutions[i%len(institutions)]
                    users.append({
                        'email': f'user.{i}@facilita.com',
                        'name': f'Usuário {i}',
                        'password': os.getenv('USER_PASSWORD', 'user123'),
                        'role': UserRole.USER,
                        'institution_id': inst['id'],
                        'department_name': None
                    })
                
                # Inserir usuários
                for user_data in users:
                    # Encontrar departamento se especificado
                    department = None
                    if user_data['department_name'] and user_data['institution_id']:
                        institution = Institution.query.get(user_data['institution_id'])
                        if institution and institution.branches:
                            for branch in institution.branches:
                                department = Department.query.filter_by(
                                    branch_id=branch.id,
                                    name=user_data['department_name']
                                ).first()
                                if department:
                                    break
                    
                    user = User(
                        id=str(uuid.uuid4()),
                        email=user_data['email'],
                        name=user_data['name'],
                        user_role=user_data['role'],
                        institution_id=user_data['institution_id'],
                        department_id=department.id if department else None,
                        active=True
                    )
                    user.set_password(user_data['password'])
                    db.session.add(user)
                
                db.session.commit()
                app.logger.info("Usuários iniciais inseridos com sucesso!")

                # 5. Preferências de usuário (~100)
                user_preferences = []
                regular_users = [u for u in users if u['role'] == UserRole.USER]
                
                for user in regular_users:
                    # 2 preferências por usuário
                    for _ in range(2):
                        inst = institutions[int(user['email'].split('.')[1])%len(institutions)]
                        category_name = ['Saúde', 'Bancário', 'Notarial', 'Universidade', 'Transporte'][_%5]
                        category_id = category_map[category_name]
                        neighborhood = neighborhoods[int(user['email'].split('.')[1])%10]['name']
                        
                        user_preferences.append({
                            'user_email': user['email'],
                            'institution_id': inst['id'],
                            'service_category_id': category_id,
                            'neighborhood': neighborhood
                        })
                
                # Inserir preferências
                for pref in user_preferences:
                    user = User.query.filter_by(email=pref['user_email']).first()
                    if user:
                        preference = UserPreference(
                            id=str(uuid.uuid4()),
                            user_id=user.id,
                            institution_id=pref['institution_id'],
                            service_category_id=pref['service_category_id'],
                            neighborhood=pref['neighborhood']
                        )
                        db.session.add(preference)
                
                db.session.commit()
                app.logger.info("Preferências de usuário inseridas com sucesso!")

                # 6. Tickets (~3000)
                all_queues = Queue.query.all()
                regular_users = User.query.filter_by(user_role=UserRole.USER).all()
                
                for queue in all_queues:
                    # Resetar contadores da fila
                    queue.active_tickets = 0
                    queue.current_ticket = 0
                    
                    # Criar 5 tickets por fila
                    for i in range(1, 6):
                        is_physical = (i % 3 == 0)  # 1 em cada 3 é físico
                        user = None if is_physical else regular_users[i%len(regular_users)]
                        status = 'Pendente' if i == 1 else 'Atendido'  # Primeiro ticket pendente
                        
                        issued_at = datetime.utcnow() - timedelta(days=i)
                        
                        ticket = Ticket(
                            id=str(uuid.uuid4()),
                            queue_id=queue.id,
                            user_id=user.id if user else None,
                            ticket_number=i,
                            qr_code=f"QR-{uuid.uuid4().hex[:10]}",
                            status=status,
                            priority=0,
                            is_physical=is_physical,
                            counter=1 if status == 'Atendido' else None,
                            issued_at=issued_at,
                            attended_at=issued_at + timedelta(minutes=30) if status == 'Atendido' else None,
                            service_time=15.0 if status == 'Atendido' else None,
                            expires_at=issued_at + timedelta(hours=4) if is_physical else None,
                            trade_available=False
                        )
                        db.session.add(ticket)
                        
                        if status == 'Pendente':
                            queue.active_tickets += 1
                            queue.current_ticket = max(queue.current_ticket, i)
                
                db.session.commit()
                app.logger.info("Tickets iniciais inseridos com sucesso!")

        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Erro ao inserir dados iniciais: {str(e)}")
            raise