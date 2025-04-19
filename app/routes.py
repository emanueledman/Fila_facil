from flask import Blueprint, jsonify, request

api_bp = Blueprint('api', __name__)

# Dados de exemplo (simulando um banco de dados)
dados = [
    {"id": 1, "nome": "Item 1", "descricao": "Descrição do Item 1"},
    {"id": 2, "nome": "Item 2", "descricao": "Descrição do Item 2"}
]

# Endpoint para listar todos os itens
@api_bp.route('/itens', methods=['GET'])
def listar_itens():
    return jsonify(dados)

# Endpoint para obter um item específico
@api_bp.route('/itens/<int:id>', methods=['GET'])
def obter_item(id):
    item = next((item for item in dados if item['id'] == id), None)
    if item:
        return jsonify(item)
    return jsonify({"erro": "Item não encontrado"}), 404

# Endpoint para criar um novo item
@api_bp.route('/itens', methods=['POST'])
def criar_item():
    novo_item = request.get_json()
    if not novo_item or 'nome' not in novo_item or 'descricao' not in novo_item:
        return jsonify({"erro": "Dados inválidos"}), 400
    novo_item['id'] = len(dados) + 1
    dados.append(novo_item)
    return jsonify(novo_item), 201