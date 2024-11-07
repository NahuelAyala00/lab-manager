from flask import Flask, request, jsonify
from firebase_admin import credentials, firestore, initialize_app
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime

app = Flask(__name__)

# Configuração do Firebase
cred = credentials.Certificate("firebase_credentials.json")
initialize_app(cred)

# Banco de dados Firestore
db = firestore.client()

# Referência para usuários e laboratórios no Firestore
users_ref = db.collection("users")
labs_ref = db.collection("laboratorios")

SECRET_KEY = "your_secret_key"  # Use uma chave secreta segura

# Função para criar usuário (Admin ou Professor)
@app.route("/register", methods=["POST"])
def register_user():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    user_type = data.get("user_type")

    # Validar se o usuário é Admin ou Professor
    if user_type not in ["admin", "professor"]:
        return jsonify({"error": "Tipo de usuário inválido"}), 400

    hashed_password = generate_password_hash(password)

    # Criar usuário no Firestore
    user_data = {
        "username": username,
        "password": hashed_password,
        "user_type": user_type
    }
    users_ref.add(user_data)

    return jsonify({"message": "Usuário registrado com sucesso!"}), 201

# Função de login de usuário
@app.route("/login", methods=["POST"])
def login_user():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Verifique o usuário no Firestore
    user_doc = users_ref.where("username", "==", username).limit(1).get()

    if not user_doc:
        return jsonify({"error": "Usuário não encontrado"}), 404

    user = user_doc[0].to_dict()

    # Verifique se a senha está correta
    if not check_password_hash(user["password"], password):
        return jsonify({"error": "Senha incorreta"}), 401

    # Gerar token JWT
    token = jwt.encode({
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({"message": f"Bem-vindo {username}!", "token": token}), 200

# Função para criar laboratório
@app.route("/laboratorios", methods=["POST"])
def create_lab():
    # Obter o token do cabeçalho
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"error": "Usuário não autenticado"}), 401

    try:
        # Decodificar o token
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload['username']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

    # Verifique o tipo de usuário no Firestore
    user_doc = users_ref.where("username", "==", username).limit(1).get()
    if not user_doc:
        return jsonify({"error": "Usuário não encontrado"}), 404

    user = user_doc[0].to_dict()
    if user["user_type"] != "admin":
        return jsonify({"error": "Permissão negada"}), 403

    # Se o usuário for admin, podemos criar o laboratório
    data = request.get_json()
    nome = data.get("nome")
    num_pcs = data.get("num_pcs")
    localizacao = data.get("localizacao")
    status = data.get("status")
    softwares = data.get("softwares", [])

    # Dados do laboratório
    lab_data = {
        "nome": nome,
        "num_pcs": num_pcs,
        "localizacao": localizacao,
        "status": status,
        "softwares": softwares
    }

    # Adiciona o laboratório ao Firestore
    lab_ref = labs_ref.add(lab_data)  # Retorna uma tupla (referência, documento)

    # A referência do documento está no primeiro item da tupla
    lab_id = lab_ref[1].id  # Acessando o ID corretamente

    return jsonify({"message": "Laboratório criado com sucesso!", "lab_id": lab_id}), 201

# Função para listar laboratórios
@app.route("/laboratorios", methods=["GET"])
def list_labs():
    labs = labs_ref.stream()
    labs_list = []

    for lab in labs:
        labs_list.append(lab.to_dict())

    return jsonify(labs_list), 200

# Função para atualizar laboratório
@app.route("/laboratorios/<lab_id>", methods=["PUT"])
def update_lab(lab_id):
    # Obter o token do cabeçalho
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"error": "Usuário não autenticado"}), 401

    try:
        # Decodificar o token
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload['username']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

    # Verifique o tipo de usuário no Firestore
    user_doc = users_ref.where("username", "==", username).limit(1).get()
    if not user_doc:
        return jsonify({"error": "Usuário não encontrado"}), 404

    user = user_doc[0].to_dict()
    if user["user_type"] != "admin":
        return jsonify({"error": "Permissão negada"}), 403

    # Atualiza o laboratório
    data = request.get_json()
    lab_ref = labs_ref.document(lab_id)

    # Verifica se o laboratório existe
    if not lab_ref.get().exists:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    lab_ref.update(data)
    return jsonify({"message": "Laboratório atualizado com sucesso!"}), 200

# Função para remover laboratório
@app.route("/laboratorios/<lab_id>", methods=["DELETE"])
def delete_lab(lab_id):
    # Obter o token do cabeçalho
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"error": "Usuário não autenticado"}), 401

    try:
        # Decodificar o token
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload['username']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

    # Verifique o tipo de usuário no Firestore
    user_doc = users_ref.where("username", "==", username).limit(1).get()
    if not user_doc:
        return jsonify({"error": "Usuário não encontrado"}), 404

    user = user_doc[0].to_dict()
    if user["user_type"] != "admin":
        return jsonify({"error": "Permissão negada"}), 403

    # Remove o laboratório
    lab_ref = labs_ref.document(lab_id)

    # Verifica se o laboratório existe
    if not lab_ref.get().exists:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    lab_ref.delete()
    return jsonify({"message": "Laboratório removido com sucesso!"}), 200

# Função para adicionar software a um laboratório
@app.route("/laboratorios/<lab_id>/softwares", methods=["POST"])
def add_software(lab_id):
    data = request.get_json()
    software = data.get("software")

    lab_ref = labs_ref.document(lab_id)
    lab = lab_ref.get().to_dict()

    if not lab:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    softwares = lab["softwares"]
    if software not in softwares:
        softwares.append(software)
        lab_ref.update({"softwares": softwares})
        return jsonify({"message": f"Software {software} adicionado ao laboratório!"}), 200
    else:
        return jsonify({"message": "Software já está instalado no laboratório"}), 400

# Função para remover software de um laboratório
@app.route("/laboratorios/<lab_id>/softwares", methods=["DELETE"])
def remove_software(lab_id):
    data = request.get_json()
    software = data.get("software")

    lab_ref = labs_ref.document(lab_id)
    lab = lab_ref.get().to_dict()

    if not lab:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    softwares = lab["softwares"]
    if software in softwares:
        softwares.remove(software)
        lab_ref.update({"softwares": softwares})
        return jsonify({"message": f"Software {software} removido do laboratório!"}), 200
    else:
        return jsonify({"message": "Software não encontrado no laboratório"}), 400
    

    # Função para modificar o status de manutenção do laboratório
@app.route("/laboratorios/<lab_id>/manutencao", methods=["PUT"])
def set_lab_maintenance(lab_id):
    # Obter o token do cabeçalho
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"error": "Usuário não autenticado"}), 401

    try:
        # Decodificar o token
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload['username']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

    # Verifique o tipo de usuário no Firestore
    user_doc = users_ref.where("username", "==", username).limit(1).get()
    if not user_doc:
        return jsonify({"error": "Usuário não encontrado"}), 404

    user = user_doc[0].to_dict()
    if user["user_type"] != "admin":
        return jsonify({"error": "Permissão negada"}), 403

    # Modifica o status do laboratório
    data = request.get_json()
    status = data.get("status")  # O novo status do laboratório

    # Valida o status (se for "em manutencao" ou outro status válido)
    if status not in ["em manutencao", "disponivel", "ocupado"]:
        return jsonify({"error": "Status inválido. Use 'em manutencao', 'disponivel' ou 'ocupado'."}), 400

    lab_ref = labs_ref.document(lab_id)

    # Verifica se o laboratório existe
    if not lab_ref.get().exists:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    lab_ref.update({"status": status})
    return jsonify({"message": f"Status do laboratório atualizado para {status}!"}), 200


if __name__ == "__main__":
    app.run(debug=True)
