from flask import Flask, request, jsonify
from firebase_admin import credentials, firestore, initialize_app
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configuração do Firebase
cred = credentials.Certificate("firebase_credentials.json")
initialize_app(cred)

# Banco de dados Firestore
db = firestore.client()

# Referência para usuários e laboratórios no Firestore
users_ref = db.collection("users")
labs_ref = db.collection("laboratorios")

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

# Função para autenticação de usuários
@app.route("/login", methods=["POST"])
def login_user():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user_doc = users_ref.where("username", "==", username).limit(1).get()

    if not user_doc:
        return jsonify({"error": "Usuário não encontrado"}), 404

    user = user_doc[0].to_dict()
    if not check_password_hash(user["password"], password):
        return jsonify({"error": "Senha incorreta"}), 401

    return jsonify({"message": f"Bem-vindo {username}!"}), 200

# Função para criar laboratório
@app.route("/laboratorios", methods=["POST"])
def create_lab():
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
    data = request.get_json()
    lab_ref = labs_ref.document(lab_id)

    # Atualiza o laboratório no Firestore
    lab_ref.update(data)
    return jsonify({"message": "Laboratório atualizado com sucesso!"}), 200

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
        return jsonify({"error": "Software não encontrado no laboratório"}), 404

# Função para marcar um laboratório como "em manutenção"
@app.route("/laboratorios/<lab_id>/manutencao", methods=["PATCH"])
def mark_maintenance(lab_id):
    lab_ref = labs_ref.document(lab_id)
    lab = lab_ref.get().to_dict()

    if not lab:
        return jsonify({"error": "Laboratório não encontrado"}), 404

    lab_ref.update({"status": "em manutenção"})
    return jsonify({"message": "Laboratório marcado como em manutenção!"}), 200

@app.route('/')
def home():
    return 'teste'

if __name__ == '__main__':
    app.run(debug=True)
