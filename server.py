from flask import Flask, request, jsonify
from secure_social_media_encryption import SecureSocialMediaApp
from flask import send_from_directory
from flask import render_template
import base64


app = Flask(__name__)
social_media_app = SecureSocialMediaApp()

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<user_name>/get_permissions', methods=['GET'])
def get_permissions(user_name):
    if user_name not in social_media_app.users:
        return jsonify({'error': 'User not found'}), 404
    permissions = social_media_app.get_users_with_permission(user_name)
    return jsonify({'allowed_users': permissions}), 200

@app.route('/<user_name>')
def user_page(user_name):
    if user_name not in social_media_app.users:
        return jsonify({'error': 'User not found'}), 404
    return render_template('user.html', user_name=user_name)

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    user_name = request.json.get('user_name')
    if not user_name:
        return jsonify({'error': 'User name is required'}), 400
    social_media_app.generate_keys_and_certificate(user_name)
    return jsonify({'message': f'Keys and certificate generated for {user_name}'}), 201

@app.route('/add_permission', methods=['POST'])
def add_permission():
    user_name = request.json.get('user_name')
    allowed_user = request.json.get('allowed_user')
    if not all([user_name, allowed_user]):
        return jsonify({'error': 'User name and allowed user are required'}), 400
    social_media_app.add_permission(user_name, allowed_user)
    return jsonify({'message': f'{allowed_user} can now decrypt messages from {user_name}'}), 200

@app.route('/remove_permission', methods=['POST'])
def remove_permission():
    user_name = request.json.get('user_name')
    disallowed_user = request.json.get('disallowed_user')
    if not all([user_name, disallowed_user]):
        return jsonify({'error': 'User name and disallowed user are required'}), 400
    result = social_media_app.remove_permission(user_name, disallowed_user)
    if result:
        return jsonify({'message': f'{disallowed_user} can no longer decrypt messages from {user_name}'}), 200
    else:
        return jsonify({'error': 'Failed to remove permission'}), 400

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()  # parsing the JSON body
    if not data:
        return jsonify({'error': 'Request must be JSON'}), 400

    sender = data.get('sender')
    message = data.get('message')
    if not all([sender, message]):
        return jsonify({'error': 'Sender and message are required'}), 400

    try:
        # handles the logic of encrypting for all users appropriately
        social_media_app.handle_message_for_all_users(sender, message)
        return jsonify({'message': 'Message sent successfully'}), 200
    except Exception as e:
        # catch any exceptions and return a meaningful error message
        return jsonify({'error': str(e)}), 400

@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    sender = request.json.get('sender')
    receiver = request.json.get('receiver')
    encrypted_message = request.json.get('encrypted_message')
    if not all([sender, receiver, encrypted_message]):
        return jsonify({'error': 'Sender, receiver, and encrypted_message are required'}), 400
    try:
        decrypted_message = social_media_app.decrypt_message_from_user(encrypted_message.encode('ISO-8859-1'), receiver, sender)
        return jsonify({'decrypted_message': decrypted_message}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/<user_name>/sent_messages', methods=['GET'])
def get_sent_messages(user_name):
    if user_name not in social_media_app.users:
        return jsonify({'error': 'User not found'}), 404
    messages = social_media_app.users[user_name]['sent_messages']
    return jsonify(messages), 200

@app.route('/<user_name>/received_messages', methods=['GET'])
def get_received_messages(user_name):
    if user_name not in social_media_app.users:
        return jsonify({'error': 'User not found'}), 404
    messages = social_media_app.get_received_messages_with_permission_check(user_name)
    return jsonify(messages), 200

@app.route('/get_users', methods=['GET'])
def get_users():
    return jsonify(list(social_media_app.users.keys())), 200

@app.route('/get_users_details', methods=['GET'])
def get_users_details():
    user_details = {}
    for user_name, details in social_media_app.users.items():
        user_details[user_name] = {
            "certificate": details["certificate"].decode('utf-8'),  # Assuming the certificate is stored as bytes
            "permissions": details["permissions"],
            # "sent_messages": details["sent_messages"],
            # "received_messages": details["received_messages"]
        }
    return jsonify(user_details), 200

if __name__ == '__main__':
    app.run(debug=True)

