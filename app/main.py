from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from keytab_generator import KeytabGenerator
import io
import traceback

app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app)

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/api/generate-keytab', methods=['POST'])
def generate_keytab():
    """API endpoint to generate keytab file"""
    try:
        data = request.get_json()
        
        # Validate input
        domain = data.get('domain', '').strip()
        spn = data.get('spn', '').strip()
        password = data.get('password', '')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        if not spn:
            return jsonify({'error': 'SPN is required'}), 400
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        # Generate keytab
        keytab_data = KeytabGenerator.generate_keytab(domain, spn, password)
        
        # Return as file
        keytab_file = io.BytesIO(keytab_data)
        filename = f'{spn.replace("/", "_")}.keytab'
        
        return send_file(
            keytab_file,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    print("Starting Kerberos Keytab Generator...")
    print("Open http://localhost:5000 in your browser")
    app.run(debug=True, host='localhost', port=5000)
