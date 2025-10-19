from flask import Flask, render_template, jsonify, request
from misp_integration import MISPIntegration
import sqlite3

app = Flask(__name__)
DB_PATH = "attacks.db"

# Configurazione MISP
MISP_URL = ''
MISP_KEY = ''  

def get_attacks(limit=50):
    """Legge solo gli attacchi NON archiviati dal database"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute("""
    SELECT id, timestamp, source_ip, victim_ip, method, user_agent, attack_type, 
           payload, target, full_url, anomaly_score, rule_ids, unique_id
    FROM attacks 
    WHERE archived = 0
    ORDER BY id DESC 
    LIMIT ?
""", (limit,))

    attacks = [dict(row) for row in cur.fetchall()]
    conn.close()
    
    return attacks

@app.route('/')
def index():
    """Pagina principale"""
    return render_template('index.html')

@app.route('/api/attacks')
def api_attacks():
    """API per ottenere gli attacchi (JSON)"""
    attacks = get_attacks(limit=100)
    return jsonify(attacks)

@app.route('/api/attacks/<int:attack_id>', methods=['DELETE'])
def delete_attack(attack_id):
    """Archivia un attacco (non lo elimina fisicamente)"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("UPDATE attacks SET archived = 1 WHERE id = ?", (attack_id,))
        conn.commit()
        affected = cur.rowcount
        conn.close()
        
        if affected > 0:
            return jsonify({"success": True, "message": "Attacco archiviato"})
        else:
            return jsonify({"success": False, "message": "Attacco non trovato"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/misp/create-event', methods=['POST'])
def create_misp_event():
    """Crea evento MISP da attacchi selezionati"""
    try:
        data = request.json
        event_params = data.get('event_params')
        attack_ids = data.get('attack_ids', [])
        
        # Recupera attacchi dal DB
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        placeholders = ','.join('?' * len(attack_ids))
       
        cur.execute(f"""
            SELECT id, timestamp, source_ip, victim_ip, method, user_agent, attack_type,
                   payload, target, full_url, anomaly_score, rule_ids
            FROM attacks
            WHERE id IN ({placeholders})
        """, attack_ids)

        attacks = [dict(row) for row in cur.fetchall()]
        conn.close()
        
        if not attacks:
            return jsonify({'success': False, 'message': 'Nessun attacco selezionato'}), 400
        
        # Crea evento MISP
        misp = MISPIntegration(MISP_URL, MISP_KEY)
        result = misp.create_event_from_attacks(event_params, attacks)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
