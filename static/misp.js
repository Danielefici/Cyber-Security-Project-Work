// Gestione modale MISP
let selectedAttackIds = new Set();

document.getElementById('btn-open-misp').addEventListener('click', function() {
    document.getElementById('misp-modal').style.display = 'block';
    loadAttacksForMISP();
});

document.getElementById('btn-close-misp').addEventListener('click', function() {
    document.getElementById('misp-modal').style.display = 'none';
    selectedAttackIds.clear();
    updateSelectedCount();
});

// Chiudi modale cliccando fuori
document.getElementById('misp-modal').addEventListener('click', function(e) {
    if (e.target === this) {
        this.style.display = 'none';
        selectedAttackIds.clear();
        updateSelectedCount();
    }
});

// Select all checkbox
document.getElementById('select-all-misp').addEventListener('change', function() {
    const checkboxes = document.querySelectorAll('.attack-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = this.checked;
        if (this.checked) {
            selectedAttackIds.add(parseInt(cb.dataset.attackId));
        } else {
            selectedAttackIds.delete(parseInt(cb.dataset.attackId));
        }
    });
    updateSelectedCount();
});

function updateSelectedCount() {
    document.getElementById('selected-count').textContent = selectedAttackIds.size;
}

async function loadAttacksForMISP() {
    try {
        const res = await fetch('/api/attacks');
        const attacks = await res.json();
        
        const tbody = document.getElementById('misp-attacks-body');
        tbody.innerHTML = '';
        
        if (!attacks.length) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center">Nessun attacco disponibile</td></tr>';
            return;
        }
        
        attacks.forEach(a => {
            const tr = document.createElement('tr');
            
            // Checkbox
            const tdCheck = document.createElement('td');
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'attack-checkbox';
            checkbox.dataset.attackId = a.id;
            checkbox.addEventListener('change', function() {
                if (this.checked) {
                    selectedAttackIds.add(parseInt(a.id));
                } else {
                    selectedAttackIds.delete(parseInt(a.id));
                }
                updateSelectedCount();
            });
            tdCheck.appendChild(checkbox);
            tr.appendChild(tdCheck);
            
            // ID
            const tdId = document.createElement('td');
            tdId.textContent = a.id;
            tr.appendChild(tdId);
            
            // IP
            const tdIp = document.createElement('td');
            tdIp.textContent = a.source_ip;
            tr.appendChild(tdIp);
            
            // Tipo
            const tdType = document.createElement('td');
            tdType.textContent = a.attack_type;
            tdType.style.color = a.attack_type.toLowerCase().includes('xss') ? '#ffd93d' : '#6bcf7f';
            tr.appendChild(tdType);
            
            // Payload
            const tdPayload = document.createElement('td');
            tdPayload.textContent = (a.payload || '').substring(0, 50) + '...';
            tdPayload.style.fontSize = '10px';
            tr.appendChild(tdPayload);
            
            tbody.appendChild(tr);
        });
        
    } catch(err) {
        console.error('Errore caricamento attacchi per MISP:', err);
    }
}

// Upload su MISP
document.getElementById('btn-upload-misp').addEventListener('click', async function() {
    if (selectedAttackIds.size === 0) {
        alert('Seleziona almeno un attacco');
        return;
    }
    
    const info = document.getElementById('misp-info').value.trim();
    if (!info) {
        alert('Inserisci un titolo per l\'evento');
        return;
    }
    
    const eventParams = {
        info: info,
        distribution: parseInt(document.getElementById('misp-distribution').value),
        threat_level_id: parseInt(document.getElementById('misp-threat').value),
        analysis: parseInt(document.getElementById('misp-analysis').value)
    };
    
    try {
        this.disabled = true;
        this.textContent = '⏳ Caricamento...';
        
        const res = await fetch('/api/misp/create-event', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                event_params: eventParams,
                attack_ids: Array.from(selectedAttackIds)
            })
        });
        
        const result = await res.json();
        
        if (result.success) {
            alert(`✅ Evento MISP creato!\nID: ${result.event_id}\nAttributi aggiunti: ${result.attributes_added}`);
            document.getElementById('misp-modal').style.display = 'none';
            selectedAttackIds.clear();
        } else {
            alert('❌ Errore: ' + result.message);
        }
        
    } catch(err) {
        alert('❌ Errore durante il caricamento: ' + err);
    } finally {
        this.disabled = false;
        this.textContent = '📤 Carica su MISP';
    }
});
