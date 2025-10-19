function getScoreClass(score) {
            if (score >= 30) return 'score-high';
            if (score >= 15) return 'score-med';
            return 'score-low';
        }

        function cleanPayload(payload) {
            if (!payload) return '';
            return payload
                .replace(/\\x[0-9a-f]{2}/gi, '')
                .replace(/\\\\/g, '\\')
                .substring(0, 2000);
        }

        async function loadAttacks() {
            try {
                const res = await fetch('/api/attacks');
                const attacks = await res.json();
                document.getElementById('count').textContent = attacks.length;

                const tbody = document.getElementById('attacks-body');
                tbody.innerHTML = '';

                if (!attacks.length) {
                    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center">Nessun attacco</td></tr>';
                    return;
                }

                attacks.forEach(a => {
                    const tr = document.createElement('tr');

                    // Timestamp
                    const tdTs = document.createElement('td');
                    tdTs.className = 'timestamp';
                    try {
                        tdTs.textContent = new Date(a.timestamp).toLocaleString('it-IT', {
                            day: '2-digit', month: '2-digit', year: 'numeric',
                            hour: '2-digit', minute: '2-digit'
                        });
                    } catch(e) { tdTs.textContent = a.timestamp; }
                    tr.appendChild(tdTs);

                    // IP ATTACCANTE
                    const tdIp = document.createElement('td');
                    tdIp.textContent = a.source_ip || '';
                    tr.appendChild(tdIp);

                    // IP Vittima
                   const tdVictimIp = document.createElement('td');
                   tdVictimIp.textContent = a.victim_ip || '';
                   tr.appendChild(tdVictimIp);


                    // Type
                    const tdType = document.createElement('td');
                    tdType.textContent = a.attack_type || '';
                    const lower = (a.attack_type || '').toLowerCase();
                    if (lower.includes('xss')) tdType.className = 'xss';
                    else if (lower.includes('sql')) tdType.className = 'sql';
                    tr.appendChild(tdType);

                    // User-Agent
                    const tdUa = document.createElement('td');
                    const divUa = document.createElement('div');
                    divUa.className = 'expandable';
                    divUa.textContent = a.user_agent || '';
                    divUa.title = 'Click per espandere';
                    divUa.onclick = function() { this.classList.toggle('expanded'); };
                    tdUa.appendChild(divUa);
                    tr.appendChild(tdUa);

                     // Method
                    const tdMethod = document.createElement('td');
                    tdMethod.textContent = a.method || '';
                    tdMethod.style.fontWeight = 'bold';
                    tdMethod.style.color = a.method === 'POST' ? '#ff6b6b' : '#aaa';
                    tr.appendChild(tdMethod);

                    // Full URL 
                    const tdUrl = document.createElement('td');
                    const divUrl = document.createElement('div');
                    divUrl.className = 'expandable';
                    divUrl.textContent = a.full_url || '';
                    divUrl.title = 'Click per espandere';
                    divUrl.onclick = function() { this.classList.toggle('expanded'); };
                    tdUrl.appendChild(divUrl);
                    tr.appendChild(tdUrl);


                    // Payload + Rules
                    const tdPayload = document.createElement('td');
                    tdPayload.className = 'payload-cell';


                    const divPayload = document.createElement('div');
                    divPayload.className = 'expandable';
                    divPayload.textContent = cleanPayload(a.payload || '');
                    divPayload.title = 'Click per espandere';
                    divPayload.onclick = function() { this.classList.toggle('expanded'); };

                    const divRules = document.createElement('div');
                    divRules.className = 'rules-info';
                    divRules.textContent = 'Rules: ' + (a.rule_ids || 'N/A');

                    tdPayload.appendChild(divPayload);
                    tdPayload.appendChild(divRules);
                    tr.appendChild(tdPayload);
                    // Dopo le Rules, aggiungi Unique ID
                    const divUniqueId = document.createElement('div');
                    divUniqueId.className = 'unique-id-info';
                    divUniqueId.textContent = 'Unique ID: ' + (a.unique_id || 'N/A');
                    divUniqueId.style.fontSize = '9px';
                    divUniqueId.style.color = '#666';
                    tdPayload.appendChild(divUniqueId);

                    // Score
                    const tdScore = document.createElement('td');
                    tdScore.className = getScoreClass(a.anomaly_score || 0);
                    tdScore.textContent = a.anomaly_score != null ? a.anomaly_score : '';
                    tr.appendChild(tdScore);

                    // Azioni
                    const tdActions = document.createElement('td');
                    tdActions.style.whiteSpace = 'nowrap';

                    // Bottone elimina
                    const btnDel = document.createElement('button');
                    btnDel.textContent = '✕';
                    btnDel.title = 'Archivia record';
                    btnDel.className = 'btn btn-delete';
                    btnDel.onclick = async function() {
                        if (!confirm('Archiviare questo attacco?')) return;
                        try {
                            const res = await fetch(`/api/attacks/${a.id}`, { method: 'DELETE' });
                            if (res.ok) {
                                loadAttacks();
                            } else {
                                alert('Errore durante Archiviazione');
                            }
                        } catch(err) {

                              alert('Errore: ' + err);
                        }
                    };


                    tdActions.appendChild(btnDel);
                    tr.appendChild(tdActions);

                    tbody.appendChild(tr);
                });
            } catch (err) {
                console.error('Errore:', err);
            }
        }

        loadAttacks();
        setInterval(loadAttacks, 5000);
