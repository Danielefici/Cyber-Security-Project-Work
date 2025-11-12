from pymisp import PyMISP, MISPEvent
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class MISPIntegration:
    def __init__(self, url, api_key, verify_cert=False):
        self.misp = PyMISP(url, api_key, verify_cert)
    
    def create_event_from_attacks(self, event_params, attacks):
        """
        Crea evento MISP da lista di attacchi
        
        event_params: {
            'info': str,
            'distribution': int,
            'threat_level_id': int,
            'analysis': int
        }
        attacks: lista di dict con campi del DB
        """
        event = MISPEvent()
        event.info = event_params['info']
        event.distribution = event_params['distribution']
        event.threat_level_id = event_params['threat_level_id']
        event.analysis = event_params['analysis']
        
        
        created_event = self.misp.add_event(event)
        event_id = created_event['Event']['id']
        
        # Aggiungi attributi da ogni attacco
        added_attrs = []
        for attack in attacks:
            # IP sorgente
            self.misp.add_attribute(event_id, {
                'type': 'ip-src',
                'value': attack['source_ip'],
                'comment': f"Attack: {attack['attack_type']}"
            })
            
            # Target URL
            if attack.get('target'):
                self.misp.add_attribute(event_id, {
                    'type': 'url',
                    'value': attack['target'],
                    'comment': f"Target URL from {attack['source_ip']}"
                })
            

            # URL completo con method
            if attack.get('full_url'):
                self.misp.add_attribute(event_id, {
                    'type': 'url',
                    'value': attack['full_url'],
                    'comment': f"{attack.get('method', 'GET')} from {attack['source_ip']} to {attack.get('victim_ip', 'unknown')}"
    })

            # IP vittima
            if attack.get('victim_ip'):
                self.misp.add_attribute(event_id, {
                    'type': 'ip-dst',
                    'value': attack['victim_ip'],
                    'comment': 'Target/Victim IP'
    })
            # Payload come text
            if attack.get('payload'):
                self.misp.add_attribute(event_id, {
                    'type': 'text',
                    'value': attack['payload'][:500],
                    'comment': f"{attack['attack_type']} payload"
                })
            
            added_attrs.append(attack['id'])
        
        return {
            'success': True,
            'event_id': event_id,
            'attributes_added': len(added_attrs),
            'attack_ids': added_attrs
        }





    

