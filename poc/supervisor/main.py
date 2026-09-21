import hmac
import os
import time
import requests
from fastapi import FastAPI, HTTPException, Header

SUPERVISOR_SECRET = os.getenv('SUPERVISOR_SECRET', '')
LEGACY_CONTROL_TOKEN = os.getenv('LEGACY_CONTROL_TOKEN', '')
ALLOWED_CONSUMERS = {'legacy-app':'http://legacy-app:8001'}
app = FastAPI(title='Application Supervisor')

@app.get('/health')
def health():
    return {'status':'healthy','service':'supervisor'}

@app.post('/restart/{consumer_id}')
def restart_consumer(consumer_id: str, fail: bool = False, authorization: str = Header(None)):
    if not SUPERVISOR_SECRET or not hmac.compare_digest(authorization or '', 'Bearer '+SUPERVISOR_SECRET):
        raise HTTPException(status_code=401, detail='Unauthorized supervisor access')
    if consumer_id not in ALLOWED_CONSUMERS:
        raise HTTPException(status_code=400, detail='Unknown restart target')
    base = ALLOWED_CONSUMERS[consumer_id]
    before = requests.get(base+'/config_meta',timeout=3)
    before.raise_for_status()
    before_id = before.json().get('process_id')
    if not before_id:
        raise HTTPException(status_code=503, detail='Consumer process identity unavailable')
    started = time.monotonic()
    trigger = requests.post(base+'/control/exit',params={'fail':str(fail).lower()},
                            headers={'Authorization':'Bearer '+LEGACY_CONTROL_TOKEN},timeout=3)
    trigger.raise_for_status()
    restarted = False
    generation = None
    for _ in range(60):
        time.sleep(0.25)
        try:
            meta = requests.get(base+'/config_meta',timeout=1)
            if meta.status_code != 200:
                continue
            restarted = meta.json().get('process_id') not in (None,before_id)
            generation = meta.json().get('generation_id')
            health_response = requests.get(base+'/health',timeout=1)
            if restarted and health_response.status_code == 200:
                return {'status':'restarted','consumer_id':consumer_id,'healthy':True,'process_restarted':True,
                        'generation_id':generation,'interruption_ms':round((time.monotonic()-started)*1000,2)}
        except requests.RequestException:
            pass
    return {'status':'failed','consumer_id':consumer_id,'healthy':False,'process_restarted':restarted,
            'generation_id':generation,'interruption_ms':round((time.monotonic()-started)*1000,2)}
