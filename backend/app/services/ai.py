from __future__ import annotations
import json, os, urllib.request, urllib.error

OLLAMA_BASE=os.getenv('SENTINELX_OLLAMA_URL','http://127.0.0.1:11434').rstrip('/')
DEFAULT_MODELS=[m.strip() for m in os.getenv('SENTINELX_AI_MODELS','llama3.2,qwen2.5:7b,gemma3:4b').split(',') if m.strip()]

def models():
    try:
        req=urllib.request.Request(OLLAMA_BASE+'/api/tags',method='GET')
        with urllib.request.urlopen(req,timeout=5) as r:
            d=json.loads(r.read().decode('utf-8'))
            names=[x.get('name') for x in d.get('models',[]) if x.get('name')]
            return {'provider':'Ollama','reachable':True,'base_url':OLLAMA_BASE,'models':names or DEFAULT_MODELS}
    except Exception:
        return {'provider':'Ollama','reachable':False,'base_url':OLLAMA_BASE,'models':DEFAULT_MODELS,'note':'Install Ollama and pull a local model to enable generated investigation text. SentinelX retains a deterministic analyst fallback.'}

def generate(prompt:str, model:str|None=None, timeout:int=35):
    selected=model or os.getenv('SENTINELX_OLLAMA_MODEL') or DEFAULT_MODELS[0]
    payload=json.dumps({'model':selected,'prompt':prompt,'stream':False}).encode('utf-8')
    req=urllib.request.Request(OLLAMA_BASE+'/api/generate',data=payload,headers={'Content-Type':'application/json'},method='POST')
    with urllib.request.urlopen(req,timeout=timeout) as r:
        d=json.loads(r.read().decode('utf-8')); return {'provider':'Ollama','model':selected,'analysis':d.get('response','').strip()}
